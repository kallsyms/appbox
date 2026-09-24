//! Running one guest thread's vCPU, calling the hooks and scheduler along the way.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use nix::sys::signal::Signal;

use super::cx::{ThreadCx, LANDING_SLOT};
use super::{
    lock, Decision, ExecRequest, FaultKind, GuestEnd, GuestFault, Hooks, Outcome, Preempt,
    Preemption, Registers, Resume, Returned, Scheduler, Slice, Stop, Syscall, Target,
};
use crate::applevisor as av;
use crate::hyperpom::crash::ExitKind;
use crate::hyperpom::exceptions::ExceptionClass;
use crate::loader::Loader;
use crate::runner::GuestThread;
use crate::trap::{read_syscall_context, write_syscall_result, DefaultTrapHandler, SVC_ESR};
use crate::vm::{VmManager, VmRunResult};

/// How far short of a target's instruction count to stop timing the guest and start looking for
/// its registers at a breakpoint. It must cover how much host interrupts inflated the count
/// (seen up to ~100k in a ~3ms slice).
const TARGET_MARGIN: u64 = 150_000;
/// The shortest timed run worth doing before switching to breakpoints.
const MIN_TIMER_NS: f64 = 2_000.0;
/// How far past a target the breakpoint phase could be, given the instruction counts, before
/// concluding it was missed: covers host interrupts inflating the counts.
const MISSED_SLACK: u64 = 500_000;

/// What starting the guest (or its next image) is due to call hooks for.
pub(super) enum Pending {
    Start,
    Exec(ExecRequest),
}

/// What a guest's threads share.
pub(super) struct Shared {
    pub(super) hooks: Mutex<Vec<Box<dyn Hooks>>>,
    pub(super) scheduler: Option<Arc<Mutex<Box<dyn Scheduler>>>>,
    /// How the guest ended, once a thread has ended it.
    pub(super) ending: Mutex<Option<GuestEnd>>,
    pub(super) pending: Mutex<Option<Pending>>,
}

impl Shared {
    /// How the guest ended, which ended its run with `exit`.
    pub(super) fn take_ending(&self, exit: ExitKind, handler: &DefaultTrapHandler) -> GuestEnd {
        if let Some(end) = lock(&self.ending).take() {
            return end;
        }
        match exit {
            ExitKind::Exit | ExitKind::ThreadExit => {
                GuestEnd::Exited(handler.exit_status().unwrap_or(0))
            }
            ExitKind::Crash(reason) => GuestEnd::Crashed {
                signal: Signal::SIGABRT,
                reason,
            },
            other => GuestEnd::Crashed {
                signal: Signal::SIGKILL,
                reason: format!("{other:?}"),
            },
        }
    }
}

fn exit_kind(end: &GuestEnd) -> ExitKind {
    match end {
        GuestEnd::Exited(_) => ExitKind::Exit,
        GuestEnd::Crashed { reason, .. } => ExitKind::Crash(reason.clone()),
    }
}

/// How finding a target went.
enum Landing {
    Reached,
    /// Ran past it, into a syscall if `at_syscall` (which is still to be handled).
    Missed { at_syscall: bool },
    /// Something else happened first.
    Event(VmRunResult),
}

pub(super) struct Driver<'a> {
    vm: &'a mut VmManager,
    thread: &'a mut GuestThread,
    loader: &'a Loader,
    shared: &'a Shared,
    /// A hook asked for a step: the next instruction's completion is a [`Stop::Step`].
    stepping: bool,
    /// Resuming from a stop, which may be at a breakpoint: its instruction runs first, rather
    /// than stopping there again.
    leaving_stop: bool,
}

impl<'a> Driver<'a> {
    pub(super) fn new(
        vm: &'a mut VmManager,
        thread: &'a mut GuestThread,
        loader: &'a Loader,
        shared: &'a Shared,
    ) -> Self {
        Self {
            vm,
            thread,
            loader,
            shared,
            stepping: false,
            leaving_stop: false,
        }
    }

    /// Runs the thread until it, or the guest, is done.
    pub(super) fn run(mut self) -> Result<ExitKind> {
        let pending = lock(&self.shared.pending).take();
        match pending {
            Some(Pending::Start) => {
                let (resume, restored) = self.hooks(Resume::Continue, |hooks, t| hooks.start(t))?;
                if let Some(exit) = self.resume(resume, restored)? {
                    return Ok(exit);
                }
            }
            Some(Pending::Exec(request)) => {
                self.hooks((), |hooks, t| hooks.exec(t, &request))?;
            }
            None => {}
        }
        loop {
            if let Some(exit) = self.advance()? {
                return Ok(exit);
            }
        }
    }

    /// Calls every hook with `call`, returning the first result other than `default` (or
    /// `default`), and whether one restored a checkpoint.
    fn hooks<R: PartialEq>(
        &mut self,
        default: R,
        mut call: impl FnMut(&mut dyn Hooks, &mut ThreadCx) -> Result<R>,
    ) -> Result<(R, bool)> {
        let mut hooks = lock(&self.shared.hooks);
        let mut t = ThreadCx {
            vm: &mut *self.vm,
            thread: &*self.thread,
            loader: self.loader,
            restored: false,
        };
        let mut chosen = None;
        for hooks in hooks.iter_mut() {
            let result = call(hooks.as_mut(), &mut t)?;
            if chosen.is_none() && result != default {
                chosen = Some(result);
            }
        }
        let restored = t.restored;
        Ok((chosen.unwrap_or(default), restored))
    }

    /// Calls the scheduler (if the threads have one) with `call`.
    fn scheduler<R>(
        &mut self,
        call: impl FnOnce(&mut dyn Scheduler, &mut ThreadCx) -> Result<R>,
    ) -> Result<Option<(R, bool)>> {
        let Some(scheduler) = &self.shared.scheduler else {
            return Ok(None);
        };
        let mut scheduler = lock(scheduler);
        let mut t = ThreadCx {
            vm: &mut *self.vm,
            thread: &*self.thread,
            loader: self.loader,
            restored: false,
        };
        let result = call(scheduler.as_mut(), &mut t)?;
        Ok(Some((result, t.restored)))
    }

    /// Runs the thread until something happens, and deals with it. Returns how the thread (or
    /// guest) ended, if it did.
    fn advance(&mut self) -> Result<Option<ExitKind>> {
        let slice = match self.scheduler(|scheduler, t| scheduler.slice(t))? {
            Some((slice, _)) => slice,
            None => Slice::Unlimited,
        };
        if let Slice::Stop = slice {
            self.stepping = false;
            return self.stop(Stop::Scheduled);
        }
        if self.stepping {
            return self.step(&slice);
        }
        if std::mem::take(&mut self.leaving_stop) {
            let pc = self.vm.vcpu.get_reg(av::Reg::PC)?;
            if self.vm.hardware_breakpoints().contains(&Some(pc)) {
                self.vm.single_step()?;
                return match self.vm.run()? {
                    VmRunResult::Step => Ok(None),
                    result => self.handle(result),
                };
            }
        }
        match slice {
            Slice::Unlimited => {
                let result = self.vm.run()?;
                self.handle(result)
            }
            Slice::Until(end) => {
                let Some(left) = end.checked_duration_since(Instant::now()) else {
                    return self.slice_ended();
                };
                self.vm.arm_timer(left)?;
                let result = self.vm.run();
                self.vm.disarm_timer()?;
                match result? {
                    VmRunResult::Timer => self.slice_ended(),
                    result => self.handle(result),
                }
            }
            Slice::At(ref target) | Slice::Near(ref target) => {
                let exact = matches!(slice, Slice::At(_));
                match self.land(target, exact)? {
                    Landing::Reached => self.slice_ended(),
                    Landing::Missed { at_syscall } => self.missed(target, at_syscall),
                    Landing::Event(result) => self.handle(result),
                }
            }
            Slice::Stop => unreachable!("handled above"),
        }
    }

    /// Executes one instruction for a hook's [`Resume::Step`] (unless the thread's slice ends
    /// right where it is), and stops.
    fn step(&mut self, slice: &Slice) -> Result<Option<ExitKind>> {
        self.stepping = false;
        if let Slice::At(target) = slice {
            if target.is_at(&Registers::save(&self.vm.vcpu)?) {
                if let Some(exit) = self.slice_ended()? {
                    return Ok(Some(exit));
                }
                return self.stop(Stop::Step);
            }
        }
        self.vm.single_step()?;
        match self.vm.run()? {
            VmRunResult::Step => self.stop(Stop::Step),
            VmRunResult::Svc => match self.syscall()? {
                Some(exit) => Ok(Some(exit)),
                None => self.stop(Stop::Step),
            },
            result => self.handle(result),
        }
    }

    /// Runs to `target` (or near it, unless `exact`); see [`Slice::At`].
    fn land(&mut self, target: &Target, exact: bool) -> Result<Landing> {
        anyhow::ensure!(
            self.vm.counting_instructions(),
            "finding targets needs GuestBuilder::count_instructions"
        );
        // Coarse: timed runs, aiming short of the target.
        if !target.careful {
            loop {
                let progress = self.vm.guest_instructions();
                let remaining =
                    target.instructions as f64 - progress as f64 - TARGET_MARGIN as f64;
                let ns = remaining * 0.8 / target.max_instructions_per_ns;
                if ns < MIN_TIMER_NS {
                    break;
                }
                self.vm.arm_timer(std::time::Duration::from_nanos(ns as u64))?;
                let result = self.vm.run();
                self.vm.disarm_timer()?;
                match result? {
                    VmRunResult::Timer => {}
                    // The target comes before the thread's next syscall.
                    VmRunResult::Svc => return Ok(Landing::Missed { at_syscall: true }),
                    result => return Ok(Landing::Event(result)),
                }
            }
        }
        if !exact {
            return Ok(Landing::Reached);
        }

        // Precise: the first breakpoint hit with the target's registers. Each hit retires at
        // least an instruction, so more hits than could possibly remain mean it was missed.
        let progress = self.vm.guest_instructions();
        let max_hits = target.instructions.saturating_sub(progress) + MISSED_SLACK;
        self.vm
            .set_hardware_breakpoint_slot(LANDING_SLOT, Some(target.registers.pc))?;
        let landing = (|| {
            let mut hits = 0u64;
            loop {
                match self.vm.run()? {
                    VmRunResult::HardwareBreakpoint => {
                        let registers = Registers::save(&self.vm.vcpu)?;
                        if target.is_at(&registers) {
                            return Ok(Landing::Reached);
                        }
                        let hooks_breakpoint = self.vm.hardware_breakpoints()[LANDING_SLOT + 1..]
                            .contains(&Some(registers.pc));
                        if hooks_breakpoint {
                            return Ok(Landing::Event(VmRunResult::HardwareBreakpoint));
                        }
                        hits += 1;
                        if hits > max_hits {
                            return Ok(Landing::Missed { at_syscall: false });
                        }
                        self.vm.single_step()?;
                    }
                    VmRunResult::Timer | VmRunResult::Step => {}
                    VmRunResult::Svc => return Ok(Landing::Missed { at_syscall: true }),
                    result => return Ok(Landing::Event(result)),
                }
            }
        })();
        self.vm.set_hardware_breakpoint_slot(LANDING_SLOT, None)?;
        landing
    }

    /// The thread's slice ended.
    fn slice_ended(&mut self) -> Result<Option<ExitKind>> {
        let Some((preempt, restored)) = self.scheduler(|scheduler, t| scheduler.preempt(t))? else {
            return Ok(None);
        };
        if restored {
            return Ok(None);
        }
        match preempt {
            Preempt::Continue => {}
            Preempt::Step => self.stepping = true,
            Preempt::Switch => {
                let registers = Registers::save(&self.vm.vcpu)?;
                let instructions = self.vm.guest_instructions();
                let shared = self.vm.shared().clone();
                let switch = self
                    .thread
                    .handler()
                    .preempt(&self.vm.vcpu, &mut shared.vma())?;
                if let Some(switch) = switch {
                    let preemption = Preemption {
                        switch,
                        registers,
                        instructions,
                    };
                    self.hooks((), |hooks, t| hooks.preempted(t, &preemption))?;
                }
            }
        }
        Ok(None)
    }

    /// The thread ran past its slice's `target`, into a syscall if `at_syscall`.
    fn missed(&mut self, target: &Target, at_syscall: bool) -> Result<Option<ExitKind>> {
        let restored = match self.scheduler(|scheduler, t| scheduler.missed(t, target))? {
            Some((_, restored)) => restored,
            None => false,
        };
        if at_syscall && !restored {
            return self.syscall();
        }
        Ok(None)
    }

    /// Deals with what stopped the vCPU.
    fn handle(&mut self, result: VmRunResult) -> Result<Option<ExitKind>> {
        match result {
            VmRunResult::Svc => self.syscall(),
            VmRunResult::HardwareBreakpoint => {
                let addr = self.vm.vcpu.get_reg(av::Reg::PC)?;
                self.stop(Stop::Breakpoint { addr })
            }
            VmRunResult::Watchpoint { addr } => {
                let kind = self
                    .vm
                    .hardware_watchpoints()
                    .iter()
                    .flatten()
                    .find(|w| w.addr <= addr && addr < w.addr + w.len.max(8))
                    .or_else(|| self.vm.hardware_watchpoints().iter().flatten().next())
                    .map(|w| w.kind)
                    .ok_or_else(|| anyhow::anyhow!("hit a watchpoint that isn't set"))?;
                // It stopped before the access; report it once done.
                self.vm.single_step()?;
                match self.vm.run()? {
                    VmRunResult::Step => self.stop(Stop::Watchpoint { addr, kind }),
                    result => self.handle(result),
                }
            }
            VmRunResult::Step | VmRunResult::Timer => Ok(None),
            VmRunResult::Stopped => Ok(Some(ExitKind::ThreadExit)),
            VmRunResult::Brk => {
                let pc = self.vm.vcpu.get_reg(av::Reg::PC)?;
                self.fault(GuestFault {
                    kind: FaultKind::Trap,
                    pc,
                    address: None,
                    syndrome: 0,
                })
            }
            VmRunResult::Other(exit) => match exit.reason {
                av::ExitReason::EXCEPTION => {
                    let fault = self.decode_fault(&exit)?;
                    self.fault(fault)
                }
                // Kicked out, e.g. by a stop that's since been dealt with.
                av::ExitReason::CANCELED => Ok(None),
                reason => anyhow::bail!(
                    "vCPU exited unexpectedly ({reason:?}) at {:#x}",
                    self.vm.vcpu.get_reg(av::Reg::PC)?
                ),
            },
        }
    }

    /// The exception the guest took, which appbox didn't handle.
    fn decode_fault(&self, exit: &av::VcpuExit) -> Result<GuestFault> {
        let vcpu = &self.vm.vcpu;
        let (syndrome, pc, address) = match ExceptionClass::from(exit.exception.syndrome >> 26) {
            // At EL0, taken to appbox's vectors, which hand it over.
            ExceptionClass::HvcA64 => {
                let esr = vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                anyhow::ensure!(esr != SVC_ESR, "a syscall isn't a fault");
                (
                    esr,
                    vcpu.get_sys_reg(av::SysReg::ELR_EL1)?,
                    vcpu.get_sys_reg(av::SysReg::FAR_EL1)?,
                )
            }
            // Stage 2: guest physical memory that isn't there.
            _ => (
                exit.exception.syndrome,
                vcpu.get_reg(av::Reg::PC)?,
                exit.exception.virtual_address,
            ),
        };
        let kind = match ExceptionClass::from(syndrome >> 26) {
            ExceptionClass::DataAbortLowerEl | ExceptionClass::DataAbortCurEl => FaultKind::DataAbort,
            ExceptionClass::InsAbortLowerEl | ExceptionClass::InsAbortCurEl => {
                FaultKind::InstructionAbort
            }
            ExceptionClass::PcALignmentFault | ExceptionClass::SpALignmentFault => {
                FaultKind::Alignment
            }
            ExceptionClass::Unknown(0) => FaultKind::UndefinedInstruction,
            ExceptionClass::FpTrapA64 => FaultKind::FloatingPoint,
            ExceptionClass::BrkA64 => FaultKind::Trap,
            _ => FaultKind::Other,
        };
        let aborted = matches!(kind, FaultKind::DataAbort | FaultKind::InstructionAbort);
        Ok(GuestFault {
            kind,
            pc,
            address: aborted.then_some(address),
            syndrome,
        })
    }

    fn fault(&mut self, fault: GuestFault) -> Result<Option<ExitKind>> {
        let (resume, restored) =
            self.hooks(Resume::End(fault.crash()), |hooks, t| hooks.fault(t, &fault))?;
        if resume != Resume::End(fault.crash()) && !restored {
            // Retry the instruction, back at EL0 if it had been taken to the vectors.
            let vcpu = &self.vm.vcpu;
            const PSTATE_MODE: u64 = 0xf;
            if vcpu.get_reg(av::Reg::CPSR)? & PSTATE_MODE != 0 {
                vcpu.set_reg(av::Reg::PC, vcpu.get_sys_reg(av::SysReg::ELR_EL1)?)?;
                vcpu.set_reg(av::Reg::CPSR, vcpu.get_sys_reg(av::SysReg::SPSR_EL1)?)?;
            }
        }
        self.resume(resume, restored)
    }

    fn stop(&mut self, stop: Stop) -> Result<Option<ExitKind>> {
        let (resume, restored) =
            self.hooks(Resume::Continue, |hooks, t| hooks.stopped(t, &stop))?;
        self.resume(resume, restored)
    }

    /// Carries on as a hook said, from where it stopped unless it `restored` a checkpoint.
    fn resume(&mut self, resume: Resume, restored: bool) -> Result<Option<ExitKind>> {
        match resume {
            Resume::Continue => self.leaving_stop = !restored,
            Resume::Step => self.stepping = true,
            Resume::End(end) => return self.end(end),
        }
        Ok(None)
    }

    /// Ends the guest with `end`, unless a hook prevents it.
    fn end(&mut self, end: GuestEnd) -> Result<Option<ExitKind>> {
        let (resume, restored) =
            self.hooks(Resume::End(end.clone()), |hooks, t| hooks.ending(t, &end))?;
        match resume {
            Resume::End(end) => {
                let exit = exit_kind(&end);
                *lock(&self.shared.ending) = Some(end);
                Ok(Some(exit))
            }
            resume => self.resume(resume, restored),
        }
    }

    /// Handles the syscall the thread is making.
    fn syscall(&mut self) -> Result<Option<ExitKind>> {
        let context = read_syscall_context(&mut self.vm.vcpu)?;
        let call = Syscall {
            number: context.num,
            args: context.args,
            return_address: context.elr,
        };
        let (decision, restored) =
            self.hooks(Decision::Default, |hooks, t| hooks.syscall(t, &call))?;
        if restored {
            return Ok(None);
        }
        let outcome = match decision {
            Decision::Default => {
                let result = self.thread.handle_syscall(&context, self.vm, self.loader)?;
                match result.exit {
                    ExitKind::Continue => match result.thread_switch {
                        Some(switch) => Outcome::Switched(switch),
                        None => {
                            if result.write_back {
                                write_syscall_result(
                                    &mut self.vm.vcpu,
                                    context.elr,
                                    result.ret0,
                                    result.ret1,
                                    result.cflags,
                                )?;
                            }
                            Outcome::Returned(Returned {
                                x0: result.ret0,
                                x1: result.ret1,
                                flags: result.cflags,
                            })
                        }
                    },
                    ExitKind::Exit => Outcome::Ended(GuestEnd::Exited(
                        self.thread.handler().exit_status().unwrap_or(0),
                    )),
                    ExitKind::ThreadExit => Outcome::ThreadExited,
                    ExitKind::Exec(request) => Outcome::Exec(request),
                    ExitKind::Crash(reason) => Outcome::Ended(GuestEnd::Crashed {
                        signal: Signal::SIGABRT,
                        reason,
                    }),
                    other => Outcome::Ended(GuestEnd::Crashed {
                        signal: Signal::SIGKILL,
                        reason: format!("{other:?}"),
                    }),
                }
            }
            Decision::Return(returned) => {
                write_syscall_result(
                    &mut self.vm.vcpu,
                    context.elr,
                    returned.x0,
                    returned.x1,
                    returned.flags,
                )?;
                Outcome::Returned(returned)
            }
            Decision::Resumed => Outcome::Resumed,
            Decision::End(end) => Outcome::Ended(end),
        };
        let (_, restored) =
            self.hooks((), |hooks, t| hooks.syscall_done(t, &call, &outcome))?;
        if restored {
            return Ok(None);
        }
        match outcome {
            Outcome::Ended(end) => self.end(end),
            Outcome::Exec(request) => Ok(Some(ExitKind::Exec(request))),
            Outcome::ThreadExited => Ok(Some(ExitKind::ThreadExit)),
            Outcome::Returned(_) | Outcome::Resumed | Outcome::Switched(_) => Ok(None),
        }
    }
}
