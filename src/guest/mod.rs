//! Running a guest program, with callbacks for what an embedder wants to observe or change.
//!
//! [`Guest`] does everything a guest needs: the VM and its memory, loading the program and the
//! shared cache, handling its syscalls, running its threads (time-shared or in parallel), exec,
//! and the processes it spawns. An embedder observes and steers it through [`Hooks`] (syscalls,
//! stops, faults and so on) and, when threads are time-shared, a [`Scheduler`] (which thread runs,
//! and for how long, down to exact instructions).
//!
//! ```ignore
//! // First thing in main: this may re-run the program, or run a guest the parent spawned.
//! let program = appbox::guest::prepare()?.unwrap_or(Program::new(path, argv, envp));
//! let end = Guest::builder(program).hooks(MyHooks::default()).run()?;
//! end.end_process();
//! ```

mod cx;
mod drive;
mod memory;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::signal::Signal;

pub use crate::checkpoint::Checkpoint;
pub use crate::exec::ExecRequest;
use crate::hyperpom::crash::ExitKind;
pub use crate::symbols::Symbolication;
pub use crate::threading::ThreadingModel;
pub use crate::threads::{Registers, ThreadId, ThreadSwitch};
pub use crate::trap::{forward_syscall, GuestMemoryChanges};
use crate::trap::DefaultTrapHandler;
pub use crate::vm::{WatchKind, Watchpoint};
use crate::vm::VmManager;
pub use cx::ThreadCx;
pub use memory::Memory;

/// How long a thread runs before others get a turn, with the default [`RoundRobin`] scheduler.
pub const DEFAULT_QUANTUM: Duration = Duration::from_millis(1);

/// A program to run as a guest.
#[derive(Clone, Debug)]
pub struct Program {
    pub path: PathBuf,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

impl Program {
    pub fn new(path: impl Into<PathBuf>, argv: Vec<String>, envp: Vec<String>) -> Self {
        Self {
            path: path.into(),
            argv,
            envp,
        }
    }
}

/// Sets up this (host) process to run a guest, which has to happen before it does anything else
/// of note: it re-runs the program in a child whose memory layout leaves the guest room (only
/// the child returns from this). Returns the program to run instead of the embedder's own, if
/// this process was started for one a guest spawned.
///
/// The binary must be signed with the `com.apple.security.cs.debugger` and
/// `com.apple.security.get-task-allow` entitlements.
pub fn prepare() -> Result<Option<Program>> {
    crate::respawn::respawn()?;
    Ok(crate::respawn::spawned_guest()?.map(|request| Program {
        path: request.path,
        argv: request.argv,
        envp: request.envp,
    }))
}

/// How a guest ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestEnd {
    /// It exited with this status.
    Exited(i32),
    /// It crashed (or was killed), as if by `signal`.
    Crashed { signal: Signal, reason: String },
}

impl GuestEnd {
    /// Ends this (host) process like the guest ended, e.g. so that a guest's parent waiting for
    /// the process sees the guest's status.
    pub fn end_process(self) -> ! {
        match self {
            GuestEnd::Exited(status) => std::process::exit(status),
            GuestEnd::Crashed { signal, .. } => crate::respawn::die_by_signal(signal),
        }
    }
}

/// A syscall (or Mach trap) a guest thread made.
#[derive(Clone, Debug)]
pub struct Syscall {
    /// Negative for Mach traps.
    pub number: u64,
    pub args: [u64; 16],
    /// Where the thread resumes once it returns, just after the `svc`.
    pub return_address: u64,
}

impl Syscall {
    pub fn name(&self) -> Option<&'static str> {
        crate::syscalls::syscall_name(self.number)
    }
}

/// What a syscall returns: `x0`, `x1`, and the condition flags, whose carry is set on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Returned {
    pub x0: u64,
    pub x1: u64,
    pub flags: u64,
}

const CARRY: u64 = 1 << 29;

impl Returned {
    pub fn ok(x0: u64) -> Self {
        Self { x0, x1: 0, flags: 0 }
    }

    pub fn errno(errno: i32) -> Self {
        Self {
            x0: errno as u64,
            x1: 0,
            flags: CARRY,
        }
    }

    pub fn failed(&self) -> bool {
        self.flags & CARRY != 0
    }
}

/// What to do with a syscall, from [`Hooks::syscall`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Handle it as appbox does.
    Default,
    /// Don't: return this instead.
    Return(Returned),
    /// Don't: the hook has already put the thread's registers how they should be.
    Resumed,
    /// End the guest.
    End(GuestEnd),
}

/// How a syscall turned out, for [`Hooks::syscall_done`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Returned(Returned),
    /// A hook put the thread's registers in place (see [`Decision::Resumed`]).
    Resumed,
    /// The thread blocked, so another one is on the vCPU now (time-shared).
    Switched(ThreadSwitch),
    /// The thread exited.
    ThreadExited,
    Exec(ExecRequest),
    Ended(GuestEnd),
}

/// Why a thread stopped, for [`Hooks::stopped`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// About to execute `addr`, where one of its hardware breakpoints is.
    Breakpoint { addr: u64 },
    /// Just accessed `addr`, which one of its hardware watchpoints covers.
    Watchpoint { addr: u64, kind: WatchKind },
    /// Executed the one instruction [`Resume::Step`] asked for (which may have been a syscall).
    Step,
    /// The scheduler stopped it ([`Slice::Stop`]).
    Scheduled,
}

/// How to carry on after a stop, fault or the like.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resume {
    Continue,
    /// Execute one instruction, then stop ([`Stop::Step`]).
    Step,
    End(GuestEnd),
}

/// What went wrong, for [`GuestFault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// A `brk` (e.g. `__builtin_trap()`).
    Trap,
    /// A load or store to memory it can't access.
    DataAbort,
    /// Executing memory it can't.
    InstructionAbort,
    Alignment,
    UndefinedInstruction,
    FloatingPoint,
    Other,
}

/// An exception the guest took that appbox doesn't handle, which natively would kill it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestFault {
    pub kind: FaultKind,
    /// The instruction that faulted.
    pub pc: u64,
    /// The address accessed, for aborts.
    pub address: Option<u64>,
    /// `ESR_EL1`, the exception's syndrome.
    pub syndrome: u64,
}

impl GuestFault {
    /// The signal the kernel would kill the process with.
    pub fn signal(&self) -> Signal {
        match self.kind {
            FaultKind::Trap => Signal::SIGTRAP,
            FaultKind::DataAbort | FaultKind::InstructionAbort | FaultKind::Other => {
                Signal::SIGSEGV
            }
            FaultKind::Alignment => Signal::SIGBUS,
            FaultKind::UndefinedInstruction => Signal::SIGILL,
            FaultKind::FloatingPoint => Signal::SIGFPE,
        }
    }

    pub fn crash(&self) -> GuestEnd {
        GuestEnd::Crashed {
            signal: self.signal(),
            reason: format!("{:?} at {:#x}", self.kind, self.pc),
        }
    }
}

/// A thread taken off the vCPU at the end of its slice, for [`Hooks::preempted`].
#[derive(Clone, Debug)]
pub struct Preemption {
    pub switch: ThreadSwitch,
    /// The preempted thread's registers where it was preempted.
    pub registers: Registers,
    /// [`ThreadCx::guest_instructions`] then.
    pub instructions: u64,
}

/// Callbacks for what a guest does. Each is called on the host thread running the guest thread
/// concerned, one at a time (with parallel threads too), and gets that thread's [`ThreadCx`].
/// Every method has a default that leaves the guest to appbox.
///
/// With several hooks, all are called in order, and the first result other than the default
/// wins.
pub trait Hooks: Send {
    /// Before the guest's first instruction.
    fn start(&mut self, _t: &mut ThreadCx) -> Result<Resume> {
        Ok(Resume::Continue)
    }

    /// Before appbox handles a syscall.
    fn syscall(&mut self, _t: &mut ThreadCx, _call: &Syscall) -> Result<Decision> {
        Ok(Decision::Default)
    }

    /// After a syscall. If another thread was switched to, `t` is that thread's.
    fn syscall_done(&mut self, _t: &mut ThreadCx, _call: &Syscall, _outcome: &Outcome) -> Result<()> {
        Ok(())
    }

    /// After a (time-shared) thread was preempted for another; `t` is the new thread's.
    fn preempted(&mut self, _t: &mut ThreadCx, _preemption: &Preemption) -> Result<()> {
        Ok(())
    }

    /// At a hardware breakpoint or watchpoint (see [`ThreadCx`]), or a step.
    fn stopped(&mut self, _t: &mut ThreadCx, _stop: &Stop) -> Result<Resume> {
        Ok(Resume::Continue)
    }

    /// At an exception that natively would kill the guest.
    fn fault(&mut self, _t: &mut ThreadCx, fault: &GuestFault) -> Result<Resume> {
        Ok(Resume::End(fault.crash()))
    }

    /// Once the guest has exec'd, from the new image's first instruction.
    fn exec(&mut self, _t: &mut ThreadCx, _request: &ExecRequest) -> Result<()> {
        Ok(())
    }

    /// When the guest is about to end, which a hook may prevent by restoring a checkpoint (see
    /// [`ThreadCx::restore`]) and continuing.
    fn ending(&mut self, _t: &mut ThreadCx, end: &GuestEnd) -> Result<Resume> {
        Ok(Resume::End(end.clone()))
    }
}

/// How far the thread on the vCPU may run, from [`Scheduler::slice`].
#[derive(Clone, Debug)]
pub enum Slice {
    /// Until it blocks (or stops or the like).
    Unlimited,
    Until(Instant),
    /// Exactly to `target`: its first instruction there with its registers.
    At(Target),
    /// To somewhere shortly before `target` (within a margin covering how inexact instruction
    /// counts are), e.g. to step the rest of the way.
    Near(Target),
    /// Not at all: it stops where it is ([`Hooks::stopped`] with [`Stop::Scheduled`]).
    Stop,
}

/// A point in a thread's execution, to stop at.
#[derive(Clone, Debug)]
pub struct Target {
    /// [`ThreadCx::guest_instructions`] there, or more (the count only ever overestimates).
    pub instructions: u64,
    /// The thread's registers there. A loop whose registers are the same from one iteration to
    /// the next makes each iteration the same point.
    pub registers: Registers,
    /// Find it with breakpoints alone, without timing the guest to get close first: slower, but
    /// it can't overshoot (see [`Scheduler::missed`]).
    pub careful: bool,
    /// How fast the guest is assumed to retire instructions at most, when timing it.
    pub max_instructions_per_ns: f64,
}

/// Faster than any Apple core retires instructions (8 per cycle at ~3.2GHz), so a timed run sized
/// assuming it can't overshoot. Measuring the rate instead isn't safe: a run in which the host
/// descheduled the vCPU's thread measures slow.
pub const MAX_INSTRUCTIONS_PER_NS: f64 = 26.0;

impl Target {
    pub fn new(instructions: u64, registers: Registers) -> Self {
        Self {
            instructions,
            registers,
            careful: false,
            max_instructions_per_ns: MAX_INSTRUCTIONS_PER_NS,
        }
    }

    /// Whether `registers` are at this point.
    pub fn is_at(&self, registers: &Registers) -> bool {
        let (a, b) = (&self.registers, registers);
        a.pc == b.pc && a.sp == b.sp && a.x == b.x && a.q == b.q && a.cpsr >> 28 == b.cpsr >> 28
    }
}

/// What to do at the end of a slice, from [`Scheduler::preempt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preempt {
    /// Switch to another thread (which [`Scheduler::next_thread`] picks), if one can run.
    Switch,
    /// Keep running this one (for another slice).
    Continue,
    /// Execute one instruction, then [`Hooks::stopped`] with [`Stop::Step`].
    Step,
}

/// Decides which (time-shared) thread runs, and for how long. Called on the vCPU's host thread.
pub trait Scheduler: Send {
    /// How far the thread on the vCPU may run before [`Self::preempt`]. Asked again whenever it
    /// resumes after something happened (a syscall, a stop, a switch or a restore).
    fn slice(&mut self, t: &mut ThreadCx) -> Result<Slice>;

    /// The thread reached the end of its slice.
    fn preempt(&mut self, _t: &mut ThreadCx) -> Result<Preempt> {
        Ok(Preempt::Switch)
    }

    /// The thread ran past its [`Slice::At`] or [`Slice::Near`] target without stopping there
    /// (the guest was timed too generously). Going back to an earlier checkpoint
    /// ([`ThreadCx::restore`]) and finding it carefully (see [`Target::careful`]) recovers.
    fn missed(&mut self, _t: &mut ThreadCx, target: &Target) -> Result<()> {
        anyhow::bail!("ran past {target:x?}")
    }

    /// Which of the `runnable` threads (in round-robin order after `from`) to switch to.
    fn next_thread(&mut self, _from: Option<ThreadId>, runnable: &[ThreadId]) -> ThreadId {
        runnable[0]
    }
}

/// The default scheduler: threads take turns, each for a quantum at most, while others could
/// run.
pub struct RoundRobin {
    quantum: Option<Duration>,
    slice: Option<(ThreadId, Instant)>,
}

impl RoundRobin {
    /// `None` only switches threads when one blocks.
    pub fn new(quantum: Option<Duration>) -> Self {
        Self {
            quantum,
            slice: None,
        }
    }
}

impl Scheduler for RoundRobin {
    fn slice(&mut self, t: &mut ThreadCx) -> Result<Slice> {
        let Some(quantum) = self.quantum.filter(|_| t.contended()) else {
            return Ok(Slice::Unlimited);
        };
        let thread = t.thread();
        let now = Instant::now();
        let end = match self.slice {
            Some((current, end)) if current == thread && end > now => end,
            _ => now + quantum,
        };
        self.slice = Some((thread, end));
        Ok(Slice::Until(end))
    }
}

/// Builds a [`Guest`]; see [`Guest::builder`].
pub struct GuestBuilder {
    program: Program,
    threading: ThreadingModel,
    hooks: Vec<Box<dyn Hooks>>,
    scheduler: Option<Box<dyn Scheduler>>,
    count_instructions: bool,
}

impl GuestBuilder {
    pub fn threading(mut self, threading: ThreadingModel) -> Self {
        self.threading = threading;
        self
    }

    /// Adds hooks, called after those added before.
    pub fn hooks(mut self, hooks: impl Hooks + 'static) -> Self {
        self.hooks.push(Box::new(hooks));
        self
    }

    /// Replaces the default [`RoundRobin`] scheduler (with [`DEFAULT_QUANTUM`]). Only for
    /// [`ThreadingModel::TimeShared`].
    pub fn scheduler(mut self, scheduler: impl Scheduler + 'static) -> Self {
        self.scheduler = Some(Box::new(scheduler));
        self
    }

    /// Counts the instructions the guest retires (see [`ThreadCx::guest_instructions`]), which
    /// [`Slice::At`] and [`Slice::Near`] need. It costs a calibration at startup (and exec).
    pub fn count_instructions(mut self) -> Self {
        self.count_instructions = true;
        self
    }

    pub fn build(self) -> Result<Guest> {
        let mut handler = DefaultTrapHandler::new(self.threading)?;
        // A guest that parallel threads spawned has them too, whatever was asked for.
        anyhow::ensure!(
            handler.threading() == ThreadingModel::TimeShared || self.scheduler.is_none(),
            "only time-shared threads have a scheduler"
        );
        let scheduler = (handler.threading() == ThreadingModel::TimeShared).then(|| {
            Arc::new(Mutex::new(
                self.scheduler
                    .unwrap_or_else(|| Box::new(RoundRobin::new(Some(DEFAULT_QUANTUM)))),
            ))
        });
        if let Some(scheduler) = &scheduler {
            let scheduler = scheduler.clone();
            handler.pick_thread = Some(Box::new(move |from, runnable| {
                lock(&scheduler).next_thread(from, runnable)
            }));
        }
        let (vm, loader) = load(&self.program, self.count_instructions)?;
        Ok(Guest {
            vm,
            loader: Arc::new(loader),
            handler,
            shared: Arc::new(drive::Shared {
                hooks: Mutex::new(self.hooks),
                scheduler,
                ending: Mutex::new(None),
                pending: Mutex::new(Some(drive::Pending::Start)),
            }),
            count_instructions: self.count_instructions,
        })
    }

    /// Builds the guest and runs it; see [`Guest::run`].
    pub fn run(self) -> Result<GuestEnd> {
        self.build()?.run()
    }
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Creates a VM with `program` loaded, ready to start.
fn load(program: &Program, count_instructions: bool) -> Result<(VmManager, crate::loader::Loader)> {
    let mut vm = VmManager::new()?;
    let loader = crate::loader::load_macho(
        &mut vm,
        &program.path,
        program.argv.clone(),
        program.envp.clone(),
    )
    .with_context(|| format!("loading {}", program.path.display()))?;
    vm.vcpu.set_reg(crate::applevisor::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(crate::applevisor::SysReg::SP_EL0, loader.stack_pointer)?;
    if count_instructions {
        vm.count_instructions()?;
    }
    Ok((vm, loader))
}

/// A guest program, ready to run.
pub struct Guest {
    vm: VmManager,
    loader: Arc<crate::loader::Loader>,
    handler: DefaultTrapHandler,
    shared: Arc<drive::Shared>,
    count_instructions: bool,
}

impl Guest {
    pub fn builder(program: Program) -> GuestBuilder {
        GuestBuilder {
            program,
            threading: ThreadingModel::TimeShared,
            hooks: Vec::new(),
            scheduler: None,
            count_instructions: false,
        }
    }

    /// Runs the guest (through its execs) until it ends.
    pub fn run(self) -> Result<GuestEnd> {
        let Guest {
            mut vm,
            mut loader,
            mut handler,
            shared,
            count_instructions,
        } = self;
        let runner: Arc<crate::runner::ThreadRunner> = {
            let shared = shared.clone();
            Arc::new(move |vm: &mut VmManager, thread: &mut crate::runner::GuestThread, loader: &crate::loader::Loader| {
                drive::Driver::new(vm, thread, loader, &shared).run()
            })
        };
        loop {
            let exit;
            (exit, handler) = handler.run(&mut vm, &loader, &runner)?;
            match exit {
                ExitKind::Exec(request) => {
                    let old = Arc::into_inner(loader).context("guest threads outlived an exec")?;
                    let new;
                    (vm, new) = crate::exec::exec(vm, old, &mut handler, &request)?;
                    if count_instructions {
                        vm.count_instructions()?;
                    }
                    loader = Arc::new(new);
                    *lock(&shared.pending) = Some(drive::Pending::Exec(request));
                }
                exit => return Ok(shared.take_ending(exit, &handler)),
            }
        }
    }
}
