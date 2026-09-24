//! Guest threads, time-shared on the VM's one vCPU.
//!
//! Only one guest thread runs at a time; the others are saved register states. That keeps the
//! guest's execution deterministic apart from where threads are switched, which callers can
//! record.
//!
//! Each guest thread has a host "proxy" thread that runs its forwarded syscalls, so the kernel
//! sees one thread per guest thread: thread ports, ulock ownership, per-thread signal masks, QoS
//! and so on all behave as they would natively, and one guest thread blocking in a syscall only
//! blocks its proxy.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::applevisor as av;
use crate::trap::forward_syscall;
use crate::workq::EventSource;

/// appbox's own guest thread identifier: 0 is the main thread, and later threads are numbered in
/// creation order, so they're the same in every run of the same guest.
pub type ThreadId = u32;

pub(crate) const MAIN_THREAD: ThreadId = 0;

/// A syscall's return registers: x0, x1 and the NZCV flags (carry set on error).
pub(crate) type SyscallReturn = (u64, u64, u64);

const X_REGS: [av::Reg; 31] = {
    use av::Reg::*;
    [
        X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19,
        X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, X30,
    ]
};

const Q_REGS: [av::SimdFpReg; 32] = {
    use av::SimdFpReg::*;
    [
        Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19,
        Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    ]
};

/// The user (EL0) register state of a guest thread that isn't on the vCPU.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registers {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u64,
    pub q: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
    pub tpidr: u64,
    pub tpidrro: u64,
}

impl Registers {
    /// Saves the state of the thread on `vcpu`, which is stopped at a syscall (i.e. in the EL1
    /// exception handler), as it will be once the syscall returns.
    pub fn save_at_syscall(vcpu: &av::Vcpu) -> Result<Self> {
        let mut regs = Self {
            sp: vcpu.get_sys_reg(av::SysReg::SP_EL0)?,
            pc: vcpu.get_sys_reg(av::SysReg::ELR_EL1)?,
            cpsr: vcpu.get_sys_reg(av::SysReg::SPSR_EL1)?,
            fpcr: vcpu.get_reg(av::Reg::FPCR)?,
            fpsr: vcpu.get_reg(av::Reg::FPSR)?,
            tpidr: vcpu.get_sys_reg(av::SysReg::TPIDR_EL0)?,
            tpidrro: vcpu.get_sys_reg(av::SysReg::TPIDRRO_EL0)?,
            ..Default::default()
        };
        for (value, reg) in regs.x.iter_mut().zip(X_REGS) {
            *value = vcpu.get_reg(reg)?;
        }
        for (value, reg) in regs.q.iter_mut().zip(Q_REGS) {
            *value = vcpu.get_simd_fp_reg(reg)?;
        }
        Ok(regs)
    }

    /// Puts this state on `vcpu`, so that running it resumes the thread in EL0.
    pub fn restore(&self, vcpu: &av::Vcpu) -> Result<()> {
        for (value, reg) in self.x.iter().zip(X_REGS) {
            vcpu.set_reg(reg, *value)?;
        }
        for (value, reg) in self.q.iter().zip(Q_REGS) {
            set_simd_fp_reg(vcpu, reg, *value)?;
        }
        vcpu.set_sys_reg(av::SysReg::SP_EL0, self.sp)?;
        vcpu.set_reg(av::Reg::PC, self.pc)?;
        vcpu.set_reg(av::Reg::CPSR, self.cpsr)?;
        vcpu.set_reg(av::Reg::FPCR, self.fpcr)?;
        vcpu.set_reg(av::Reg::FPSR, self.fpsr)?;
        vcpu.set_sys_reg(av::SysReg::TPIDR_EL0, self.tpidr)?;
        vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tpidrro)?;
        Ok(())
    }
}

unsafe extern "C" {
    fn hv_vcpu_set_simd_fp_reg(
        vcpu: applevisor_sys::hv_vcpu_t,
        reg: applevisor_sys::hv_simd_fp_reg_t,
        value: std::arch::aarch64::uint8x16_t,
    ) -> applevisor_sys::hv_return_t;
}

// applevisor's Vcpu::set_simd_fp_reg passes the value as a u128, but Hypervisor.framework takes
// a SIMD vector, which the arm64 calling convention passes in a vector register: it silently
// stores whatever happens to be in q0 instead. (applevisor's simd_nightly feature, which would
// fix this, no longer builds.)
fn set_simd_fp_reg(vcpu: &av::Vcpu, reg: av::SimdFpReg, value: u128) -> Result<()> {
    const _: () = assert!(
        std::mem::size_of::<av::VcpuInstance>() == std::mem::size_of::<applevisor_sys::hv_vcpu_t>()
    );
    // VcpuInstance only wraps the hv_vcpu_t, which it doesn't expose.
    let handle: applevisor_sys::hv_vcpu_t = unsafe { std::mem::transmute(vcpu.get_instance()) };
    let ret = unsafe {
        hv_vcpu_set_simd_fp_reg(handle, reg.into(), std::mem::transmute::<u128, _>(value))
    };
    if ret != applevisor_sys::hv_error_t::HV_SUCCESS as i32 {
        return Err(av::HypervisorError::from(ret).into());
    }
    Ok(())
}

struct Job {
    num: u64,
    args: [u64; 16],
}

/// Something the scheduler waits for.
pub(crate) enum Message {
    /// A proxy finished a syscall.
    Completed(ThreadId, SyscallReturn),
    /// A kqueue backing the guest's workqueue or one of its workloops has events to deliver.
    KeventsPending(EventSource),
}

/// A host thread that runs one guest thread's forwarded syscalls.
struct Proxy {
    jobs: Sender<Job>,
    /// The proxy's thread port name, i.e. the guest thread's.
    port: u32,
}

impl Proxy {
    fn spawn(id: ThreadId, messages: Sender<Message>) -> Result<Self> {
        let (jobs, pending) = channel::<Job>();
        let (port_tx, port_rx) = channel();
        std::thread::Builder::new()
            .name(format!("appbox-guest-{id}"))
            .spawn(move || {
                let _ = port_tx.send(unsafe { nix::libc::mach_thread_self() });
                for job in pending {
                    let ret = forward_syscall(job.num, &job.args);
                    if messages.send(Message::Completed(id, ret)).is_err() {
                        break;
                    }
                }
            })
            .context("spawning syscall proxy thread")?;
        let port = port_rx.recv().context("syscall proxy thread exited")?;
        Ok(Self { jobs, port })
    }
}

enum State {
    /// On the vCPU.
    Running,
    Runnable(Registers),
    /// Waiting for a syscall on its proxy, or one appbox emulates; the registers are as they'll
    /// be once it returns, apart from the return value.
    Blocked(Registers),
    /// An idle workqueue thread, waiting to be given work.
    Parked,
}

struct Thread {
    proxy: Proxy,
    tsd: u64,
    state: State,
}

/// A change of which guest thread is on the vCPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadSwitch {
    /// `None` if the previous thread exited.
    pub from: Option<ThreadId>,
    pub to: ThreadId,
}

/// The result of forwarding a syscall for the current thread.
pub(crate) enum Forwarded {
    Returned(SyscallReturn),
    /// It's still running, so the thread is now blocked and another must be scheduled.
    Blocked,
}

// How long a syscall can take before its thread is treated as blocked and another thread (if
// any) is run instead.
const BLOCKING_THRESHOLD: Duration = Duration::from_millis(1);

pub(crate) struct Threads {
    threads: BTreeMap<ThreadId, Thread>,
    /// `None` between taking the current thread off the vCPU and scheduling another.
    current: Option<ThreadId>,
    next_id: ThreadId,
    messages: Receiver<Message>,
    messages_tx: Sender<Message>,
    kevents_pending: BTreeSet<EventSource>,
}

fn apply_return(regs: &mut Registers, (ret0, ret1, flags): SyscallReturn) {
    regs.x[0] = ret0;
    regs.x[1] = ret1;
    regs.cpsr = (regs.cpsr & !(0b1111 << 28)) | flags;
}

impl Threads {
    pub(crate) fn new() -> Result<Self> {
        let (messages_tx, messages) = channel();
        let main = Thread {
            proxy: Proxy::spawn(MAIN_THREAD, messages_tx.clone())?,
            tsd: 0,
            state: State::Running,
        };
        Ok(Self {
            threads: BTreeMap::from([(MAIN_THREAD, main)]),
            current: Some(MAIN_THREAD),
            next_id: MAIN_THREAD + 1,
            messages,
            messages_tx,
            kevents_pending: BTreeSet::new(),
        })
    }

    /// The thread on the vCPU.
    pub(crate) fn current(&self) -> ThreadId {
        self.current.expect("a thread is scheduled")
    }

    fn current_thread(&mut self) -> &mut Thread {
        let id = self.current();
        self.threads.get_mut(&id).expect("current thread exists")
    }

    pub(crate) fn tsd(&self) -> u64 {
        self.threads[&self.current()].tsd
    }

    pub(crate) fn set_tsd(&mut self, tsd: u64) {
        self.current_thread().tsd = tsd;
    }

    /// For telling the scheduler about kevents.
    pub(crate) fn message_sender(&self) -> Sender<Message> {
        self.messages_tx.clone()
    }

    /// The kqueues that have had events since last asked.
    pub(crate) fn take_kevents_pending(&mut self) -> BTreeSet<EventSource> {
        std::mem::take(&mut self.kevents_pending)
    }

    /// Adds a thread, runnable with the registers `regs` gets from its thread port.
    pub(crate) fn spawn(&mut self, regs: impl FnOnce(u32) -> Registers) -> Result<ThreadId> {
        let id = self.next_id;
        let proxy = Proxy::spawn(id, self.messages_tx.clone())?;
        let regs = regs(proxy.port);
        self.threads.insert(
            id,
            Thread {
                proxy,
                tsd: regs.tpidrro,
                state: State::Runnable(regs),
            },
        );
        self.next_id += 1;
        Ok(id)
    }

    /// Makes a parked thread runnable with `regs`.
    pub(crate) fn unpark(&mut self, id: ThreadId, regs: Registers) {
        let thread = self.threads.get_mut(&id).expect("parked thread exists");
        debug_assert!(matches!(thread.state, State::Parked));
        thread.tsd = regs.tpidrro;
        thread.state = State::Runnable(regs);
    }

    /// A thread's port name.
    pub(crate) fn port(&self, id: ThreadId) -> u32 {
        self.threads[&id].proxy.port
    }

    /// Drops every thread but the current one, as exec does.
    pub(crate) fn retain_only_current(&mut self) {
        let current = self.current;
        // A proxy stuck in a syscall stays so; its completion is ignored once it arrives.
        self.threads.retain(|&id, _| Some(id) == current);
    }

    /// Runs a syscall on the current thread's proxy. If `may_block` and it doesn't return
    /// promptly while another thread can run (or kevents need delivering), the current thread is
    /// taken off the vCPU as blocked, and its result is delivered into its saved registers once
    /// it returns.
    pub(crate) fn forward(
        &mut self,
        vcpu: &av::Vcpu,
        num: u64,
        args: &[u64; 16],
        may_block: bool,
    ) -> Result<Forwarded> {
        let id = self.current();
        self.current_thread()
            .proxy
            .jobs
            .send(Job { num, args: *args })
            .context("syscall proxy thread exited")?;

        let mut waited_long = !may_block;
        loop {
            let message = if waited_long {
                Some(self.messages.recv().context("syscall proxies exited")?)
            } else {
                match self.messages.recv_timeout(BLOCKING_THRESHOLD) {
                    Ok(message) => Some(message),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => anyhow::bail!("syscall proxies exited"),
                }
            };
            match message {
                Some(Message::Completed(completed, ret)) if completed == id => {
                    return Ok(Forwarded::Returned(ret))
                }
                Some(message) => self.handle(message),
                None => waited_long = true,
            }
            let others_ready = self.next_runnable().is_some() || !self.kevents_pending.is_empty();
            if may_block && waited_long && others_ready {
                let regs = Registers::save_at_syscall(vcpu)?;
                self.current_thread().state = State::Blocked(regs);
                self.current = None;
                return Ok(Forwarded::Blocked);
            }
        }
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::Completed(id, ret) => {
                let Some(thread) = self.threads.get_mut(&id) else {
                    return;
                };
                if let State::Blocked(regs) = &mut thread.state {
                    let mut regs = std::mem::take(regs);
                    apply_return(&mut regs, ret);
                    thread.state = State::Runnable(regs);
                }
            }
            Message::KeventsPending(source) => {
                self.kevents_pending.insert(source);
            }
        }
    }

    /// Takes the current thread off the vCPU as blocked in a syscall appbox emulates, until
    /// [`Self::wake`].
    pub(crate) fn block_current(&mut self, vcpu: &av::Vcpu) -> Result<()> {
        let regs = Registers::save_at_syscall(vcpu)?;
        self.current_thread().state = State::Blocked(regs);
        self.current = None;
        Ok(())
    }

    /// Returns `ret` from the emulated syscall thread `id` is blocked in.
    pub(crate) fn wake(&mut self, id: ThreadId, ret: SyscallReturn) {
        self.handle(Message::Completed(id, ret));
    }

    /// Waits for a syscall to finish or kevents to arrive.
    pub(crate) fn wait(&mut self) -> Result<()> {
        let message = self.messages.recv().context("syscall proxies exited")?;
        self.handle(message);
        Ok(())
    }

    /// The next runnable thread after the last one scheduled, in id order (wrapping around).
    fn next_runnable(&self) -> Option<ThreadId> {
        let after = self.current.unwrap_or(0);
        let runnable = |(&id, thread): (&ThreadId, &Thread)| {
            matches!(thread.state, State::Runnable(_)).then_some(id)
        };
        self.threads
            .range(after + 1..)
            .find_map(runnable)
            .or_else(|| self.threads.range(..=after).find_map(runnable))
    }

    /// Whether any thread could still run: runnable, running or blocked in a syscall.
    pub(crate) fn any_alive(&self) -> bool {
        self.threads
            .values()
            .any(|thread| !matches!(thread.state, State::Parked))
    }

    /// Puts the next runnable thread on the vCPU, if there is one. No thread may be on it.
    pub(crate) fn switch_to_next(
        &mut self,
        vcpu: &av::Vcpu,
        from: Option<ThreadId>,
    ) -> Result<Option<ThreadSwitch>> {
        debug_assert!(self.current.is_none());
        self.current = from;
        let Some(to) = self.next_runnable() else {
            self.current = None;
            return Ok(None);
        };
        let thread = self.threads.get_mut(&to).expect("runnable thread exists");
        let State::Runnable(regs) = std::mem::replace(&mut thread.state, State::Running) else {
            unreachable!("next_runnable returned a runnable thread");
        };
        regs.restore(vcpu)?;
        vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, thread.tsd)?;
        self.current = Some(to);
        Ok(Some(ThreadSwitch { from, to }))
    }

    /// Takes the current thread (at a syscall that has returned `ret`) off the vCPU as runnable,
    /// if another thread could run instead (or might, once kevents are delivered). Returns
    /// whether it did.
    pub(crate) fn yield_current(&mut self, vcpu: &av::Vcpu, ret: SyscallReturn) -> Result<bool> {
        if self.next_runnable().is_none() && self.kevents_pending.is_empty() {
            return Ok(false);
        }
        let mut regs = Registers::save_at_syscall(vcpu)?;
        apply_return(&mut regs, ret);
        self.current_thread().state = State::Runnable(regs);
        self.current = None;
        Ok(true)
    }

    /// Takes the current thread off the vCPU as parked.
    pub(crate) fn park_current(&mut self) {
        self.current_thread().state = State::Parked;
        self.current = None;
    }

    /// Removes the current thread.
    pub(crate) fn exit_current(&mut self) {
        let id = self.current();
        self.threads.remove(&id);
        self.current = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::VM_TEST_LOCK;
    use crate::vm::VmManager;

    #[test]
    fn registers_roundtrip_through_the_vcpu() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vm = VmManager::new()?;
        let vcpu = &vm.vcpu;

        let mut regs = Registers {
            sp: 0x1000,
            pc: 0x2000,
            cpsr: 0x2000_0000,
            fpcr: 0x0300_0000,
            fpsr: 0x8,
            tpidr: 0x3000,
            tpidrro: 0x4000,
            ..Default::default()
        };
        for (i, x) in regs.x.iter_mut().enumerate() {
            *x = 0x1111 * (i as u64 + 1);
        }
        for (i, q) in regs.q.iter_mut().enumerate() {
            *q = ((i as u128 + 1) << 64) | (0xabcd_0000 + i as u128);
        }
        regs.restore(vcpu)?;

        // What save_at_syscall reads for the resume point, as it'd be after an svc.
        vcpu.set_sys_reg(av::SysReg::ELR_EL1, regs.pc)?;
        vcpu.set_sys_reg(av::SysReg::SPSR_EL1, regs.cpsr)?;
        assert_eq!(Registers::save_at_syscall(vcpu)?, regs);
        Ok(())
    }

    #[test]
    fn forwards_syscalls_on_a_proxy_thread() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vm = VmManager::new()?;
        let mut threads = Threads::new()?;
        let args = [0u64; 16];
        let mut forward = |num| match threads.forward(&vm.vcpu, num, &args, true)? {
            Forwarded::Returned(ret) => Ok::<_, anyhow::Error>(ret),
            Forwarded::Blocked => panic!("blocked with no other threads"),
        };

        let (pid, _, flags) = forward(crate::syscalls::SYS_getpid)?;
        assert_eq!(flags & (1 << 29), 0);
        assert_eq!(pid, std::process::id() as u64);

        // thread_selfid identifies the calling kernel thread, which must be the proxy.
        let (proxy_tid, _, _) = forward(crate::syscalls::SYS_thread_selfid)?;
        let (again, _, _) = forward(crate::syscalls::SYS_thread_selfid)?;
        let mut own_tid = 0u64;
        unsafe { nix::libc::pthread_threadid_np(0, &mut own_tid) };
        assert_eq!(proxy_tid, again);
        assert_ne!(proxy_tid, own_tid);
        Ok(())
    }
}
