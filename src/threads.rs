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

use std::collections::BTreeMap;
use std::sync::mpsc::{channel, Receiver, Sender};

use anyhow::{Context, Result};

use crate::applevisor as av;
use crate::trap::forward_syscall;

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

/// A host thread that runs one guest thread's forwarded syscalls.
struct Proxy {
    jobs: Sender<Job>,
}

impl Proxy {
    fn spawn(id: ThreadId, completions: Sender<(ThreadId, SyscallReturn)>) -> Result<Self> {
        let (jobs, pending) = channel::<Job>();
        std::thread::Builder::new()
            .name(format!("appbox-guest-{id}"))
            .spawn(move || {
                for job in pending {
                    let ret = forward_syscall(job.num, &job.args);
                    if completions.send((id, ret)).is_err() {
                        break;
                    }
                }
            })
            .context("spawning syscall proxy thread")?;
        Ok(Self { jobs })
    }
}

struct Thread {
    proxy: Proxy,
    tsd: u64,
}

pub(crate) struct Threads {
    threads: BTreeMap<ThreadId, Thread>,
    current: ThreadId,
    completions: Receiver<(ThreadId, SyscallReturn)>,
    completions_tx: Sender<(ThreadId, SyscallReturn)>,
}

impl Threads {
    pub(crate) fn new() -> Result<Self> {
        let (completions_tx, completions) = channel();
        let main = Thread {
            proxy: Proxy::spawn(MAIN_THREAD, completions_tx.clone())?,
            tsd: 0,
        };
        Ok(Self {
            threads: BTreeMap::from([(MAIN_THREAD, main)]),
            current: MAIN_THREAD,
            completions,
            completions_tx,
        })
    }

    pub(crate) fn current(&self) -> ThreadId {
        self.current
    }

    fn current_thread(&mut self) -> &mut Thread {
        self.threads
            .get_mut(&self.current)
            .expect("current thread exists")
    }

    pub(crate) fn tsd(&self) -> u64 {
        self.threads[&self.current].tsd
    }

    pub(crate) fn set_tsd(&mut self, tsd: u64) {
        self.current_thread().tsd = tsd;
    }

    /// Runs a syscall on the current thread's proxy, waiting for it to finish.
    pub(crate) fn forward(&mut self, num: u64, args: &[u64; 16]) -> Result<SyscallReturn> {
        let id = self.current;
        self.current_thread()
            .proxy
            .jobs
            .send(Job { num, args: *args })
            .context("syscall proxy thread exited")?;
        let (completed, ret) = self
            .completions
            .recv()
            .context("syscall proxy thread exited")?;
        debug_assert_eq!(completed, id);
        Ok(ret)
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
        let mut threads = Threads::new()?;
        let args = [0u64; 16];

        let (pid, _, flags) = threads.forward(crate::syscalls::SYS_getpid, &args)?;
        assert_eq!(flags & (1 << 29), 0);
        assert_eq!(pid, std::process::id() as u64);

        // thread_selfid identifies the calling kernel thread, which must be the proxy.
        let (proxy_tid, _, _) = threads.forward(crate::syscalls::SYS_thread_selfid, &args)?;
        let (again, _, _) = threads.forward(crate::syscalls::SYS_thread_selfid, &args)?;
        let mut own_tid = 0u64;
        unsafe { nix::libc::pthread_threadid_np(0, &mut own_tid) };
        assert_eq!(proxy_tid, again);
        assert_ne!(proxy_tid, own_tid);
        Ok(())
    }
}
