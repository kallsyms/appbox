use anyhow::{anyhow, Result};
use clap::Parser;
use log::{debug, info, warn};
use rbpf::assembler::assemble;
use rbpf::EbpfVmRaw;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::{mem, ptr};

use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::hyperpom::memory::VirtMemAllocator;
use appbox::vm::{VmManager, VmRunResult};

const DEFAULT_BPF_ASM: &str = "mov64 r0, 0\nexit\n";
const SCRATCH_SIZE: usize = 4096;
const HELPER_READ_MEM: u32 = 1;

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Optional eBPF program path (rbpf assembly text)
    #[clap(long)]
    pub bpf_asm: Option<PathBuf>,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

#[repr(C)]
struct SyscallContext {
    syscall_number: u64,
    args: [u64; 16],
}

struct HelperState {
    vma: *mut VirtMemAllocator,
    mem_base: *mut u8,
    mem_len: usize,
}

thread_local! {
    static HELPER_STATE: RefCell<Option<HelperState>> = RefCell::new(None);
}

struct HelperGuard;

impl HelperGuard {
    fn new(vma: &mut VirtMemAllocator, mem: &mut [u8]) -> Self {
        HELPER_STATE.with(|state| {
            *state.borrow_mut() = Some(HelperState {
                vma,
                mem_base: mem.as_mut_ptr(),
                mem_len: mem.len(),
            });
        });
        Self
    }
}

impl Drop for HelperGuard {
    fn drop(&mut self) {
        HELPER_STATE.with(|state| {
            *state.borrow_mut() = None;
        });
    }
}

fn bpf_read_mem(addr: u64, len: u64, dst: u64, _arg4: u64, _arg5: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    HELPER_STATE.with(|state| {
        let binding = state.borrow();
        let Some(state) = binding.as_ref() else {
            return 1;
        };
        let len = len as usize;
        let dst = dst as usize;
        let base = state.mem_base as usize;
        let end = match dst.checked_add(len) {
            Some(end) => end,
            None => return 1,
        };
        if dst < base || end > base + state.mem_len {
            return 1;
        }

        let vma = unsafe { &mut *state.vma };
        let mut buf = vec![0u8; len];
        if vma.read(addr, &mut buf).is_err() {
            return 1;
        }
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), dst as *mut u8, len);
        }
        0
    })
}

fn load_bpf_program(args: &Args) -> Result<Vec<u8>> {
    let asm = if let Some(path) = &args.bpf_asm {
        fs::read_to_string(path)?
    } else {
        DEFAULT_BPF_ASM.to_string()
    };
    assemble(&asm).map_err(|e| anyhow!("assemble: {e}"))
}

fn write_syscall_result(
    vcpu: &mut av::Vcpu,
    elr: u64,
    ret0: u64,
    ret1: u64,
    cflags: u64,
) -> Result<()> {
    let cpsr = (vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags;
    vcpu.set_reg(av::Reg::X0, ret0)?;
    vcpu.set_reg(av::Reg::X1, ret1)?;
    vcpu.set_reg(av::Reg::CPSR, cpsr)?;
    vcpu.set_reg(av::Reg::PC, elr)?;
    Ok(())
}

fn forward_syscall(num: u64, args: &[u64; 16]) -> (u64, u64, u64) {
    let ret0: u64;
    let ret1: u64;
    let cflags: u64;

    unsafe {
        std::arch::asm!(
            "svc #0x80",
            "mov {ret0}, x0",
            "mov {ret1}, x1",
            "mrs {cflags}, NZCV",
            in("x0") args[0],
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            in("x6") args[6],
            in("x7") args[7],
            in("x8") args[8],
            in("x9") args[9],
            in("x10") args[10],
            in("x11") args[11],
            in("x12") args[12],
            in("x13") args[13],
            in("x14") args[14],
            in("x15") args[15],
            in("x16") num,
            ret0 = lateout(reg) ret0,
            ret1 = lateout(reg) ret1,
            cflags = lateout(reg) cflags,
        );
    }

    (ret0, ret1, cflags)
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let prog = load_bpf_program(&args)?;
    let mut bpf_vm = EbpfVmRaw::new(Some(&prog)).map_err(|e| anyhow!("rbpf: {e}"))?;
    bpf_vm
        .register_helper(HELPER_READ_MEM, bpf_read_mem)
        .map_err(|e| anyhow!("rbpf helper: {e}"))?;

    let mut vm = VmManager::new()?;

    let loader = appbox::loader::load_macho(
        &mut vm,
        &PathBuf::from(args.executable.clone()),
        vec![args.executable.clone()],
        vec![],
    )?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;

    let mut bpf_mem = vec![0u8; mem::size_of::<SyscallContext>() + SCRATCH_SIZE];

    loop {
        let exit = match vm.run()? {
            VmRunResult::Svc => {
                let elr = vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                let esr = vm.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                if esr != 0x56000080 {
                    warn!("Unhandled ESR_EL1 value: {:#x}", esr);
                    ExitKind::Crash("Unhandled fault".to_string())
                } else {
                    let num = vm.vcpu.get_reg(av::Reg::X16)?;
                    let args = [
                        vm.vcpu.get_reg(av::Reg::X0)?,
                        vm.vcpu.get_reg(av::Reg::X1)?,
                        vm.vcpu.get_reg(av::Reg::X2)?,
                        vm.vcpu.get_reg(av::Reg::X3)?,
                        vm.vcpu.get_reg(av::Reg::X4)?,
                        vm.vcpu.get_reg(av::Reg::X5)?,
                        vm.vcpu.get_reg(av::Reg::X6)?,
                        vm.vcpu.get_reg(av::Reg::X7)?,
                        vm.vcpu.get_reg(av::Reg::X8)?,
                        vm.vcpu.get_reg(av::Reg::X9)?,
                        vm.vcpu.get_reg(av::Reg::X10)?,
                        vm.vcpu.get_reg(av::Reg::X11)?,
                        vm.vcpu.get_reg(av::Reg::X12)?,
                        vm.vcpu.get_reg(av::Reg::X13)?,
                        vm.vcpu.get_reg(av::Reg::X14)?,
                        vm.vcpu.get_reg(av::Reg::X15)?,
                    ];

                    if num == appbox::syscalls::SYS_exit {
                        ExitKind::Exit
                    } else {
                        let ctx = SyscallContext {
                            syscall_number: num,
                            args,
                        };
                        bpf_mem.fill(0);
                        unsafe {
                            ptr::copy_nonoverlapping(
                                &ctx as *const SyscallContext as *const u8,
                                bpf_mem.as_mut_ptr(),
                                mem::size_of::<SyscallContext>(),
                            );
                        }

                        let _guard = HelperGuard::new(&mut vm.vma, &mut bpf_mem);
                        let decision = bpf_vm
                            .execute_program(&mut bpf_mem)
                            .map_err(|e| anyhow!("rbpf exec: {e}"))?;

                        let (exit, ret0, ret1, cflags) = match decision {
                            0 => {
                                let (ret0, ret1, cflags) = forward_syscall(num, &args);
                                (ExitKind::Continue, ret0, ret1, cflags)
                            }
                            1 => (ExitKind::Continue, nix::libc::EPERM as u64, 0, 1 << 29),
                            2 => {
                                info!("Killed by eBPF policy");
                                (
                                    ExitKind::Crash("Killed by eBPF policy".to_string()),
                                    0,
                                    0,
                                    0,
                                )
                            }
                            _ => (ExitKind::Continue, nix::libc::EPERM as u64, 0, 1 << 29),
                        };

                        if exit != ExitKind::Continue {
                            exit
                        } else {
                            debug!("Returning x0={:x} x1={:x} cflags={:x}", ret0, ret1, cflags);

                            write_syscall_result(&mut vm.vcpu, elr, ret0, ret1, cflags)?;
                            ExitKind::Continue
                        }
                    }
                }
            }
            VmRunResult::Brk => ExitKind::Continue,
            VmRunResult::Other(exit_info) => match exit_info.reason {
                av::ExitReason::EXCEPTION => {
                    match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                        ExceptionClass::InsAbortLowerEl => {
                            ExitKind::Crash("Instruction Abort".to_string())
                        }
                        _ => Err(ExceptionError::UnimplementedException(
                            exit_info.exception.syndrome,
                        ))?,
                    }
                }
                av::ExitReason::CANCELED => ExitKind::Timeout,
                av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
                av::ExitReason::UNKNOWN => panic!(
                    "Vcpu exited unexpectedly at address {:#x}",
                    vm.vcpu.get_reg(av::Reg::PC)?
                ),
            },
        };

        match exit {
            ExitKind::Continue => continue,
            _ => {
                println!("VM exited: {:?}", exit);
                break;
            }
        }
    }

    Ok(())
}
