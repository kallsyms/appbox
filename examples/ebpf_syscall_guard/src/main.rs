use anyhow::{anyhow, Result};
use clap::Parser;
use log::{debug, info};
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
use appbox::trap::{
    read_syscall_context, write_syscall_result, DefaultTrapHandler, SyscallResult, TrapHandler,
};
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
struct BpfSyscallContext {
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

    let mut argv = Vec::new();
    argv.push(args.executable.clone());
    argv.extend(args.arguments.iter().cloned());
    let loader = appbox::loader::load_macho(
        &mut vm,
        &PathBuf::from(args.executable.clone()),
        argv,
        vec![],
    )?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;

    let mut handler = DefaultTrapHandler::new();
    let mut bpf_mem = vec![0u8; mem::size_of::<BpfSyscallContext>() + SCRATCH_SIZE];

    loop {
        let exit = match vm.run()? {
            VmRunResult::Svc => {
                let ctx = read_syscall_context(&mut vm.vcpu)?;
                let bpf_ctx = BpfSyscallContext {
                    syscall_number: ctx.num,
                    args: ctx.args,
                };
                bpf_mem.fill(0);
                unsafe {
                    ptr::copy_nonoverlapping(
                        &bpf_ctx as *const BpfSyscallContext as *const u8,
                        bpf_mem.as_mut_ptr(),
                        mem::size_of::<BpfSyscallContext>(),
                    );
                }

                let _guard = HelperGuard::new(&mut vm.vma, &mut bpf_mem);
                let decision = bpf_vm
                    .execute_program(&mut bpf_mem)
                    .map_err(|e| anyhow!("rbpf exec: {e}"))?;

                let result = match decision {
                    0 => handler.handle_syscall(&ctx, &mut vm.vcpu, &mut vm.vma, &loader)?,
                    1 => SyscallResult::cont(nix::libc::EPERM as u64, 0, 1 << 29),
                    2 => {
                        info!("Killed by eBPF policy");
                        SyscallResult::exit(ExitKind::Crash("Killed by eBPF policy".to_string()))
                    }
                    _ => SyscallResult::cont(nix::libc::EPERM as u64, 0, 1 << 29),
                };

                match result.exit {
                    ExitKind::Continue => {
                        if result.write_back {
                            debug!(
                                "Returning x0={:x} x1={:x} cflags={:x}",
                                result.ret0, result.ret1, result.cflags
                            );
                            write_syscall_result(
                                &mut vm.vcpu,
                                ctx.elr,
                                result.ret0,
                                result.ret1,
                                result.cflags,
                            )?;
                        }
                        ExitKind::Continue
                    }
                    _ => result.exit,
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
