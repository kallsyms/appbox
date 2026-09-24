use anyhow::{anyhow, Result};
use clap::Parser;
use log::info;
use rbpf::assembler::assemble;
use rbpf::EbpfVmRaw;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::{mem, ptr};

use appbox::guest::{
    Decision, Guest, GuestEnd, Hooks, Memory, Program, Returned, Syscall,
    ThreadCx,
};
use nix::sys::signal::Signal;

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
    memory: *const Memory<'static>,
    mem_base: *mut u8,
    mem_len: usize,
}

thread_local! {
    static HELPER_STATE: RefCell<Option<HelperState>> = RefCell::new(None);
}

/// Makes `memory` available to the helpers while it lives.
struct HelperGuard<'a>(std::marker::PhantomData<&'a Memory<'a>>);

impl<'a> HelperGuard<'a> {
    fn new(memory: &'a Memory<'a>, mem: &mut [u8]) -> Self {
        HELPER_STATE.with(|state| {
            *state.borrow_mut() = Some(HelperState {
                memory: memory as *const Memory as *const Memory<'static>,
                mem_base: mem.as_mut_ptr(),
                mem_len: mem.len(),
            });
        });
        Self(std::marker::PhantomData)
    }
}

impl Drop for HelperGuard<'_> {
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

        let memory = unsafe { &*state.memory };
        let mut buf = vec![0u8; len];
        if memory.read(addr, &mut buf).is_err() {
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

/// Asks the eBPF program about each syscall: 0 to allow it, 1 to fail it with EPERM, 2 to kill
/// the guest.
struct Guard {
    bpf: EbpfVmRaw<'static>,
    memory: Vec<u8>,
}

// SAFETY: appbox calls hooks one at a time, so the eBPF VM (whose helper table isn't Send) is
// never used from two threads at once, just possibly from one and then another.
unsafe impl Send for Guard {}

impl Hooks for Guard {
    fn syscall(&mut self, t: &mut ThreadCx, call: &Syscall) -> Result<Decision> {
        let context = BpfSyscallContext {
            syscall_number: call.number,
            args: call.args,
        };
        self.memory.fill(0);
        unsafe {
            ptr::copy_nonoverlapping(
                &context as *const BpfSyscallContext as *const u8,
                self.memory.as_mut_ptr(),
                mem::size_of::<BpfSyscallContext>(),
            );
        }
        let verdict = {
            let memory = t.memory();
            let _guard = HelperGuard::new(&memory, &mut self.memory);
            self.bpf
                .execute_program(&mut self.memory)
                .map_err(|e| anyhow!("rbpf exec: {e}"))?
        };
        Ok(match verdict {
            0 => Decision::Default,
            1 => Decision::Return(Returned::errno(nix::libc::EPERM)),
            2 => {
                info!("Killed by eBPF policy");
                Decision::End(GuestEnd::Crashed {
                    signal: Signal::SIGKILL,
                    reason: "killed by eBPF policy".into(),
                })
            }
            _ => return Err(anyhow!("Invalid eBPF return value: {verdict}")),
        })
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    let program = appbox::guest::prepare()?.unwrap_or_else(|| {
        let mut argv = vec![args.executable.clone()];
        argv.extend(args.arguments.iter().cloned());
        Program::new(&args.executable, argv, vec![])
    });

    let prog: &'static [u8] = Box::leak(load_bpf_program(&args)?.into_boxed_slice());
    let mut bpf = EbpfVmRaw::new(Some(prog)).map_err(|e| anyhow!("rbpf: {e}"))?;
    bpf.register_helper(HELPER_READ_MEM, bpf_read_mem)
        .map_err(|e| anyhow!("rbpf helper: {e}"))?;

    let end = Guest::builder(program)
        .hooks(Guard {
            bpf,
            memory: vec![0u8; mem::size_of::<BpfSyscallContext>() + SCRATCH_SIZE],
        })
        .run()?;
    println!("guest ended: {end:?}");
    end.end_process()
}
