use anyhow::Result;
use clap::Parser;
use log::{debug, warn};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use appbox::applevisor as av;
use appbox::hyperpom::crash::ExitKind;
use appbox::hyperpom::error::ExceptionError;
use appbox::hyperpom::exceptions::ExceptionClass;
use appbox::trap::{
    read_syscall_context, write_syscall_result, DefaultTrapHandler, SyscallResult, TrapHandler,
};
use appbox::vm::{VmManager, VmRunResult};

#[derive(Clone, Copy)]
enum ArgFormat {
    Hex,
    Dec,
    Octal,
    Ptr,
    Str,
    Size,
}

fn formatters_by_syscall() -> &'static HashMap<u64, Vec<ArgFormat>> {
    static MAP: OnceLock<HashMap<u64, Vec<ArgFormat>>> = OnceLock::new();
    MAP.get_or_init(|| {
        use ArgFormat::*;
        let mut map = HashMap::new();

        for (num, _name) in appbox::syscalls::SYSCALLS {
            map.insert(*num, vec![Hex; 5]);
        }

        map.insert(appbox::syscalls::SYS_exit, vec![Dec]);
        map.insert(appbox::syscalls::SYS_read, vec![Dec, Ptr, Size]);
        map.insert(appbox::syscalls::SYS_write, vec![Dec, Ptr, Size]);
        map.insert(appbox::syscalls::SYS_open, vec![Str, Hex, Octal]);
        map.insert(appbox::syscalls::SYS_close, vec![Dec]);
        map.insert(appbox::syscalls::SYS_link, vec![Str, Str]);
        map.insert(appbox::syscalls::SYS_unlink, vec![Str]);
        map.insert(appbox::syscalls::SYS_chdir, vec![Str]);
        map.insert(appbox::syscalls::SYS_chmod, vec![Str, Octal]);
        map.insert(appbox::syscalls::SYS_chown, vec![Str, Dec, Dec]);
        map.insert(appbox::syscalls::SYS_getpid, vec![]);
        map.insert(appbox::syscalls::SYS_setuid, vec![Dec]);
        map.insert(appbox::syscalls::SYS_getuid, vec![]);
        map.insert(appbox::syscalls::SYS_geteuid, vec![]);
        map.insert(appbox::syscalls::SYS_kill, vec![Dec, Dec]);
        map.insert(appbox::syscalls::SYS_getppid, vec![]);
        map.insert(appbox::syscalls::SYS_getegid, vec![]);
        map.insert(appbox::syscalls::SYS_getgid, vec![]);
        map.insert(appbox::syscalls::SYS_execve, vec![Str, Ptr, Ptr]);
        map.insert(
            appbox::syscalls::SYS_posix_spawn,
            vec![Ptr, Str, Ptr, Ptr, Ptr],
        );
        map.insert(appbox::syscalls::SYS_munmap, vec![Ptr, Size]);
        map.insert(appbox::syscalls::SYS_mprotect, vec![Ptr, Size, Hex]);
        map.insert(appbox::syscalls::SYS_setreuid, vec![Dec, Dec]);
        map.insert(appbox::syscalls::SYS_setregid, vec![Dec, Dec]);
        map.insert(appbox::syscalls::SYS_mkdir, vec![Str, Octal]);
        map.insert(appbox::syscalls::SYS_pread, vec![Dec, Ptr, Size, Dec]);
        map.insert(appbox::syscalls::SYS_setgid, vec![Dec]);
        map.insert(appbox::syscalls::SYS_setegid, vec![Dec]);
        map.insert(appbox::syscalls::SYS_seteuid, vec![Dec]);
        map.insert(appbox::syscalls::SYS_stat, vec![Str, Ptr]);
        map.insert(appbox::syscalls::SYS_fstat, vec![Dec, Ptr]);
        map.insert(appbox::syscalls::SYS_lstat, vec![Str, Ptr]);
        map.insert(
            appbox::syscalls::SYS_mmap,
            vec![Ptr, Size, Hex, Hex, Dec, Hex],
        );
        map.insert(appbox::syscalls::SYS_shm_open, vec![Str, Hex, Octal]);
        map.insert(appbox::syscalls::SYS_shared_region_check_np, vec![Ptr]);
        map.insert(
            appbox::syscalls::SYS_proc_info,
            vec![Hex, Hex, Hex, Hex, Hex],
        );
        map.insert(appbox::syscalls::SYS_read_nocancel, vec![Dec, Ptr, Size]);
        map.insert(appbox::syscalls::SYS_write_nocancel, vec![Dec, Ptr, Size]);
        map.insert(appbox::syscalls::SYS_open_nocancel, vec![Str, Hex, Octal]);
        map.insert(
            appbox::syscalls::SYS_pread_nocancel,
            vec![Dec, Ptr, Size, Dec],
        );
        map.insert(appbox::syscalls::SYS_openat, vec![Dec, Str, Hex, Octal]);
        map.insert(
            appbox::syscalls::SYS_openat_nocancel,
            vec![Dec, Str, Hex, Octal],
        );

        map.insert(
            appbox::syscalls::TRAP_mach_vm_allocate,
            vec![Hex, Ptr, Size, Hex],
        );
        map.insert(
            appbox::syscalls::TRAP_mach_vm_deallocate,
            vec![Hex, Ptr, Size],
        );
        map.insert(
            appbox::syscalls::TRAP_mach_vm_protect,
            vec![Hex, Ptr, Size, Hex],
        );
        map.insert(
            appbox::syscalls::TRAP_mach_vm_map,
            vec![Hex, Ptr, Size, Hex, Hex, Hex, Hex, Hex, Hex],
        );
        map.insert(
            appbox::syscalls::TRAP_mach_msg2,
            vec![Ptr, Hex, Size, Hex, Hex],
        );

        map
    })
}

fn default_formatters() -> &'static [ArgFormat] {
    static DEFAULT: [ArgFormat; 5] = [ArgFormat::Hex; 5];
    &DEFAULT
}

fn format_arg(
    vma: &mut appbox::hyperpom::memory::VirtMemAllocator,
    fmt: ArgFormat,
    val: u64,
) -> String {
    match fmt {
        ArgFormat::Hex => format!("0x{:x}", val),
        ArgFormat::Dec => format!("{}", val),
        ArgFormat::Octal => format!("0o{:o}", val),
        ArgFormat::Size => format!("{}", val),
        ArgFormat::Ptr => {
            if val == 0 {
                "NULL".to_string()
            } else {
                format!("0x{:016x}", val)
            }
        }
        ArgFormat::Str => format_c_string(vma, val),
    }
}

fn format_c_string(vma: &mut appbox::hyperpom::memory::VirtMemAllocator, addr: u64) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }

    let mut buf = Vec::new();
    for i in 0..256u64 {
        let byte = match vma.read_byte(addr + i) {
            Ok(b) => b,
            Err(_) => return format!("0x{:016x}", addr),
        };
        if byte == 0 {
            break;
        }
        buf.push(byte);
    }

    let mut out = String::new();
    out.push('"');
    for b in buf {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out.push('"');
    out
}

fn format_syscall_args(
    vma: &mut appbox::hyperpom::memory::VirtMemAllocator,
    num: u64,
    args: &[u64; 16],
) -> Vec<String> {
    let map = formatters_by_syscall();
    let formatters = map
        .get(&num)
        .map(|v| v.as_slice())
        .unwrap_or_else(default_formatters);

    formatters
        .iter()
        .enumerate()
        .map(|(idx, fmt)| format_arg(vma, *fmt, args[idx]))
        .collect()
}

fn format_syscall_result(result: &SyscallResult) -> String {
    if result.cflags & (1 << 29) != 0 {
        if result.ret1 != 0 {
            format!("err={} x1=0x{:x}", result.ret0, result.ret1)
        } else {
            format!("err={}", result.ret0)
        }
    } else if result.ret1 != 0 {
        format!("0x{:x} x1=0x{:x}", result.ret0, result.ret1)
    } else {
        format!("0x{:x}", result.ret0)
    }
}

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,

    /// Write the trace to this file (which processes the guest spawns append to too) instead of
    /// stderr.
    #[clap(short, long)]
    pub output: Option<PathBuf>,

    /// Guest threads' time slice in microseconds, or 0 to only switch threads when one blocks.
    #[clap(long)]
    pub quantum: Option<u64>,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

fn print_stack(
    trace: &mut dyn Write,
    vm: &VmManager,
    loader: &appbox::loader::Loader,
) -> Result<()> {
    for (idx, addr) in appbox::unwind_user_stack(vm, 32).iter().enumerate() {
        let symbol = loader
            .symbolicate(*addr)
            .map(|s| format!("{}!{}+{:#x}", s.image, s.symbol, addr - s.symbol_addr))
            .unwrap_or_default();
        writeln!(trace, "{:02} {:#018x} {}", idx, addr, symbol)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    appbox::respawn::respawn()?;

    // Not stdout, which is the guest's (and a spawned guest's may well be a pipe its parent reads).
    let mut trace: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        ),
        None => Box::new(std::io::stderr()),
    };

    // Processes the guest spawns get their own copy of this program, running the spawned guest.
    let (executable, argv, envp) = match appbox::respawn::spawned_guest()? {
        Some(request) => (request.path, request.argv, request.envp),
        None => {
            let mut argv = vec![args.executable.clone()];
            argv.extend(args.arguments.iter().cloned());
            (PathBuf::from(&args.executable), argv, vec![])
        }
    };

    let mut vm = VmManager::new()?;
    let mut loader = appbox::loader::load_macho(&mut vm, &executable, argv, envp)?;

    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;

    let mut handler = DefaultTrapHandler::new()?;
    if let Some(quantum) = args.quantum {
        handler.set_quantum((quantum > 0).then(|| std::time::Duration::from_micros(quantum)));
    }

    loop {
        let exit = match vm.run()? {
            VmRunResult::Svc => {
                let ctx = read_syscall_context(&mut vm.vcpu)?;
                let name = appbox::syscalls::syscall_name(ctx.num)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|| format!("<unknown 0x{:x}>", ctx.num));
                let args = format_syscall_args(&mut vm.vma, ctx.num, &ctx.args);
                write!(
                    trace,
                    "[{}] {}({}) = ",
                    handler.current_thread(),
                    name,
                    args.join(", ")
                );
                trace.flush()?;

                let result = handler.handle_syscall(&ctx, &mut vm.vcpu, &mut vm.vma, &loader)?;
                match result.exit {
                    ExitKind::Continue if result.thread_switch.is_some() => {
                        let switch = result.thread_switch.unwrap();
                        writeln!(trace, "<switched to thread {}>", switch.to)?;
                        ExitKind::Continue
                    }
                    ExitKind::Continue => {
                        writeln!(trace, "{}", format_syscall_result(&result))?;
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
                    _ => {
                        writeln!(trace, "{:?}", result.exit)?;
                        result.exit
                    }
                }
            }
            // Nothing here sets breakpoints, so this is the guest trapping (e.g. abort()).
            VmRunResult::Brk => {
                print_stack(&mut trace, &vm, &loader)?;
                ExitKind::Crash("guest trap (brk)".to_string())
            }
            VmRunResult::Timer => {
                if let Some(switch) = handler.handle_timer(&vm.vcpu, &mut vm.vma)? {
                    writeln!(
                        trace,
                        "[{}] <preempted, switched to thread {}>",
                        switch.from.unwrap_or_default(),
                        switch.to
                    )?;
                }
                ExitKind::Continue
            }
            VmRunResult::HardwareBreakpoint | VmRunResult::Step | VmRunResult::Watchpoint { .. } => {
                ExitKind::Crash("unexpected debug exception".to_string())
            }
            VmRunResult::Other(exit_info) => match exit_info.reason {
                av::ExitReason::EXCEPTION => {
                    match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                        ExceptionClass::InsAbortLowerEl => {
                            ExitKind::Crash("Instruction Abort".to_string())
                        }
                        // The guest faulted, e.g. accessing memory that isn't mapped.
                        ExceptionClass::HvcA64 => {
                            let esr = vm.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                            let far = vm.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?;
                            let elr = vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                            writeln!(
                                trace,
                                "guest exception: ESR_EL1={esr:#x} FAR_EL1={far:#x} ELR_EL1={elr:#x}"
                            )?;
                            print_stack(&mut trace, &vm, &loader)?;
                            ExitKind::Crash(format!("guest exception (ESR_EL1 {esr:#x})"))
                        }
                        _ => Err(ExceptionError::UnimplementedException(
                            exit_info.exception.syndrome,
                        ))?,
                    }
                }
                av::ExitReason::CANCELED => ExitKind::Timeout,
                av::ExitReason::VTIMER_ACTIVATED => unimplemented!(),
                av::ExitReason::UNKNOWN => {
                    warn!(
                        "Vcpu exited unexpectedly at address {:#x}",
                        vm.vcpu.get_reg(av::Reg::PC)?
                    );
                    ExitKind::Crash("Unknown Vcpu exit".to_string())
                }
            },
        };

        match exit {
            ExitKind::Continue => continue,
            ExitKind::Exec(request) => {
                writeln!(trace, "exec {:?} {:?}", request.path, request.argv)?;
                (vm, loader) = appbox::exec::exec(vm, loader, &mut handler, &request)?;
            }
            _ => {
                writeln!(trace, "VM exited: {:?}", exit)?;
                break;
            }
        }
    }

    // Exit like the guest did, so e.g. a guest parent's waitpid() sees its status.
    if let Some(status) = handler.exit_status() {
        drop(vm);
        std::process::exit(status);
    }
    Ok(())
}
