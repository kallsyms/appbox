use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use appbox::guest::{
    Decision, ExecRequest, Guest, GuestEnd, GuestFault, Hooks, Outcome, Preemption, Program,
    Memory, Resume, Returned, RoundRobin, Syscall, ThreadCx, ThreadId, ThreadingModel,
};

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
    vma: &mut Memory,
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

fn format_c_string(vma: &mut Memory, addr: u64) -> String {
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
    vma: &mut Memory,
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

fn format_returned(returned: &Returned) -> String {
    let x1 = (returned.x1 != 0)
        .then(|| format!(" x1=0x{:x}", returned.x1))
        .unwrap_or_default();
    if returned.failed() {
        format!("err={}{x1}", returned.x0)
    } else {
        format!("0x{:x}{x1}", returned.x0)
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

    /// Guest threads' time slice in microseconds, or 0 to only switch threads when one blocks
    /// (time-shared only).
    #[clap(long)]
    pub quantum: Option<u64>,

    /// Run each guest thread on a vCPU of its own, all at once, rather than taking turns on one
    /// (see appbox::threading). Guests this spawns do the same.
    #[clap(long)]
    pub parallel: bool,

    /// Target executable
    #[clap(required = true)]
    pub executable: String,

    /// Target arguments
    #[clap(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

/// Traces what the guest does.
struct Strace {
    trace: Box<dyn Write + Send>,
    /// Each thread's syscall in progress, as traced so far.
    calls: HashMap<ThreadId, String>,
}

impl Strace {
    fn line(&mut self, line: std::fmt::Arguments) -> Result<()> {
        self.trace.write_fmt(line)?;
        self.trace.write_all(b"\n")?;
        Ok(())
    }
}

impl Hooks for Strace {
    fn start(&mut self, t: &mut ThreadCx) -> Result<Resume> {
        let threading = t.handler().threading();
        self.line(format_args!("threading: {threading:?}"))?;
        Ok(Resume::Continue)
    }

    fn syscall(&mut self, t: &mut ThreadCx, call: &Syscall) -> Result<Decision> {
        let name = call
            .name()
            .map(str::to_string)
            .unwrap_or_else(|| format!("<unknown 0x{:x}>", call.number));
        let args = format_syscall_args(&mut t.memory(), call.number, &call.args);
        let thread = t.thread();
        self.calls
            .insert(thread, format!("[{thread}] {name}({})", args.join(", ")));
        Ok(Decision::Default)
    }

    fn syscall_done(&mut self, t: &mut ThreadCx, _call: &Syscall, outcome: &Outcome) -> Result<()> {
        let caller = match outcome {
            Outcome::Switched(switch) => switch.from.unwrap_or(t.thread()),
            _ => t.thread(),
        };
        let call = self.calls.remove(&caller).unwrap_or_default();
        match outcome {
            Outcome::Returned(returned) => self.line(format_args!("{call} = {}", format_returned(returned))),
            Outcome::Switched(switch) => {
                self.line(format_args!("{call} = <switched to thread {}>", switch.to))
            }
            outcome => self.line(format_args!("{call} = {outcome:?}")),
        }
    }

    fn preempted(&mut self, _t: &mut ThreadCx, preemption: &Preemption) -> Result<()> {
        let switch = preemption.switch;
        self.line(format_args!(
            "[{}] <preempted, switched to thread {}>",
            switch.from.unwrap_or_default(),
            switch.to
        ))
    }

    fn fault(&mut self, t: &mut ThreadCx, fault: &GuestFault) -> Result<Resume> {
        self.line(format_args!("guest fault: {fault:x?}"))?;
        for (idx, addr) in t.stack(32).iter().enumerate() {
            let symbol = t
                .symbolicate(*addr)
                .map(|s| format!("{}!{}+{:#x}", s.image, s.symbol, addr - s.symbol_addr))
                .unwrap_or_default();
            self.line(format_args!("{idx:02} {addr:#018x} {symbol}"))?;
        }
        Ok(Resume::End(fault.crash()))
    }

    fn exec(&mut self, _t: &mut ThreadCx, request: &ExecRequest) -> Result<()> {
        self.line(format_args!("exec {:?} {:?}", request.path, request.argv))
    }

    fn ending(&mut self, _t: &mut ThreadCx, end: &GuestEnd) -> Result<Resume> {
        self.line(format_args!("VM exited: {end:?}"))?;
        Ok(Resume::End(end.clone()))
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

    // Not stdout, which is the guest's (and a spawned guest's may well be a pipe its parent reads).
    let trace: Box<dyn Write + Send> = match &args.output {
        Some(path) => Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        ),
        None => Box::new(std::io::stderr()),
    };

    let threading = if args.parallel {
        ThreadingModel::Parallel
    } else {
        ThreadingModel::TimeShared
    };
    let mut guest = Guest::builder(program).threading(threading);
    // Parallel threads don't take turns.
    if let Some(quantum) = args.quantum.filter(|_| !args.parallel) {
        let quantum = (quantum > 0).then(|| std::time::Duration::from_micros(quantum));
        guest = guest.scheduler(RoundRobin::new(quantum));
    }
    let end = guest
        .hooks(Strace {
            trace,
            calls: HashMap::new(),
        })
        .run()?;
    end.end_process()
}
