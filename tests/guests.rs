//! End-to-end tests: guest programs run under the strace example, which does everything a real
//! embedder does (respawning with a pinned host layout, handling exec and spawned processes).

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(60);

fn target_dir() -> PathBuf {
    // target/<profile>/deps/<this test>
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

/// The strace example, signed with the entitlements appbox needs.
fn strace() -> &'static Path {
    static STRACE: OnceLock<PathBuf> = OnceLock::new();
    STRACE.get_or_init(|| {
        // Only a full `cargo test` builds examples.
        let status = Command::new(std::env::var("CARGO").unwrap_or("cargo".into()))
            .args(["build", "--example", "strace"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .unwrap();
        assert!(status.success(), "building the strace example failed");
        let path = target_dir().join("examples/strace");
        assert!(path.exists(), "{} not built", path.display());
        let entitlements = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/entitlements.xml");
        let status = Command::new("codesign")
            .arg("--entitlements")
            .arg(entitlements)
            .args(["--force", "-s", "-"])
            .arg(&path)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "codesign failed");
        path
    })
}

/// Compiles `tests/guests/<name>.c`.
fn guest(name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/guests/{name}.c"));
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("guest-{name}"));
    let status = Command::new("xcrun")
        .args(["clang", "-O1", "-o"])
        .arg(&binary)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    binary
}

fn run(args: &[&Path]) -> Output {
    run_strace(&[], args)
}

fn run_strace(strace_args: &[&str], args: &[&Path]) -> Output {
    // Its own process group, so a timeout also kills the respawned child and anything the guest
    // spawned.
    let child = Command::new(strace())
        .args(strace_args)
        .args(args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pgid = child.id() as i32;
    let (done, output) = mpsc::channel();
    // Collecting output while waiting keeps the child from blocking on a full pipe.
    std::thread::spawn(move || done.send(child.wait_with_output()));
    match output.recv_timeout(TIMEOUT) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            unsafe { nix::libc::killpg(pgid, nix::libc::SIGKILL) };
            panic!("{:?} timed out", args);
        }
    }
}

/// Checks the guest's exit status, its output, and strace's trace (on stderr).
#[track_caller]
fn assert_output(
    output: &Output,
    expected_status: i32,
    expected: &[&str],
    expected_trace: &[&str],
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = || format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(output.status.code(), Some(expected_status), "{}", context());
    for line in expected {
        assert!(stdout.contains(line), "missing {line:?}\n{}", context());
    }
    for line in expected_trace {
        assert!(
            stderr.contains(line),
            "missing {line:?} in trace\n{}",
            context()
        );
    }
}

#[test]
fn echo() {
    let output = run(&[Path::new("/bin/echo"), Path::new("hello from the guest")]);
    assert_output(&output, 0, &["hello from the guest"], &[]);
}

#[test]
fn exec() {
    let output = run(&[
        Path::new("/usr/bin/env"),
        Path::new("/bin/echo"),
        Path::new("exec works"),
    ]);
    assert_output(&output, 0, &["exec works"], &["exec \"/bin/echo\""]);
}

#[test]
fn spawned_processes() {
    let output = run(&[&guest("spawn")]);
    assert_output(
        &output,
        3,
        &["child says hi", "echo exited 0", "false exited 1"],
        &[],
    );
}

#[test]
fn sigaction() {
    let output = run(&[&guest("sigaction")]);
    assert_output(
        &output,
        0,
        &[
            "handler readback: ok",
            "write to closed pipe: EPIPE ok",
            "catch SIGKILL: EINVAL ok",
        ],
        &[],
    );
}

#[test]
fn pthreads() {
    let output = run(&[&guest("pthreads")]);
    assert_output(
        &output,
        0,
        &["counter=40000/40000 joins=60/60 distinct_ports=1"],
        &["<switched to thread"],
    );
}

#[test]
fn dispatch() {
    let output = run(&[&guest("dispatch")]);
    assert_output(
        &output,
        0,
        &[
            "dispatch_async: ok",
            "group: 100/100",
            "serial order: ok",
            "dispatch_after: ok",
            "timer source: ok",
            "read source: ok",
            "read: x",
            "mach receive source: ok",
            "mach message id: 1234",
            "main queue: ok",
        ],
        &["<switched to thread"],
    );
}

#[test]
fn exec_applies_close_on_exec() {
    let trace = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cloexec.trace");
    let _ = std::fs::remove_file(&trace);
    // The trace file is the embedder's own close-on-exec descriptor, which must survive.
    let output = run_strace(&["-o", trace.to_str().unwrap()], &[&guest("cloexec")]);
    assert_output(
        &output,
        0,
        &[
            "O_CLOEXEC: closed",
            "plain: open",
            "FD_CLOEXEC set: closed",
            "pipe: open",
            "F_DUPFD_CLOEXEC: closed",
        ],
        &[],
    );
    let trace = std::fs::read_to_string(trace).unwrap();
    let after_exec = &trace[trace.find("\nexec ").expect("no exec in trace")..];
    assert!(after_exec.contains("VM exited: Exit"), "{trace}");
}
