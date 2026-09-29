//! End-to-end tests: guest programs run under the strace example, which does everything a real
//! embedder does (respawning with a pinned host layout, handling exec and spawned processes).

mod common;

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output};

use common::guest;

fn run(args: &[&Path]) -> Output {
    run_strace(&[], args)
}

fn run_strace(strace_args: &[&str], args: &[&Path]) -> Output {
    let child = common::spawn(Command::new(common::example("strace")).args(strace_args).args(args));
    common::wait_with_timeout(child)
}

/// Checks the guest's exit status, its output, and strace's trace (on stderr).
#[track_caller]
fn assert_output(
    output: &Output,
    expected_status: i32,
    expected: &[&str],
    expected_trace: &[&str],
) {
    common::assert_stdout(output, expected_status, expected);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = || format!("stdout:\n{stdout}\nstderr:\n{stderr}");
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

#[test]
fn preemption() {
    let output = run(&[&guest("preempt")]);
    assert_output(
        &output,
        0,
        &["worker ran while main spun: yes"],
        &["<preempted, switched to thread"],
    );
}

#[test]
fn crashing_guests_die_by_their_signal() {
    let crash = guest("crash");
    for (how, signal) in [
        ("trap", nix::libc::SIGTRAP),
        ("segv", nix::libc::SIGSEGV),
        ("abort", nix::libc::SIGABRT),
    ] {
        let output = run(&[&crash, Path::new(how)]);
        assert_eq!(
            output.status.signal(),
            Some(signal),
            "{how}: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Runs the guest with each of its threads on a vCPU of its own.
fn run_parallel(args: &[&Path]) -> Output {
    run_strace(&["--parallel"], args)
}

#[test]
fn parallel_pthreads() {
    let output = run_parallel(&[&guest("pthreads")]);
    assert_output(
        &output,
        0,
        &["counter=40000/40000 joins=60/60 distinct_ports=1"],
        &["threading: Parallel"],
    );
}

#[test]
fn parallel_dispatch() {
    let output = run_parallel(&[&guest("dispatch")]);
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
        &[],
    );
}

#[test]
fn parallel_threads_run_at_once() {
    // Without preemption: the worker can only run while main spins on another vCPU.
    let output = run_strace(&["--parallel", "--quantum", "0"], &[&guest("preempt")]);
    assert_output(&output, 0, &["worker ran while main spun: yes"], &[]);
}

#[test]
fn parallel_exec() {
    let output = run_parallel(&[
        Path::new("/usr/bin/env"),
        Path::new("/bin/echo"),
        Path::new("exec works"),
    ]);
    assert_output(&output, 0, &["exec works"], &["exec \"/bin/echo\""]);
}

#[test]
fn parallel_threading_carries_over_to_spawned_processes() {
    let output = run_parallel(&[&guest("spawn")]);
    assert_output(
        &output,
        3,
        &["child says hi", "echo exited 0", "false exited 1"],
        &[],
    );
    let trace = String::from_utf8_lossy(&output.stderr);
    assert_eq!(trace.matches("threading: Parallel").count(), 3, "{trace}");
    assert!(!trace.contains("threading: TimeShared"), "{trace}");
}
