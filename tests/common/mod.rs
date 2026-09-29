//! Building and running the examples and guest programs the end-to-end tests use.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(60);

fn target_dir() -> PathBuf {
    // target/<profile>/deps/<this test>
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

/// The example `name`, signed with the entitlements appbox needs.
pub fn example(name: &str) -> PathBuf {
    static BUILT: Mutex<Option<HashMap<String, PathBuf>>> = Mutex::new(None);
    let mut built = BUILT.lock().unwrap_or_else(|e| e.into_inner());
    let built = built.get_or_insert_with(HashMap::new);
    if let Some(path) = built.get(name) {
        return path.clone();
    }
    // Only a full `cargo test` builds examples.
    let status = Command::new(std::env::var("CARGO").unwrap_or("cargo".into()))
        .args(["build", "--example", name])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .unwrap();
    assert!(status.success(), "building the {name} example failed");
    let path = target_dir().join("examples").join(name);
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
    built.insert(name.to_string(), path.clone());
    path
}

/// Compiles `tests/guests/<name>.c`.
pub fn guest(name: &str) -> PathBuf {
    // Tests sharing a guest mustn't compile it over each other.
    static COMPILING: Mutex<()> = Mutex::new(());
    let _compiling = COMPILING.lock().unwrap_or_else(|e| e.into_inner());
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

/// Starts `command` in a process group of its own, with its output piped, so that
/// [`wait_with_timeout`] can kill it along with the respawned child and anything the guest
/// spawned.
pub fn spawn(command: &mut Command) -> Child {
    command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Waits for `child` (from [`spawn`]) to finish, killing it (and panicking) after [`TIMEOUT`].
pub fn wait_with_timeout(child: Child) -> Output {
    let pgid = child.id() as i32;
    let (done, output) = mpsc::channel();
    // Collecting output while waiting keeps the child from blocking on a full pipe.
    std::thread::spawn(move || done.send(child.wait_with_output()));
    match output.recv_timeout(TIMEOUT) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            unsafe { nix::libc::killpg(pgid, nix::libc::SIGKILL) };
            panic!("timed out");
        }
    }
}

/// Checks a run's exit status, and that its stdout contains each of `expected`.
#[track_caller]
pub fn assert_stdout(output: &Output, expected_status: i32, expected: &[&str]) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = || format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(output.status.code(), Some(expected_status), "{}", context());
    for line in expected {
        assert!(stdout.contains(line), "missing {line:?}\n{}", context());
    }
}
