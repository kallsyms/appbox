//! Replacing the guest's process image, as `execve()` does.
//!
//! The guest shares the host process, so its `execve()` can't be forwarded: that would replace the
//! host (and panics the kernel while it tears down the VM). Instead the trap handler returns
//! [`ExitKind::Exec`](crate::hyperpom::crash::ExitKind::Exec), and the caller runs [`exec`] to load
//! the new image into a fresh VM, as the kernel would.
//!
//! File descriptors are shared with the host, so close-on-exec is only applied to the ones the
//! guest owns (see fds.rs).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;
use log::debug;

use crate::applevisor as av;
use crate::loader::{arm64_slice, load_macho, Loader};
use crate::trap::DefaultTrapHandler;
use crate::vm::VmManager;

/// What the guest asked to run: the executable (after following any `#!` line) and the
/// arguments and environment it'll see.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ExecRequest {
    pub path: PathBuf,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

// See exec_shell_imgact in xnu's bsd/kern/kern_exec.c.
const INTERPRETER_LINE_MAX: usize = 512;

fn is_whitespace(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn is_eol(c: u8) -> bool {
    c == b'#' || c == b'\n'
}

/// The `#!` line's interpreter and arguments, if `header` (the start of a file) has one.
fn parse_interpreter_line(header: &[u8]) -> Option<Result<Vec<String>, i32>> {
    let line = header.strip_prefix(b"#!")?;
    let line = &line[..line.len().min(INTERPRETER_LINE_MAX - 2)];
    let Some(end) = line.iter().position(|&c| is_eol(c)) else {
        return Some(Err(nix::libc::ENOEXEC));
    };
    let words: Vec<String> = line[..end]
        .split(|&c| is_whitespace(c))
        .filter(|word| !word.is_empty())
        .map(|word| String::from_utf8_lossy(word).into_owned())
        .collect();
    if words.is_empty() {
        return Some(Err(nix::libc::ENOEXEC));
    }
    Some(Ok(words))
}

/// Reads the start of `path`, failing with the errno `execve` would if it can't be executed.
fn read_executable_header(path: &Path) -> Result<Vec<u8>, i32> {
    let errno = |err: std::io::Error| err.raw_os_error().unwrap_or(nix::libc::EIO);
    nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).map_err(|err| err as i32)?;
    let metadata = std::fs::metadata(path).map_err(errno)?;
    if !metadata.is_file() {
        return Err(nix::libc::EACCES);
    }
    let mut header = Vec::with_capacity(INTERPRETER_LINE_MAX);
    std::fs::File::open(path)
        .map_err(errno)?
        .take(INTERPRETER_LINE_MAX as u64)
        .read_to_end(&mut header)
        .map_err(errno)?;
    Ok(header)
}

fn check_loadable(path: &Path) -> Result<(), i32> {
    let data = std::fs::read(path).map_err(|err| err.raw_os_error().unwrap_or(nix::libc::EIO))?;
    arm64_slice(&data).map(|_| ()).map_err(|err| {
        debug!("can't exec {}: {:#}", path.display(), err);
        nix::libc::ENOEXEC
    })
}

impl ExecRequest {
    /// Works out what `execve(path, argv, envp)` would run, following a `#!` interpreter line
    /// (only one level, like xnu). Returns the errno `execve` would fail with if it can't.
    pub fn resolve(path: PathBuf, argv: Vec<String>, envp: Vec<String>) -> Result<Self, i32> {
        let header = read_executable_header(&path)?;
        let Some(interpreter_line) = parse_interpreter_line(&header) else {
            check_loadable(&path)?;
            return Ok(Self { path, argv, envp });
        };

        let mut interpreter_argv = interpreter_line?;
        let interpreter = PathBuf::from(&interpreter_argv[0]);
        let interpreter_header = read_executable_header(&interpreter)?;
        if interpreter_header.starts_with(b"#!") {
            return Err(nix::libc::ENOEXEC);
        }
        check_loadable(&interpreter)?;

        // The interpreter gets the script's path in place of argv[0].
        interpreter_argv.push(path.to_string_lossy().into_owned());
        interpreter_argv.extend(argv.into_iter().skip(1));
        Ok(Self {
            path: interpreter,
            argv: interpreter_argv,
            envp,
        })
    }
}

/// Replaces the guest in `vm` with `request`'s executable, like `execve()`: all guest memory is
/// released, and a fresh VM is created with the new image loaded and its entry point and stack
/// set up, ready to run.
///
/// Like the kernel, this is past the point of no return once started: on error the old image is
/// already gone.
pub fn exec(
    vm: VmManager,
    loader: Loader,
    handler: &mut DefaultTrapHandler,
    request: &ExecRequest,
) -> Result<(VmManager, Loader)> {
    debug!("exec {:?}", request);
    handler.prepare_for_exec();
    drop(loader);
    // Only one VM can exist per process, so the old one must be gone before creating another.
    drop(vm);

    let mut vm = VmManager::new()?;
    let loader = load_macho(
        &mut vm,
        &request.path,
        request.argv.clone(),
        request.envp.clone(),
    )?;
    vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
    vm.vcpu
        .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;
    Ok((vm, loader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_script(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("appbox-exec-{name}-{}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_interpreter_lines_like_xnu() {
        assert_eq!(
            parse_interpreter_line(b"#!  /usr/bin/env  python3 -u \t\nprint(1)"),
            Some(Ok(strings(&["/usr/bin/env", "python3", "-u"])))
        );
        assert_eq!(
            parse_interpreter_line(b"#!/bin/sh # comment\n"),
            Some(Ok(strings(&["/bin/sh"])))
        );
        assert_eq!(
            parse_interpreter_line(b"#!   \n"),
            Some(Err(nix::libc::ENOEXEC))
        );
        assert_eq!(
            parse_interpreter_line(&[b"#!/bin/sh ".as_slice(), &[b'x'; 600]].concat()),
            Some(Err(nix::libc::ENOEXEC))
        );
        assert_eq!(parse_interpreter_line(b"\xcf\xfa\xed\xfe"), None);
    }

    #[test]
    fn resolves_binaries_and_scripts() {
        let echo = ExecRequest::resolve("/bin/echo".into(), strings(&["echo", "hi"]), vec![]);
        assert_eq!(echo.unwrap().path, PathBuf::from("/bin/echo"));

        let script = temp_script("script", "#!/bin/echo -n\n");
        let request = ExecRequest::resolve(
            script.clone(),
            strings(&["ignored", "a", "b"]),
            strings(&["K=V"]),
        )
        .unwrap();
        assert_eq!(request.path, PathBuf::from("/bin/echo"));
        assert_eq!(
            request.argv,
            strings(&["/bin/echo", "-n", script.to_str().unwrap(), "a", "b"])
        );
        assert_eq!(request.envp, strings(&["K=V"]));
        std::fs::remove_file(script).unwrap();
    }

    #[test]
    fn exec_replaces_the_guest_image() -> Result<()> {
        let _guard = crate::test_support::VM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut vm = VmManager::new()?;
        let loader = load_macho(
            &mut vm,
            Path::new("/usr/bin/true"),
            strings(&["true"]),
            vec![],
        )?;
        let mut handler = DefaultTrapHandler::new()?;
        let old_entry = loader.entry_point;

        let request = ExecRequest::resolve(
            "/bin/echo".into(),
            strings(&["echo", "hi"]),
            strings(&["K=V"]),
        )
        .unwrap();
        let (vm, loader) = exec(vm, loader, &mut handler, &request)?;

        assert_ne!(loader.entry_point, old_entry);
        assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, loader.entry_point);
        let sp = vm.vcpu.get_sys_reg(av::SysReg::SP_EL0)?;
        assert_eq!(sp, loader.stack_pointer);
        let vma = vm.vma();
        assert_eq!(vma.read_qword(sp + 8)?, 2);
        assert_eq!(vma.read_cstring(vma.read_qword(sp + 16)?)?, "echo");
        assert_eq!(vma.read_cstring(vma.read_qword(sp + 24)?)?, "hi");
        assert_eq!(vma.read_cstring(vma.read_qword(sp + 40)?)?, "K=V");
        Ok(())
    }

    #[test]
    fn resolve_fails_with_execve_errnos() {
        let resolve = |path: &Path| ExecRequest::resolve(path.to_path_buf(), vec![], vec![]);
        assert_eq!(
            resolve(Path::new("/nonexistent/appbox")),
            Err(nix::libc::ENOENT)
        );
        assert_eq!(resolve(Path::new("/tmp")), Err(nix::libc::EACCES));

        let not_macho = temp_script("garbage", "not an executable\n");
        assert_eq!(resolve(&not_macho), Err(nix::libc::ENOEXEC));

        let inner = temp_script("inner", "#!/bin/sh\n");
        let nested = temp_script("nested", &format!("#!{}\n", inner.display()));
        assert_eq!(resolve(&nested), Err(nix::libc::ENOEXEC));

        for path in [not_macho, inner, nested] {
            std::fs::remove_file(path).unwrap();
        }
    }
}
