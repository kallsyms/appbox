//! Which of the host process's file descriptors are the guest's.
//!
//! The guest shares the host's descriptor table, so exec can only apply close-on-exec to the
//! descriptors the guest owns: closing every `FD_CLOEXEC` descriptor would also close the
//! embedder's own (Rust's standard library opens everything close-on-exec). The guest owns what
//! it inherited, i.e. what was open without `FD_CLOEXEC` when appbox started (anything inherited
//! across the host's own exec must lack it), plus what its syscalls create.
//!
//! Descriptors created in ways not tracked here (e.g. received over a socket with `SCM_RIGHTS`)
//! are left open across exec.

use std::collections::{BTreeMap, BTreeSet};

use log::debug;

use crate::hyperpom::memory::VirtMemAllocator;
use crate::syscalls;
use crate::threads::{SyscallReturn, ThreadId};

// See sys/proc_info.h.
const PROC_PIDLISTFDS: i32 = 1;
const PROC_FDINFO_SIZE: usize = 8;

/// The host process's open descriptors.
pub(crate) fn open_fds() -> Vec<i32> {
    let pid = std::process::id() as i32;
    let size = unsafe {
        nix::libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    if size <= 0 {
        return Vec::new();
    }
    // Room for a few opened meanwhile.
    let mut buf = vec![0u8; size as usize + 16 * PROC_FDINFO_SIZE];
    let size = unsafe {
        nix::libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr() as *mut _,
            buf.len() as i32,
        )
    };
    // struct proc_fdinfo { int32_t proc_fd; uint32_t proc_fdtype; }
    buf[..size.max(0) as usize]
        .chunks_exact(PROC_FDINFO_SIZE)
        .map(|info| i32::from_ne_bytes(info[..4].try_into().unwrap()))
        .collect()
}

fn is_close_on_exec(fd: i32) -> Option<bool> {
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    (flags >= 0).then_some(flags & nix::libc::FD_CLOEXEC != 0)
}

/// Syscalls that return a new descriptor in x0.
fn returns_fd(num: u64, args: &[u64; 16]) -> bool {
    match num {
        syscalls::SYS_open
        | syscalls::SYS_open_nocancel
        | syscalls::SYS_openat
        | syscalls::SYS_openat_nocancel
        | syscalls::SYS_open_extended
        | syscalls::SYS_open_dprotected_np
        | syscalls::SYS_openat_dprotected_np
        | syscalls::SYS_guarded_open_np
        | syscalls::SYS_guarded_open_dprotected_np
        | syscalls::SYS_guarded_kqueue_np
        | syscalls::SYS_kqueue
        | syscalls::SYS_socket
        | syscalls::SYS_accept
        | syscalls::SYS_accept_nocancel
        | syscalls::SYS_dup
        | syscalls::SYS_dup2
        | syscalls::SYS_fileport_makefd
        | syscalls::SYS_openbyid_np
        | syscalls::SYS_fhopen
        | syscalls::SYS_necp_open
        | syscalls::SYS_necp_session_open => true,
        syscalls::SYS_fcntl | syscalls::SYS_fcntl_nocancel => {
            matches!(args[1] as i32, nix::libc::F_DUPFD | nix::libc::F_DUPFD_CLOEXEC)
        }
        _ => false,
    }
}

/// Whether `track` could change anything for syscall `num`.
pub(crate) fn affects_fds(num: u64, args: &[u64; 16]) -> bool {
    returns_fd(num, args)
        || matches!(
            num,
            syscalls::SYS_pipe
                | syscalls::SYS_socketpair
                | syscalls::SYS_close
                | syscalls::SYS_close_nocancel
                | syscalls::SYS_guarded_close_np
        )
}

/// The descriptors syscall `num` created, given what it returned.
pub(crate) fn created_fds(
    vma: &VirtMemAllocator,
    num: u64,
    args: &[u64; 16],
    (ret0, ret1, flags): SyscallReturn,
) -> Vec<i32> {
    if flags & (1 << 29) != 0 {
        return Vec::new();
    }
    if returns_fd(num, args) {
        return vec![ret0 as i32];
    }
    match num {
        syscalls::SYS_pipe => vec![ret0 as i32, ret1 as i32],
        syscalls::SYS_socketpair => match vma.read_qword(args[3]) {
            Ok(pair) => vec![pair as i32, (pair >> 32) as i32],
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Whether syscall `num` closes its first argument.
pub(crate) fn closes_fd(num: u64) -> bool {
    matches!(
        num,
        syscalls::SYS_close | syscalls::SYS_close_nocancel | syscalls::SYS_guarded_close_np
    )
}

#[derive(Clone)]
pub(crate) struct GuestFds {
    fds: BTreeSet<i32>,
    /// Descriptor syscalls that guest threads are blocked in, whose results are tracked once the
    /// threads resume.
    pending: BTreeMap<ThreadId, (u64, [u64; 16])>,
}

impl GuestFds {
    /// Starts with the descriptors the guest inherited.
    pub(crate) fn new() -> Self {
        let fds = open_fds()
            .into_iter()
            .filter(|&fd| is_close_on_exec(fd) == Some(false))
            .collect();
        Self {
            fds,
            pending: BTreeMap::new(),
        }
    }

    /// Tracks the descriptors syscall `num` created or closed, given what it returned.
    pub(crate) fn track(
        &mut self,
        vma: &VirtMemAllocator,
        num: u64,
        args: &[u64; 16],
        ret: SyscallReturn,
    ) {
        self.fds.extend(created_fds(vma, num, args, ret));
        if ret.2 & (1 << 29) == 0 && closes_fd(num) {
            self.fds.remove(&(args[0] as i32));
        }
    }

    pub(crate) fn contains_fd(&self, fd: i32) -> bool {
        self.fds.contains(&fd)
    }

    /// Notes that thread `id` is blocked in syscall `num`, if it could affect descriptors.
    pub(crate) fn blocked(&mut self, id: ThreadId, num: u64, args: &[u64; 16]) {
        if affects_fds(num, args) {
            self.pending.insert(id, (num, *args));
        }
    }

    /// Tracks the syscall thread `id` was blocked in, now that it has returned `ret`.
    pub(crate) fn resumed(&mut self, vma: &VirtMemAllocator, id: ThreadId, ret: SyscallReturn) {
        if let Some((num, args)) = self.pending.remove(&id) {
            self.track(vma, num, &args, ret);
        }
    }

    /// Whether thread `id` is blocked in a descriptor syscall.
    pub(crate) fn is_pending(&self, id: ThreadId) -> bool {
        self.pending.contains_key(&id)
    }

    /// Closes the guest's close-on-exec descriptors, as exec does.
    pub(crate) fn close_on_exec(&mut self) {
        self.pending.clear();
        self.fds.retain(|&fd| match is_close_on_exec(fd) {
            Some(true) => {
                debug!("closing close-on-exec fd {fd}");
                unsafe { nix::libc::close(fd) };
                false
            }
            Some(false) => true,
            // Closed some way we didn't see.
            None => false,
        });
    }

    #[cfg(test)]
    fn contains(&self, fd: i32) -> bool {
        self.contains_fd(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::VM_TEST_LOCK;
    use crate::vm::VmManager;
    use std::os::fd::{AsRawFd, IntoRawFd};

    fn ok(fd: i32) -> SyscallReturn {
        (fd as u64, 0, 0)
    }

    /// Without inherited descriptors, which could belong to other tests running meanwhile.
    fn empty() -> GuestFds {
        GuestFds {
            fds: BTreeSet::new(),
            pending: BTreeMap::new(),
        }
    }

    #[test]
    fn inherits_only_fds_without_close_on_exec() {
        // std opens close-on-exec, like an embedder's own files.
        let embedders = std::fs::File::open("/dev/null").unwrap();
        let inherited = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        unsafe { nix::libc::fcntl(inherited, nix::libc::F_SETFD, 0) };

        let fds = GuestFds::new();
        assert!(fds.contains(inherited));
        assert!(!fds.contains(embedders.as_raw_fd()));
        unsafe { nix::libc::close(inherited) };
    }

    #[test]
    fn exec_closes_only_the_guests_close_on_exec_fds() {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vm = VmManager::new().unwrap();
        let vma = &vm.vma();
        let mut fds = empty();
        let embedders = std::fs::File::open("/dev/null").unwrap();
        let open = |cloexec: bool| {
            let fd = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
            if !cloexec {
                unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) };
            }
            fd
        };
        let (cloexec, kept) = (open(true), open(false));
        let args = [0u64; 16];
        fds.track(vma, syscalls::SYS_open, &args, ok(cloexec));
        fds.track(vma, syscalls::SYS_open, &args, ok(kept));
        // Failed syscalls don't create anything.
        fds.track(vma, syscalls::SYS_open, &args, (9999, 0, 1 << 29));
        assert!(!fds.contains(9999));

        fds.close_on_exec();
        assert_eq!(is_close_on_exec(cloexec), None);
        assert_eq!(is_close_on_exec(kept), Some(false));
        assert_eq!(is_close_on_exec(embedders.as_raw_fd()), Some(true));
        assert!(!fds.contains(cloexec) && fds.contains(kept));
        unsafe { nix::libc::close(kept) };
    }

    #[test]
    fn tracks_closes_and_dups() {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vm = VmManager::new().unwrap();
        let vma = &vm.vma();
        let mut fds = empty();
        let mut args = [0u64; 16];
        args[1] = nix::libc::F_DUPFD_CLOEXEC as u64;
        fds.track(vma, syscalls::SYS_fcntl, &args, ok(1000));
        fds.track(vma, syscalls::SYS_pipe, &args, (1001, 1002, 0));
        assert!(fds.contains(1000) && fds.contains(1001) && fds.contains(1002));

        args[0] = 1001;
        fds.track(vma, syscalls::SYS_close, &args, ok(0));
        assert!(!fds.contains(1001));

        // Blocked syscalls are tracked once their thread resumes.
        fds.blocked(3, syscalls::SYS_accept, &args);
        assert!(fds.is_pending(3));
        fds.resumed(vma, 3, ok(1003));
        assert!(fds.contains(1003) && !fds.is_pending(3));
    }
}
