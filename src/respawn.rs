//! Re-running the current program in a fresh process with a host address space layout that leaves
//! room for the guest.
//!
//! Guest memory is mapped 1:1 into the host, so the guest's expectations about free address space
//! must hold in the host process too. The host's own malloc heap is the main obstacle: libmalloc
//! places it using the `malloc_entropy` the kernel passes in `apple[]`, randomly, in the same range
//! the guest's malloc will want (see [`crate::layout`]). [`respawn`] starts a child with ASLR
//! disabled and, before it runs, overwrites that entropy so the child's heap lands in a known spot.
//! This also makes the host layout deterministic, which matters for record/replay.
//!
//! Pinning needs `task_for_pid` on the child, so the binary must be signed with the
//! `com.apple.security.cs.debugger` and `com.apple.security.get-task-allow` entitlements.
//!
//! ```no_run
//! fn main() -> anyhow::Result<()> {
//!     appbox::respawn::respawn()?;
//!     // ... create the VM, load and run the guest ...
//!     Ok(())
//! }
//! ```

use std::ffi::CString;

use anyhow::{bail, Context, Result};
use log::debug;

use crate::layout::pinned_host_malloc_entropy;
use crate::mach::{
    mach_port_deallocate, mach_vm_read_overwrite, mach_vm_region, mach_vm_write, task_for_pid,
    KERN_SUCCESS, VM_PROT_READ, VM_PROT_WRITE, VM_REGION_BASIC_INFO_64,
    VM_REGION_BASIC_INFO_COUNT_64,
};

const RESPAWNED_ENV: &str = "APPBOX_RESPAWNED";

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h
const POSIX_SPAWN_START_SUSPENDED: i16 = 0x0080;
const _POSIX_SPAWN_DISABLE_ASLR: i16 = 0x0100;

/// Whether this process is a child started by [`respawn`].
pub fn is_respawned() -> bool {
    std::env::var_os(RESPAWNED_ENV).is_some()
}

/// Runs the current executable (with the same arguments and environment) in a child process with
/// ASLR disabled and its malloc entropy pinned, then exits with the child's status. Returns
/// immediately in the child.
pub fn respawn() -> Result<()> {
    if is_respawned() {
        return Ok(());
    }

    let entropy = pinned_host_malloc_entropy()
        .context("host malloc layout unknown for this macOS version")?;
    let executable = CString::new(
        std::env::current_exe()?
            .into_os_string()
            .into_encoded_bytes(),
    )?;
    let argv = CStringArray::new(std::env::args())?;
    let envp = CStringArray::new(
        std::env::vars()
            .map(|(k, v)| format!("{k}={v}"))
            .chain(std::iter::once(format!("{RESPAWNED_ENV}=1"))),
    )?;

    let mut attr: nix::libc::posix_spawnattr_t = std::ptr::null_mut();
    if unsafe { nix::libc::posix_spawnattr_init(&mut attr) } != 0 {
        return Err(std::io::Error::last_os_error()).context("posix_spawnattr_init");
    }
    let flags = POSIX_SPAWN_START_SUSPENDED | _POSIX_SPAWN_DISABLE_ASLR;
    if unsafe { nix::libc::posix_spawnattr_setflags(&mut attr, flags) } != 0 {
        return Err(std::io::Error::last_os_error()).context("posix_spawnattr_setflags");
    }

    let mut pid: nix::libc::pid_t = 0;
    let ret = unsafe {
        nix::libc::posix_spawn(
            &mut pid,
            executable.as_ptr(),
            std::ptr::null(),
            &attr,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::from_raw_os_error(ret)).context("posix_spawn");
    }
    debug!("respawned as pid {}", pid);
    let pid = nix::unistd::Pid::from_raw(pid);

    use nix::sys::signal::{kill, Signal};
    if let Err(err) = pin_malloc_entropy(pid.as_raw(), entropy) {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(pid, None);
        return Err(err.context("pinning the host malloc layout"));
    }
    kill(pid, Signal::SIGCONT)?;

    use nix::sys::wait::{waitpid, WaitStatus};
    match waitpid(pid, None)? {
        WaitStatus::Exited(_, code) => std::process::exit(code),
        WaitStatus::Signaled(_, signal, _) => std::process::exit(128 + signal as i32),
        status => bail!("unexpected child wait status: {:?}", status),
    }
}

/// Overwrites the `malloc_entropy` apple[] string of suspended process `pid`, which the kernel
/// placed on its stack at exec.
fn pin_malloc_entropy(pid: nix::libc::pid_t, entropy: [u64; 2]) -> Result<()> {
    let mut task: nix::libc::mach_port_t = 0;
    let kr = unsafe { task_for_pid(nix::libc::mach_task_self(), pid, &mut task) };
    if kr != KERN_SUCCESS {
        bail!(
            "task_for_pid failed (kern_return_t={}); needs the com.apple.security.cs.debugger \
             and com.apple.security.get-task-allow entitlements",
            kr
        );
    }
    let result = overwrite_malloc_entropy(task, entropy);
    unsafe { mach_port_deallocate(nix::libc::mach_task_self(), task) };
    result
}

fn overwrite_malloc_entropy(task: nix::libc::mach_port_t, entropy: [u64; 2]) -> Result<()> {
    const KEY: &[u8] = b"malloc_entropy=";
    // The stack is small this early; skip anything big (e.g. the shared region).
    const MAX_REGION_SIZE: u64 = 64 << 20;

    let replacement = format!("malloc_entropy=0x{:x},0x{:x}\0", entropy[0], entropy[1]);
    let mut addr = 0u64;
    loop {
        let mut size = 0u64;
        let mut info = [0i32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
        let mut count = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object_name = 0;
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object_name,
            )
        };
        if kr != KERN_SUCCESS {
            bail!("malloc_entropy not found in child");
        }
        // Only look in writable memory (the stack): the string also appears as a literal in any
        // binary that, like appbox, formats it.
        let protection = info[0];
        let rw = VM_PROT_READ | VM_PROT_WRITE;
        if protection & rw == rw && size <= MAX_REGION_SIZE {
            let mut data = vec![0u8; size as usize];
            let mut read = 0u64;
            let kr = unsafe {
                mach_vm_read_overwrite(task, addr, size, data.as_mut_ptr() as u64, &mut read)
            };
            if kr == KERN_SUCCESS {
                let found = data.windows(KEY.len()).enumerate().find_map(|(offset, w)| {
                    if w != KEY {
                        return None;
                    }
                    let len = data[offset..].iter().position(|&b| b == 0)?;
                    is_kernel_entropy_string(&data[offset..offset + len]).then_some((offset, len))
                });
                if let Some((offset, original_len)) = found {
                    if replacement.len() - 1 > original_len {
                        bail!("replacement malloc_entropy longer than the original");
                    }
                    let kr = unsafe {
                        mach_vm_write(
                            task,
                            addr + offset as u64,
                            replacement.as_ptr() as usize,
                            replacement.len() as u32,
                        )
                    };
                    if kr != KERN_SUCCESS {
                        bail!("mach_vm_write failed: kern_return_t={}", kr);
                    }
                    return Ok(());
                }
            }
        }
        addr += size;
    }
}

/// Whether `s` looks like the kernel's `malloc_entropy=0x<hex>,0x<hex>`.
fn is_kernel_entropy_string(s: &[u8]) -> bool {
    let Some(values) = s.strip_prefix(b"malloc_entropy=") else {
        return false;
    };
    let values: Vec<_> = values.split(|&b| b == b',').collect();
    values.len() == 2
        && values.iter().all(|v| {
            v.strip_prefix(b"0x")
                .is_some_and(|hex| !hex.is_empty() && hex.iter().all(u8::is_ascii_hexdigit))
        })
}

struct CStringArray {
    _owned: Vec<CString>,
    pointers: Vec<*mut nix::libc::c_char>,
}

impl CStringArray {
    fn new(strings: impl IntoIterator<Item = String>) -> Result<Self> {
        let owned = strings
            .into_iter()
            .map(CString::new)
            .collect::<Result<Vec<_>, _>>()?;
        let pointers = owned
            .iter()
            .map(|s| s.as_ptr() as *mut _)
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect();
        Ok(Self {
            _owned: owned,
            pointers,
        })
    }

    fn as_ptr(&self) -> *const *mut nix::libc::c_char {
        self.pointers.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_kernel_entropy_string() {
        assert!(is_kernel_entropy_string(
            b"malloc_entropy=0x1ba92ad87cbf923b,0x54025c9efff41442"
        ));
        assert!(!is_kernel_entropy_string(b"malloc_entropy=0x{:x},0x{:x}"));
        assert!(!is_kernel_entropy_string(b"malloc_entropy=0x1"));
        assert!(!is_kernel_entropy_string(b"malloc_entropy=0x,0x2"));
    }
}
