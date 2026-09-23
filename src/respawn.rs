//! Re-running the current program in a fresh process until its address space layout works out.
//!
//! Some host allocations we can't control (e.g. the host's own malloc heap) are placed randomly at
//! startup and may leave no room for what the guest needs, which is reported as an
//! [`AddressSpaceConflict`]. Since the layout differs in every process, the fix is to try again in
//! a new one:
//!
//! ```no_run
//! fn main() -> anyhow::Result<()> {
//!     appbox::respawn::respawn(&Default::default())?;
//!     if let Err(err) = run() {
//!         appbox::respawn::exit_if_retryable(&err);
//!         return Err(err);
//!     }
//!     Ok(())
//! }
//! # fn run() -> anyhow::Result<()> { Ok(()) }
//! ```

use std::ffi::CString;

use anyhow::{bail, Context, Result};
use log::{debug, warn};

use crate::layout::{is_address_space_conflict, AddressSpaceConflict};

const RESPAWNED_ENV: &str = "APPBOX_RESPAWNED";

/// Exit code a respawned child uses to ask for another attempt.
pub const RETRY_EXIT_CODE: i32 = 200;

// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/spawn.h#L62
const _POSIX_SPAWN_DISABLE_ASLR: i16 = 0x0100;

pub struct RespawnOptions {
    pub max_attempts: usize,
    pub disable_aslr: bool,
}

impl Default for RespawnOptions {
    fn default() -> Self {
        Self {
            max_attempts: 100,
            disable_aslr: false,
        }
    }
}

/// Whether this process is a child started by [`respawn`].
pub fn is_respawned() -> bool {
    std::env::var_os(RESPAWNED_ENV).is_some()
}

/// Runs the current executable (with the same arguments and environment) in a child process,
/// starting a new one whenever it exits with [`RETRY_EXIT_CODE`], then exits with the child's
/// status. Only returns in the child, which should report retryable failures with
/// [`exit_if_retryable`].
pub fn respawn(options: &RespawnOptions) -> Result<()> {
    if is_respawned() {
        return Ok(());
    }

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
    if options.disable_aslr
        && unsafe { nix::libc::posix_spawnattr_setflags(&mut attr, _POSIX_SPAWN_DISABLE_ASLR) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("posix_spawnattr_setflags");
    }

    for attempt in 1..=options.max_attempts {
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
        debug!("respawned as pid {} (attempt {})", pid, attempt);

        use nix::sys::wait::{waitpid, WaitStatus};
        match waitpid(nix::unistd::Pid::from_raw(pid), None)? {
            WaitStatus::Exited(_, RETRY_EXIT_CODE) => {
                warn!(
                    "address space conflict, retrying in a new process (attempt {}/{})",
                    attempt, options.max_attempts
                );
            }
            WaitStatus::Exited(_, code) => std::process::exit(code),
            WaitStatus::Signaled(_, signal, _) => std::process::exit(128 + signal as i32),
            status => bail!("unexpected child wait status: {:?}", status),
        }
    }
    Err(anyhow::Error::new(AddressSpaceConflict {
        what: "the guest",
    }))
    .context(format!("gave up after {} attempts", options.max_attempts))
}

/// In a child started by [`respawn`], exits with [`RETRY_EXIT_CODE`] if `err` is an
/// [`AddressSpaceConflict`] so that the parent tries again.
pub fn exit_if_retryable(err: &anyhow::Error) {
    if is_respawned() && is_address_space_conflict(err) {
        warn!("{:#}", err);
        std::process::exit(RETRY_EXIT_CODE);
    }
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
