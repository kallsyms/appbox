//! Keeping host allocations out of the way of the guest's.
//!
//! Guest memory is mapped 1:1 into the host process, so any address the guest expects to be free
//! must also be free on the host. Most guest allocations go through us and can be placed wherever
//! we like, but some are made at fixed addresses the guest chooses itself.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;

use crate::mach::{
    mach_vm_allocate, mach_vm_deallocate, KERN_SUCCESS, VM_FLAGS_FIXED, VM_FLAGS_OVERWRITE,
};

const GIB: u64 = 1 << 30;

unsafe extern "C" {
    fn getentropy(buf: *mut std::ffi::c_void, len: usize) -> i32;
}

/// The host's address space has no room for something that has to live at a particular address.
///
/// This usually means the host's own malloc heap is in the way, i.e. the process wasn't started
/// through [`crate::respawn::respawn`].
#[derive(Debug)]
pub struct AddressSpaceConflict {
    pub(crate) what: &'static str,
}

impl fmt::Display for AddressSpaceConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no room in the host address space for {}; was the process started via \
             appbox::respawn?",
            self.what
        )
    }
}

impl std::error::Error for AddressSpaceConflict {}

// xzone malloc (libmalloc) reserves its "pointer range" with a fixed mach_vm_map at one of
// `candidates` XZONE_GRANULE-spaced addresses starting at `first`, picked by
// `(uint32_t)malloc_entropy[1] % candidates`, and aborts if that fails. See
// xzm_main_malloc_zone_init_range_groups (CONFIG_MACOS_RANGES) in libmalloc's xzone_segment.c.
const XZONE_GRANULE: u64 = 32 << 20;
// 4GiB guard + 16GiB range + 4GiB guard.
const XZONE_RESERVATION_SIZE: u64 = 24 * GIB;

struct XzoneWindow {
    first: u64,
    candidates: u64,
}

fn xzone_window(macos_major: u32) -> Option<XzoneWindow> {
    match macos_major {
        // libmalloc-812.100.31: candidates from 16GiB up to 63GiB minus the reservation.
        26 => Some(XzoneWindow {
            first: 16 * GIB,
            candidates: (63 * GIB - XZONE_RESERVATION_SIZE - 16 * GIB) / XZONE_GRANULE,
        }),
        // Source not yet published; measured on 27.0 (26A428) by varying malloc_entropy.
        27 => Some(XzoneWindow {
            first: 0x71_8000_0000,
            candidates: 0x440,
        }),
        _ => None,
    }
}

fn macos_major_version() -> Option<u32> {
    let mut buf = [0u8; 32];
    let mut len = buf.len();
    let ret = unsafe {
        nix::libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buf.as_mut_ptr() as _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    let version = std::str::from_utf8(&buf[..len])
        .ok()?
        .trim_end_matches('\0');
    version.split('.').next()?.parse().ok()
}

/// The `malloc_entropy` to give the host process (see [`crate::respawn`]) so that its own xzone
/// malloc heap lands at the top of the window, leaving the bottom for the guest's, and so that the
/// host's malloc layout is deterministic. `None` if the window isn't known for this macOS version.
///
/// The values are kept short since they have to fit over the kernel-provided string.
pub(crate) fn pinned_host_malloc_entropy() -> Option<[u64; 2]> {
    let window = xzone_window(macos_major_version()?)?;
    Some([0x5eed, window.candidates - 1])
}

/// Encodes `candidate` into `random` such that libmalloc picks it, keeping as much of the rest of
/// the entropy random as possible.
fn xzone_entropy(candidate: u64, candidates: u64, random: u64) -> u64 {
    let multiples = ((1u64 << 32) - candidate) / candidates;
    let low = candidate + candidates * ((random & 0xffff_ffff) % multiples);
    (random & !0xffff_ffff) | low
}

/// Where the guest's malloc will reserve its heap, and the `malloc_entropy` that makes it do so.
///
/// The range is reserved on the host until the guest asks for it (see [`Self::take_reservation`])
/// or this is dropped, so that host allocations made in the meantime can't take it.
#[derive(Debug)]
pub(crate) struct GuestMallocPlacement {
    pub(crate) entropy: [u64; 2],
    reservation: Reservation,
}

/// The guest malloc heap's range, reserved on the host until the guest takes it.
#[derive(Clone, Debug)]
pub(crate) struct Reservation {
    addr: u64,
    size: u64,
    taken: Arc<AtomicBool>,
}

impl Reservation {
    /// Reserves the range again, for the guest to take again, once the guest's mapping of it is
    /// gone (e.g. undone by restoring a checkpoint).
    pub(crate) fn give_back(&self) -> Result<()> {
        let mut addr = self.addr;
        let kr = unsafe {
            mach_vm_allocate(
                nix::libc::mach_task_self(),
                &mut addr,
                self.size,
                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            )
        };
        anyhow::ensure!(
            kr == KERN_SUCCESS,
            "reserving {:#x} for the guest's malloc heap again: kern_return_t={kr}",
            self.addr
        );
        self.taken.store(false, Ordering::Relaxed);
        Ok(())
    }
}

impl GuestMallocPlacement {
    /// Picks a free spot for the guest's xzone malloc heap reservation and reserves it.
    pub(crate) fn new() -> Result<Self> {
        let macos_major = macos_major_version().context("could not determine macOS version")?;
        let window = xzone_window(macos_major)
            .with_context(|| format!("guest malloc placement unknown for macOS {}", macos_major))?;

        for candidate in 0..window.candidates {
            let mut addr = window.first + candidate * XZONE_GRANULE;
            let kr = unsafe {
                mach_vm_allocate(
                    nix::libc::mach_task_self(),
                    &mut addr,
                    XZONE_RESERVATION_SIZE,
                    VM_FLAGS_FIXED,
                )
            };
            if kr != KERN_SUCCESS {
                continue;
            }
            debug!("reserved {:#x} for the guest's malloc heap", addr);

            let mut random = [0u64; 2];
            if unsafe { getentropy(random.as_mut_ptr() as _, 16) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            return Ok(Self {
                entropy: [
                    random[0],
                    xzone_entropy(candidate, window.candidates, random[1]),
                ],
                reservation: Reservation {
                    addr,
                    size: XZONE_RESERVATION_SIZE,
                    taken: Arc::new(AtomicBool::new(false)),
                },
            });
        }
        Err(AddressSpaceConflict {
            what: "the guest's malloc heap",
        }
        .into())
    }

    /// If `(addr, size)` is our reservation, hands it over to the guest: returns it (while not
    /// already taken), meaning the caller may overwrite the range.
    pub(crate) fn take_reservation(&self, addr: u64, size: u64) -> Option<Reservation> {
        let reservation = &self.reservation;
        ((reservation.addr, reservation.size) == (addr, size)
            && !reservation.taken.swap(true, Ordering::Relaxed))
        .then(|| reservation.clone())
    }
}

impl Drop for GuestMallocPlacement {
    fn drop(&mut self) {
        let reservation = &self.reservation;
        if !reservation.taken.load(Ordering::Relaxed) {
            unsafe {
                mach_vm_deallocate(
                    nix::libc::mach_task_self(),
                    reservation.addr,
                    reservation.size,
                )
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xzone_entropy_selects_candidate() {
        for (candidate, candidates, random) in [
            (0, 0x440, 0),
            (0x43f, 0x440, u64::MAX),
            (5, 0x2e0, 0x1234_5678_9abc_def0),
        ] {
            let entropy = xzone_entropy(candidate, candidates, random);
            assert_eq!((entropy as u32 as u64) % candidates, candidate);
            assert_eq!(entropy >> 32, random >> 32);
        }
    }

    #[test]
    fn macos_major_version_is_known() {
        assert!(macos_major_version().is_some_and(|major| major >= 13));
    }
}
