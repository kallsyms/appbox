// For passing SIMD registers to Hypervisor.framework; see threads::set_simd_fp_reg.
#![feature(simd_ffi)]

mod commpage;
mod debug;
mod dyld;
mod dyld_cache_format;
mod checkpoint;
mod exec;
mod fds;
pub mod gdb;
pub mod guest;
mod layout;
mod loader;
mod mach;
mod respawn;
mod runner;
mod symbols;
pub mod syscalls;
mod threading;
mod threads;
mod trap;
mod vm;
mod workq;

// Adapted from the hyperpom fuzzer, whose API is broader than appbox needs.
#[allow(dead_code)]
mod hyperpom;
pub mod applevisor {
    pub use applevisor::*;
}

use debug::unwind_user_stack;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    pub static VM_TEST_LOCK: Mutex<()> = Mutex::new(());
}
