// For passing SIMD registers to Hypervisor.framework; see threads::set_simd_fp_reg.
#![feature(simd_ffi)]

pub mod commpage;
pub mod debug;
pub mod dyld;
pub mod dyld_cache_format;
pub mod exec;
pub mod gdb;
pub mod layout;
pub mod loader;
mod mach;
pub mod respawn;
pub mod symbols;
pub mod syscalls;
pub mod threads;
pub mod trap;
pub mod vm;

pub mod hyperpom;
pub mod applevisor {
    pub use applevisor::*;
}

pub use debug::{format_user_stack, format_vm_state, unwind_user_stack};
pub use symbols::Symbolication;

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;

    pub static VM_TEST_LOCK: Mutex<()> = Mutex::new(());
}
