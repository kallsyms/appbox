pub(crate) const KERN_SUCCESS: i32 = 0;
pub(crate) const VM_FLAGS_FIXED: i32 = 0;
pub(crate) const VM_FLAGS_OVERWRITE: i32 = 0x4000;

unsafe extern "C" {
    pub(crate) fn mach_vm_allocate(
        target: nix::libc::mach_port_t,
        address: *mut u64,
        size: u64,
        flags: i32,
    ) -> i32;

    pub(crate) fn mach_vm_deallocate(
        target: nix::libc::mach_port_t,
        address: u64,
        size: u64,
    ) -> i32;

    pub(crate) fn mach_vm_map(
        target: nix::libc::mach_port_t,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: nix::libc::mach_port_t,
        offset: u64,
        copy: i32,
        cur_protection: i32,
        max_protection: i32,
        inheritance: u32,
    ) -> i32;
}
