pub(crate) const KERN_SUCCESS: i32 = 0;
pub(crate) const VM_FLAGS_FIXED: i32 = 0;
pub(crate) const VM_FLAGS_OVERWRITE: i32 = 0x4000;
pub(crate) const VM_PROT_READ: i32 = 0x1;
pub(crate) const VM_PROT_WRITE: i32 = 0x2;
pub(crate) const VM_REGION_BASIC_INFO_64: i32 = 9;
// sizeof(vm_region_basic_info_data_64_t) / sizeof(natural_t)
pub(crate) const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

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

    pub(crate) fn task_for_pid(
        target_tport: nix::libc::mach_port_t,
        pid: nix::libc::pid_t,
        task: *mut nix::libc::mach_port_t,
    ) -> i32;

    pub(crate) fn mach_vm_region(
        target: nix::libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        info_count: *mut u32,
        object_name: *mut nix::libc::mach_port_t,
    ) -> i32;

    pub(crate) fn mach_vm_read_overwrite(
        target: nix::libc::mach_port_t,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> i32;

    pub(crate) fn mach_vm_write(
        target: nix::libc::mach_port_t,
        address: u64,
        data: usize,
        data_count: u32,
    ) -> i32;

    pub(crate) fn mach_port_deallocate(
        task: nix::libc::mach_port_t,
        name: nix::libc::mach_port_t,
    ) -> i32;
}
