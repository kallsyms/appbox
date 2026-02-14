use crate::applevisor as av;
use crate::hyperpom::crash::ExitKind;
use crate::hyperpom::memory::VirtMemAllocator;
use crate::loader::Loader;
use crate::syscalls;
use anyhow::Result;
use log::{debug, error, trace, warn};
use std::collections::{HashSet, VecDeque};
use std::ffi::CStr;

const KERN_SUCCESS: u64 = 0;
const KERN_DENIED: u64 = 53;
const KERN_NOT_FOUND: u64 = 56;
const SVC_ESR: u64 = 0x5600_0080;
const PAGE_ALIGN: u64 = 0x4000;

#[repr(C)]
struct MachMsgHeader {
    msgh_bits: u32,
    msgh_size: u32,
    msgh_remote_port: u32,
    msgh_local_port: u32,
    msgh_reserved: u32,
    msgh_id: u32,
}

#[repr(C)]
struct MigReplyError {
    hdr: MachMsgHeader,
    ndr: u64,
    ret_code: u32,
}

#[repr(C)]
struct KernelRpcMachVmMapRequest {
    head: MachMsgHeader,
    ndr: [u8; 8],
    target: u32,
    _pad0: u32,
    address: u64,
    size: u64,
    mask: u64,
    flags: i32,
    _pad1: u32,
    object: u32,
    _pad2: u32,
    offset: u64,
    copy: i32,
    cur_protection: i32,
    max_protection: i32,
    inheritance: i32,
}

#[repr(C)]
struct KernelRpcMachVmMapReply {
    head: MachMsgHeader,
    ndr: [u8; 8],
    ret_code: u32,
    _pad0: u32,
    address: u64,
}

pub struct SyscallContext {
    pub num: u64,
    pub args: [u64; 16],
    pub elr: u64,
    pub esr: u64,
}

pub struct SyscallResult {
    pub ret0: u64,
    pub ret1: u64,
    pub cflags: u64,
    pub exit: ExitKind,
    pub write_back: bool,
}

impl SyscallResult {
    pub fn cont(ret0: u64, ret1: u64, cflags: u64) -> Self {
        Self {
            ret0,
            ret1,
            cflags,
            exit: ExitKind::Continue,
            write_back: true,
        }
    }

    pub fn exit(exit: ExitKind) -> Self {
        Self {
            ret0: 0,
            ret1: 0,
            cflags: 0,
            exit,
            write_back: false,
        }
    }
}

pub trait TrapHandler {
    fn handle_syscall(
        &mut self,
        ctx: &SyscallContext,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        loader: &Loader,
    ) -> Result<SyscallResult>;
}

pub fn read_syscall_context(vcpu: &mut av::Vcpu) -> Result<SyscallContext> {
    let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
    let esr = vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
    let mut num = vcpu.get_reg(av::Reg::X16)?;
    if num <= 0xffff_ffff && (num & 0x8000_0000) != 0 {
        num |= 0xffff_ffff_0000_0000;
    }
    let args = [
        vcpu.get_reg(av::Reg::X0)?,
        vcpu.get_reg(av::Reg::X1)?,
        vcpu.get_reg(av::Reg::X2)?,
        vcpu.get_reg(av::Reg::X3)?,
        vcpu.get_reg(av::Reg::X4)?,
        vcpu.get_reg(av::Reg::X5)?,
        vcpu.get_reg(av::Reg::X6)?,
        vcpu.get_reg(av::Reg::X7)?,
        vcpu.get_reg(av::Reg::X8)?,
        vcpu.get_reg(av::Reg::X9)?,
        vcpu.get_reg(av::Reg::X10)?,
        vcpu.get_reg(av::Reg::X11)?,
        vcpu.get_reg(av::Reg::X12)?,
        vcpu.get_reg(av::Reg::X13)?,
        vcpu.get_reg(av::Reg::X14)?,
        vcpu.get_reg(av::Reg::X15)?,
    ];

    Ok(SyscallContext {
        num,
        args,
        elr,
        esr,
    })
}

pub fn write_syscall_result(
    vcpu: &mut av::Vcpu,
    elr: u64,
    ret0: u64,
    ret1: u64,
    cflags: u64,
) -> Result<()> {
    let cpsr = (vcpu.get_sys_reg(av::SysReg::SPSR_EL1)? & !(0b1111 << 28)) | cflags;
    vcpu.set_reg(av::Reg::X0, ret0)?;
    vcpu.set_reg(av::Reg::X1, ret1)?;
    vcpu.set_reg(av::Reg::CPSR, cpsr)?;
    vcpu.set_reg(av::Reg::PC, elr)?;
    Ok(())
}

pub fn forward_syscall(num: u64, args: &[u64; 16]) -> (u64, u64, u64) {
    let ret0: u64;
    let ret1: u64;
    let cflags: u64;

    trace!("Forwarding syscall 0x{:x}(0x{:x?})", num, args);
    unsafe {
        std::arch::asm!(
            "svc #0x80",
            "mov {ret0}, x0",
            "mov {ret1}, x1",
            "mrs {cflags}, NZCV",
            in("x0") args[0],
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            in("x6") args[6],
            in("x7") args[7],
            in("x8") args[8],
            in("x9") args[9],
            in("x10") args[10],
            in("x11") args[11],
            in("x12") args[12],
            in("x13") args[13],
            in("x14") args[14],
            in("x15") args[15],
            in("x16") num,
            ret0 = lateout(reg) ret0,
            ret1 = lateout(reg) ret1,
            cflags = lateout(reg) cflags,
        );
    }

    (ret0, ret1, cflags)
}

pub struct DefaultTrapHandler {
    map_fixed_next: u64,
    mappings: Vec<(u64, usize)>,
    tsd: u64,
}

impl DefaultTrapHandler {
    pub fn new() -> Self {
        Self::new_with_map_base(0x6_0000_0000)
    }

    pub fn new_with_map_base(map_fixed_next: u64) -> Self {
        Self {
            map_fixed_next,
            mappings: Vec::new(),
            tsd: 0,
        }
    }

    fn record_mapping(&mut self, addr: u64, size: usize) {
        self.mappings.push((addr, size));
    }

    fn remove_mapping(&mut self, addr: u64, size: u64) {
        if let Some(idx) = self
            .mappings
            .iter()
            .position(|&(va, len)| va == addr && len as u64 == size)
        {
            self.mappings.remove(idx);
        }
    }

    fn align_size(size: u64) -> u64 {
        (size + (PAGE_ALIGN - 1)) & !(PAGE_ALIGN - 1)
    }
}

impl TrapHandler for DefaultTrapHandler {
    fn handle_syscall(
        &mut self,
        ctx: &SyscallContext,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        loader: &Loader,
    ) -> Result<SyscallResult> {
        let _elr = ctx.elr;
        let esr = ctx.esr;
        if esr != SVC_ESR {
            error!("Unhandled ESR_EL1 value: {:#x}", esr);
            return Ok(SyscallResult::exit(ExitKind::Crash(
                "Unhandled fault".to_string(),
            )));
        }

        let num = ctx.num;
        let mut args = ctx.args;
        debug!(
            "Incoming syscall ({}) {:x}(x{:x?})",
            syscalls::syscall_name(num).unwrap_or("<unknown>"),
            num,
            args
        );

        let mut ret0: u64 = 0;
        let mut ret1: u64 = 0;
        let mut cflags: u64 = 0;
        let mut handled = false;

        // Stage 1: handle syscalls that need special handling.
        // Optionally also useful for tossing in debugging statements on specific syscalls.
        //
        // See https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master
        // and https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/syscall_sw.c#L105
        // for numbering.
        // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/arm64/sleh.c#L1686
        // for dispatch code.
        match num {
            syscalls::SYS_exit => {
                return Ok(SyscallResult::exit(ExitKind::Exit));
            }
            syscalls::SYS_munmap => {
                // TODO: actually remove from vma.
                // TODO: handle partial unmapping
                self.remove_mapping(args[0], args[1]);
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::SYS_mprotect => {
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::SYS_mmap => {
                // page align size
                args[1] = Self::align_size(args[1]);
                // fake fixed address
                if args[3] & nix::libc::MAP_FIXED as u64 == 0 {
                    args[3] |= nix::libc::MAP_FIXED as u64;
                    trace!("Fixing mmap address to {:x}", self.map_fixed_next);
                    args[0] = self.map_fixed_next;
                    self.map_fixed_next += args[1];
                }
            }
            syscalls::TRAP_mach_vm_allocate => {
                // TODO: ensure task is ourselves
                // page align size
                args[2] = Self::align_size(args[2]);
                // fake fixed address
                // Check for VM_FLAGS_ANYWHERE being set
                if args[3] & 1 != 0 {
                    args[3] &= !1;
                    trace!(
                        "Fixing mach_vm_allocate address to {:x}",
                        self.map_fixed_next
                    );
                    unsafe { *(args[1] as *mut u64) = self.map_fixed_next };
                    self.map_fixed_next += args[2];
                }
            }
            syscalls::TRAP_mach_vm_map => {
                // TODO: ensure task is ourselves
                // page align size
                args[2] = Self::align_size(args[2]);
                // fake fixed address
                // Check for VM_FLAGS_ANYWHERE being set
                if args[4] & 1 != 0 {
                    args[4] &= !1;
                    // If a mask is set greater than the 16k page we align to,
                    // bump map_fixed_next to the next correctly aligned address.
                    if args[3] > 0x3fff {
                        self.map_fixed_next = (self.map_fixed_next + args[3]) & !args[3];
                    }
                    trace!("Fixing mach_vm_map address to {:x}", self.map_fixed_next);
                    unsafe { *(args[1] as *mut u64) = self.map_fixed_next };
                    self.map_fixed_next += args[2];
                }
            }
            syscalls::TRAP_mach_vm_protect => {
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::TRAP_mach_vm_deallocate => {
                // TODO: handle partial unmapping
                self.remove_mapping(args[1], args[2]);
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::SYS_shm_open => {
                // TODO: why was this needed?
                // Maybe shm isn't allowed to be mapped into VM?
                let name = unsafe { CStr::from_ptr(args[0] as _) };
                trace!("shm_open({})", name.to_string_lossy());
                ret0 = KERN_DENIED;
                ret1 = 0;
                cflags = 1 << 29;
                handled = true;
            }
            syscalls::SYS_shared_region_check_np => {
                // Return where we loaded the dyld shared cache.
                // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/vm/vm_unix.c#L2017
                if args[0] != u64::MAX {
                    debug!(
                        "Returning {:x} for shared_region_check_np",
                        loader.shared_cache.base_address() as u64
                    );
                    unsafe {
                        *(args[0] as *mut u64) = loader.shared_cache.base_address() as u64;
                    }
                }
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::SYS_proc_info => {
                // This should be ignored by the host anyways
                // (https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/kern/task.c#L740)
                // but stub it out for good measure.
                if args[0] == 0xf {
                    debug!("Stubbing out proc_info for PROC_INFO_CALL_SET_DYLD_IMAGES");
                    ret0 = 0;
                    ret1 = 0;
                    cflags = 0;
                    handled = true;
                }
            }
            syscalls::TRAP_mach_msg2 => {
                // We need to stub a few messages here.
                // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/mach_traps.h#L465
                // for trap argument layout.
                let msgh_id = args[4] >> 32;
                match msgh_id {
                    3405 => {
                        // task_info with TASK_DYLD_INFO. Return NOT_FOUND.
                        // Subsystem task (3400), 6th routine so id 3405.
                        // https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/task.defs#L69
                        let flavor: u32 = unsafe { *((args[0] + 0x20) as *const u32) };
                        if flavor == 0x11 {
                            debug!("Returning NOT_FOUND for task_info flavor TASK_DYLD_INFO");
                            ret0 = KERN_NOT_FOUND;
                            ret1 = 0;
                            cflags = 1 << 29;
                            handled = true;
                        }
                    }
                    4811 => unsafe {
                        // mach_vm_map
                        // https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/mach/mach_vm.defs#L352
                        let req = args[0] as *mut KernelRpcMachVmMapRequest;
                        // In macOS 14, the above does not work for some reason (returning MACH_SEND_INVALID_REPLY), but only on replay.
                        // To get around this, emulate the map behavior with mmap.
                        // TODO: this assumes object == 0.
                        (*req).size = Self::align_size((*req).size);
                        if (*req).flags & 1 != 0 {
                            trace!(
                                "Fixing kernelrpc_mach_vm_map address to {:x}",
                                self.map_fixed_next
                            );
                            (*req).address = self.map_fixed_next;
                            self.map_fixed_next += (*req).size;
                        }

                        let address = (*req).address;
                        nix::libc::mmap(
                            address as _,
                            (*req).size as _,
                            (*req).cur_protection as _,
                            nix::libc::MAP_PRIVATE
                                | nix::libc::MAP_ANONYMOUS
                                | nix::libc::MAP_FIXED,
                            -1,
                            0,
                        );
                        vma.map_1to1(address, (*req).size as _, av::MemPerms::RWX)?;
                        self.record_mapping(address, (*req).size as _);

                        let reply = args[0] as *mut KernelRpcMachVmMapReply;
                        (*reply).head.msgh_bits = 0x1200;
                        (*reply).head.msgh_size =
                            std::mem::size_of::<KernelRpcMachVmMapReply>() as _;
                        (*reply).head.msgh_remote_port = 0;
                        (*reply).head.msgh_id = (*reply).head.msgh_id + 100;
                        (*reply).ret_code = KERN_SUCCESS as _;
                        (*reply).address = address;

                        ret0 = KERN_SUCCESS;
                        handled = true;
                    },
                    8000 => {
                        // task_restartable_ranges_register. Fake return SUCCESS.
                        // Subsystem task_restartable (8000), 0th routine.
                        debug!("Returning KERN_SUCCESS for task_restartable_ranges_register");
                        unsafe {
                            let reply = args[0] as *mut MigReplyError;
                            // Incoming msgh_bits is 0x1513.
                            // On a real system, reply is 0x1200.
                            // idk, maybe the remote bits (0x13=MACH_MSG_TYPE_COPY_SEND) gets reduced to
                            // MACH_MSG_TYPE_PORT_SEND (0x12)?
                            (*reply).hdr.msgh_bits = 0x1200;
                            (*reply).hdr.msgh_size = 36;
                            (*reply).hdr.msgh_remote_port = 0;
                            (*reply).hdr.msgh_reserved = 0;
                            (*reply).hdr.msgh_id = (*reply).hdr.msgh_id + 100;
                            (*reply).ndr = 0x100000000;
                            (*reply).ret_code = KERN_SUCCESS as _;
                        }
                        ret0 = KERN_SUCCESS;
                        ret1 = 0;
                        cflags = 0;
                        handled = true;
                    }
                    _ => {}
                }
            }
            0x8000_0000 | 0xffff_ffff_8000_0000 => {
                // platform_syscall
                let code = args[3];
                match code {
                    2 => {
                        self.tsd = args[0];
                        handled = true;
                    }
                    3 => {
                        ret0 = self.tsd;
                        handled = true;
                    }
                    _ => {
                        warn!("Unknown platform syscall {}", code);
                    }
                }
            }
            _ => {}
        }

        if !handled {
            (ret0, ret1, cflags) = forward_syscall(num, &args);
        }

        // Stage 2.5: map newly allocated memory into the VM as necessary.
        match num {
            syscalls::SYS_mmap => {
                if cflags & (1 << 29) == 0 {
                    trace!("1:1 map of {:x} {:x} due to mmap", ret0, args[1]);
                    vma.map_1to1(ret0, args[1] as _, av::MemPerms::RWX)?;
                    self.record_mapping(ret0, args[1] as _);
                }
            }
            syscalls::TRAP_mach_vm_allocate => {
                if ret0 == KERN_SUCCESS {
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!(
                        "1:1 map of {:x} {:x} due to mach_vm_allocate",
                        addr,
                        args[2]
                    );
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.record_mapping(addr, args[2] as usize);
                }
            }
            syscalls::TRAP_mach_vm_map => {
                if ret0 == KERN_SUCCESS {
                    let addr: u64 = unsafe { *(args[1] as *const u64) };
                    trace!("1:1 map of {:x} {:x} due to mach_vm_map", addr, args[2]);
                    vma.map_1to1(addr, args[2] as usize, av::MemPerms::RWX)?;
                    self.record_mapping(addr, args[2] as usize);
                }
            }
            _ => {}
        }

        vcpu.set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tsd)?;
        Ok(SyscallResult::cont(ret0, ret1, cflags))
    }
}

// Explore from the given set of potential pointers, returning a set of pages that are
// accessible from the set of pointers.
// Currently recurses up to 2 levels deep, as I can't think of any syscalls which would
// pointer chase more than that.
pub fn explore_pointers(vma: &VirtMemAllocator, entry_points: &[u64]) -> HashSet<u64> {
    let mut valid_pages = HashSet::new();
    let mut queue = entry_points
        .iter()
        .filter_map(|&addr| {
            if check_ptr(vma, addr, &mut valid_pages) {
                Some((addr, 0))
            } else {
                None
            }
        })
        .collect::<VecDeque<_>>();
    let mut pages = HashSet::from_iter(queue.iter().map(|&(addr, _)| addr & !0xfff));

    while let Some((start_addr, depth)) = queue.pop_front() {
        // TODO: we can probably safely assume alignment here
        // TODO: +0x200 is arbitrary
        for addr in start_addr..start_addr + 0x200 {
            // +0x200 can take us to a new, potentially unmapped page so we have to check.
            // But we only have to do this when crossing the page boundry, not every time.
            if (addr + 7) & !0xfff != addr & !0xfff {
                if !check_ptr(vma, addr, &mut valid_pages) {
                    break;
                }
                pages.insert((addr + 7) & !0xfff);
            }
            let maybe_ptr = vma.read_qword(addr).unwrap();
            if !vma.read_byte(maybe_ptr).is_ok() {
                continue;
            }
            let ptr_page_addr = maybe_ptr & !0xfff;
            if !pages.contains(&ptr_page_addr) {
                pages.insert(ptr_page_addr);
                if depth < 2 {
                    queue.push_back((maybe_ptr, depth + 1));
                }
            }
        }
    }

    pages
}

fn check_ptr(vma: &VirtMemAllocator, ptr: u64, valid_pages: &mut HashSet<u64>) -> bool {
    if valid_pages.contains(&(ptr & !0xfff)) && valid_pages.contains(&((ptr + 7) & !0xfff)) {
        return true;
    }
    if vma.read_qword(ptr).is_ok() {
        valid_pages.insert(ptr & !0xfff);
        valid_pages.insert((ptr + 7) & !0xfff);
        return true;
    }
    false
}
