use crate::applevisor as av;
use crate::exec::ExecRequest;
use crate::hyperpom::crash::ExitKind;
use crate::hyperpom::memory::VirtMemAllocator;
use crate::layout::AddressSpaceConflict;
use crate::loader::Loader;
use crate::mach::{
    mach_vm_allocate, mach_vm_deallocate, mach_vm_map, mach_vm_read_overwrite, VM_FLAGS_OVERWRITE,
};
use crate::syscalls;
use anyhow::{Context, Result};
use log::{debug, error, trace, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::io;
use std::sync::OnceLock;

const KERN_SUCCESS: u64 = 0;
const KERN_DENIED: u64 = 53;
const KERN_NOT_FOUND: u64 = 56;
const SVC_ESR: u64 = 0x5600_0080;
const PAGE_ALIGN: u64 = 0x4000;
// macOS 27 reserves 0x1_8000_0000..~0x70_0000_0000 in every process (shared region).
const FIXED_MAP_BASE: u64 = 0x80_0000_0000;
const FIXED_MAP_SIZE: u64 = 0x1_0000_0000;
// Guest memory is mapped into the VM as RWX regardless of host protections. A page the host
// has mapped executable is typed XNU_USER_EXEC by SPTM, and handing one to hv_vm_map panics the
// kernel (VIOLATION_ILLEGAL_MAPPING_TYPE). The host never executes guest memory, so drop
// execute permission from host-side mappings made on the guest's behalf.
const PROT_EXEC: u64 = nix::libc::PROT_EXEC as u64;

static FIXED_MAP_POOL: OnceLock<std::result::Result<(), i32>> = OnceLock::new();

#[derive(Clone, Copy)]
#[repr(C)]
struct MachMsgHeader {
    msgh_bits: u32,
    msgh_size: u32,
    msgh_remote_port: u32,
    msgh_local_port: u32,
    msgh_reserved: u32,
    msgh_id: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed(4))]
struct MigReplyError {
    hdr: MachMsgHeader,
    ndr: u64,
    ret_code: u32,
}
const _: () = assert!(std::mem::size_of::<MigReplyError>() == 36);

#[derive(Clone, Copy)]
#[repr(C, packed(4))]
struct MachMsgPortDescriptor {
    name: u32,
    _pad1: u32,
    _pad2: u16,
    disposition: u8,
    type_: u8,
}

// MIG request/reply layouts for mach_vm_map (mach_vm.defs), which MIG packs to 4 bytes.
#[derive(Clone, Copy)]
#[repr(C, packed(4))]
struct KernelRpcMachVmMapRequest {
    head: MachMsgHeader,
    descriptor_count: u32,
    object: MachMsgPortDescriptor,
    ndr: [u8; 8],
    address: u64,
    size: u64,
    mask: u64,
    flags: i32,
    offset: u64,
    copy: i32,
    cur_protection: i32,
    max_protection: i32,
    inheritance: i32,
}
const _: () = assert!(std::mem::size_of::<KernelRpcMachVmMapRequest>() == 100);

#[derive(Clone, Copy)]
#[repr(C, packed(4))]
struct KernelRpcMachVmMapReply {
    head: MachMsgHeader,
    ndr: [u8; 8],
    ret_code: u32,
    address: u64,
}
const _: () = assert!(std::mem::size_of::<KernelRpcMachVmMapReply>() == 44);

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
    if num <= 0xffff_ffff && (num & 0x8000_0000) != 0 && num != 0x8000_0000 {
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
    exit_status: Option<i32>,
}

impl DefaultTrapHandler {
    pub fn new() -> Result<Self> {
        Self::new_with_map_base(FIXED_MAP_BASE)
    }

    pub fn new_with_map_base(map_fixed_next: u64) -> Result<Self> {
        if !cfg!(test) {
            Self::ensure_fixed_map_pool()?;
        }
        Ok(Self {
            map_fixed_next,
            mappings: Vec::new(),
            tsd: 0,
            exit_status: None,
        })
    }

    /// The status the guest passed to `exit()`, once it has.
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }

    fn record_mapping(&mut self, addr: u64, size: usize) {
        self.mappings.push((addr, size));
    }

    fn remove_mapping(&mut self, addr: u64, size: u64) {
        let end = addr + size;
        self.mappings = std::mem::take(&mut self.mappings)
            .into_iter()
            .flat_map(|(va, len)| {
                let va_end = va + len as u64;
                if va_end <= addr || end <= va {
                    return vec![(va, len)];
                }
                let mut remaining = vec![];
                if va < addr {
                    remaining.push((va, (addr - va) as usize));
                }
                if end < va_end {
                    remaining.push((end, (va_end - end) as usize));
                }
                remaining
            })
            .collect();
    }

    /// Releases the host memory backing everything the guest has mapped through this handler,
    /// e.g. when replacing it on exec.
    pub fn release_guest_memory(&mut self) {
        for (addr, size) in self.mappings.drain(..) {
            unsafe { mach_vm_deallocate(nix::libc::mach_task_self(), addr, size as u64) };
        }
        self.tsd = 0;
    }

    fn align_size(size: u64) -> u64 {
        (size + (PAGE_ALIGN - 1)) & !(PAGE_ALIGN - 1)
    }

    fn ensure_fixed_map_pool() -> Result<()> {
        let reservation = FIXED_MAP_POOL.get_or_init(|| {
            let mut addr = FIXED_MAP_BASE;
            let kr = unsafe {
                mach_vm_allocate(nix::libc::mach_task_self(), &mut addr, FIXED_MAP_SIZE, 0)
            };
            if kr == KERN_SUCCESS as i32 && addr == FIXED_MAP_BASE {
                Ok(())
            } else {
                Err(if kr == KERN_SUCCESS as i32 {
                    nix::libc::KERN_NO_SPACE
                } else {
                    kr
                })
            }
        });

        match reservation {
            Ok(()) => Ok(()),
            Err(kr) => Err(anyhow::Error::new(AddressSpaceConflict {
                what: "the fixed mapping pool",
            }))
            .context(format!(
                "failed to reserve fixed mapping pool at {:#x} size {:#x}: kern_return_t={}",
                FIXED_MAP_BASE, FIXED_MAP_SIZE, kr
            )),
        }
    }

    fn release_fixed_map_range(&self, addr: u64, size: u64) -> Result<()> {
        let kr = unsafe { mach_vm_deallocate(nix::libc::mach_task_self(), addr, size) };
        if kr == KERN_SUCCESS as i32 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "failed to release fixed mapping pool range {:#x}..{:#x}: kern_return_t={}",
                addr,
                addr + size,
                kr
            ))
        }
    }

    fn restore_fixed_map_range(&self, addr: u64, size: u64) -> Result<()> {
        let mut requested = addr;
        let kr = unsafe { mach_vm_allocate(nix::libc::mach_task_self(), &mut requested, size, 0) };
        if kr == KERN_SUCCESS as i32 && requested == addr {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "failed to restore fixed mapping pool range {:#x}..{:#x}: kern_return_t={} actual={:#x}",
                addr,
                addr + size,
                kr,
                requested
            ))
        }
    }

    fn reserve_fixed_address(&mut self, size: u64, mask: Option<u64>) -> u64 {
        if let Some(mask) = mask {
            if mask > PAGE_ALIGN - 1 {
                self.map_fixed_next = (self.map_fixed_next + mask) & !mask;
            }
        }
        let addr = self.map_fixed_next;
        self.map_fixed_next += size;
        addr
    }

    fn unmap_from_vm(
        &mut self,
        vma: &mut VirtMemAllocator,
        loader: &Loader,
        addr: u64,
        size: u64,
    ) -> Result<()> {
        let start = addr & !(PAGE_ALIGN - 1);
        let size = Self::align_size(addr + size) - start;
        trace!("1:1 unmap of {:x} {:x}", start, size);
        // TODO: handle partial unmapping
        self.remove_mapping(start, size);
        loader.leak_mappings_overlapping(start, size);
        vma.unmap_1to1(start, size as usize)?;
        Ok(())
    }

    fn write_out_address(&self, out_addr: u64, value: u64) {
        unsafe { *(out_addr as *mut u64) = value };
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
        let mut released_fixed_map_range: Option<(u64, u64)> = None;

        // Stage 1: handle syscalls that need special handling.
        // Optionally also useful for tossing in debugging statements on specific syscalls.
        //
        // See https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/syscalls.master
        // and https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/syscall_sw.c#L105
        // for numbering.
        // See https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/osfmk/arm64/sleh.c#L1686
        // for dispatch code.
        match num {
            syscalls::SYS_posix_spawn => match read_posix_spawn(vma, &args) {
                // Replacing the calling process: an exec.
                Ok(spawn) if spawn.flags & POSIX_SPAWN_SETEXEC != 0 => {
                    if spawn.file_actions.is_some() {
                        ret0 = nix::libc::ENOTSUP as u64;
                        cflags = 1 << 29;
                    } else {
                        return Ok(SyscallResult::exit(ExitKind::Exec(spawn.request)));
                    }
                    handled = true;
                }
                // A new process, which gets its own host process and VM.
                Ok(spawn) => {
                    match crate::respawn::spawn_guest(&spawn) {
                        Ok(pid) => {
                            if args[0] != 0 {
                                vma.write_dword(args[0], pid.as_raw() as u32)?;
                            }
                            ret0 = 0;
                        }
                        Err(err) => {
                            warn!("failed to spawn guest process: {:#}", err);
                            ret0 = err
                                .downcast_ref::<io::Error>()
                                .and_then(io::Error::raw_os_error)
                                .unwrap_or(nix::libc::EAGAIN)
                                as u64;
                            cflags = 1 << 29;
                        }
                    }
                    handled = true;
                }
                Err(errno) => {
                    ret0 = errno as u64;
                    cflags = 1 << 29;
                    handled = true;
                }
            },
            syscalls::SYS_execve
            | syscalls::SYS___mac_execve
            | syscalls::SYS_fork
            | syscalls::SYS_vfork => {
                let request = match num {
                    // The child would have to be a copy of this process's guest.
                    syscalls::SYS_fork | syscalls::SYS_vfork => Err(nix::libc::ENOTSUP),
                    _ => read_exec_args(vma, args[0], args[1], args[2])
                        .map_or(Err(nix::libc::EFAULT), |(path, argv, envp)| {
                            ExecRequest::resolve(path, argv, envp)
                        }),
                };
                match request {
                    Ok(request) => return Ok(SyscallResult::exit(ExitKind::Exec(request))),
                    Err(errno) => {
                        ret0 = errno as u64;
                        ret1 = 0;
                        cflags = 1 << 29;
                        handled = true;
                    }
                }
            }
            syscalls::SYS_exit => {
                self.exit_status = Some(args[0] as i32);
                return Ok(SyscallResult::exit(ExitKind::Exit));
            }
            syscalls::SYS_mprotect => {
                ret0 = 0;
                ret1 = 0;
                cflags = 0;
                handled = true;
            }
            syscalls::SYS_mmap => {
                args[2] &= !PROT_EXEC;
                // page align size
                args[1] = Self::align_size(args[1]);
                // fake fixed address
                if args[3] & nix::libc::MAP_FIXED as u64 == 0 {
                    args[3] |= nix::libc::MAP_FIXED as u64;
                    let chosen = self.reserve_fixed_address(args[1], None);
                    trace!("Fixing mmap address to {:x}", chosen);
                    self.release_fixed_map_range(chosen, args[1])?;
                    args[0] = chosen;
                    released_fixed_map_range = Some((chosen, args[1]));
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
                    let chosen = self.reserve_fixed_address(args[2], None);
                    trace!("Fixing mach_vm_allocate address to {:x}", chosen);
                    self.release_fixed_map_range(chosen, args[2])?;
                    self.write_out_address(args[1], chosen);
                    (ret0, ret1, cflags) = forward_syscall(num, &args);
                    if ret0 != KERN_SUCCESS {
                        self.restore_fixed_map_range(chosen, args[2])?;
                    }
                    handled = true;
                }
            }
            syscalls::TRAP_mach_vm_map => {
                // cur_protection
                args[5] &= !PROT_EXEC;
                // TODO: ensure task is ourselves
                // page align size
                args[2] = Self::align_size(args[2]);
                // fake fixed address
                // Check for VM_FLAGS_ANYWHERE being set
                if args[4] & 1 != 0 {
                    args[4] &= !1;
                    let chosen = self.reserve_fixed_address(args[2], Some(args[3]));
                    trace!("Fixing mach_vm_map address to {:x}", chosen);
                    self.release_fixed_map_range(chosen, args[2])?;
                    self.write_out_address(args[1], chosen);
                    (ret0, ret1, cflags) = forward_syscall(num, &args);
                    if ret0 != KERN_SUCCESS {
                        self.restore_fixed_map_range(chosen, args[2])?;
                    }
                    handled = true;
                } else {
                    let addr = unsafe { *(args[1] as *const u64) };
                    if loader.take_guest_malloc_reservation(addr, args[2]) {
                        args[4] |= VM_FLAGS_OVERWRITE as u64;
                    }
                }
            }
            syscalls::TRAP_mach_vm_protect => {
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
                let header = unsafe { &*(args[0] as *const MachMsgHeader) };
                let msgh_id = header.msgh_id as u64;
                let msgh_size = header.msgh_size as usize;
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
                        if msgh_size < std::mem::size_of::<KernelRpcMachVmMapRequest>() {
                            ret0 = KERN_DENIED;
                            ret1 = 0;
                            cflags = 1 << 29;
                            return Ok(SyscallResult::cont(ret0, ret1, cflags));
                        }
                        let req_ptr = args[0] as *mut KernelRpcMachVmMapRequest;
                        let mut req = std::ptr::read_unaligned(req_ptr);
                        // In macOS 14, the above does not work for some reason (returning MACH_SEND_INVALID_REPLY), but only on replay.
                        // To get around this, perform the map ourselves and fake the reply.
                        // TODO: this assumes object == 0.
                        req.size = Self::align_size(req.size);
                        let released_fixed_range = if req.flags & 1 != 0 {
                            Some(req.size)
                        } else {
                            None
                        };
                        if req.flags & 1 != 0 {
                            let chosen = self.reserve_fixed_address(req.size, Some(req.mask));
                            trace!("Fixing kernelrpc_mach_vm_map address to {:x}", chosen);
                            self.release_fixed_map_range(chosen, req.size)?;
                            req.address = chosen;
                        }
                        std::ptr::write_unaligned(req_ptr, req);

                        let address = req.address;
                        if address & (PAGE_ALIGN - 1) != 0 {
                            ret0 = KERN_DENIED;
                            ret1 = 0;
                            cflags = 1 << 29;
                            return Ok(SyscallResult::cont(ret0, ret1, cflags));
                        }
                        // Going through the kernel (rather than e.g. mmap(MAP_FIXED)) preserves
                        // mach_vm_map semantics, notably that a fixed mapping without
                        // VM_FLAGS_OVERWRITE fails instead of clobbering host memory.
                        // max_protection is widened since the guest's mprotect and
                        // mach_vm_protect are no-ops on the host.
                        let mut flags = req.flags;
                        if flags & 1 == 0 && loader.take_guest_malloc_reservation(address, req.size)
                        {
                            flags |= VM_FLAGS_OVERWRITE;
                        }
                        let mut mapped_address = address;
                        let kr = mach_vm_map(
                            nix::libc::mach_task_self(),
                            &mut mapped_address,
                            req.size,
                            req.mask,
                            flags,
                            0,
                            0,
                            0,
                            req.cur_protection & !(PROT_EXEC as i32),
                            nix::libc::PROT_READ | nix::libc::PROT_WRITE,
                            req.inheritance as u32,
                        );
                        let reply_ptr = args[0] as *mut KernelRpcMachVmMapReply;
                        let mut reply = std::ptr::read_unaligned(reply_ptr);
                        reply.head.msgh_bits = 0x1200;
                        reply.head.msgh_size = std::mem::size_of::<KernelRpcMachVmMapReply>() as _;
                        reply.head.msgh_remote_port = 0;
                        reply.head.msgh_id += 100;
                        if kr != KERN_SUCCESS as i32 {
                            if let Some(size) = released_fixed_range {
                                self.restore_fixed_map_range(address, size)?;
                            }
                            // MIG servers reply to failures with a bare mig_reply_error_t.
                            reply.head.msgh_size = std::mem::size_of::<MigReplyError>() as _;
                            reply.ret_code = kr as _;
                            ret0 = KERN_SUCCESS;
                        } else {
                            vma.map_1to1(mapped_address, req.size as _, av::MemPerms::RWX)?;
                            self.record_mapping(mapped_address, req.size as _);
                            reply.ret_code = KERN_SUCCESS as _;
                            reply.address = mapped_address;
                            ret0 = KERN_SUCCESS;
                        }
                        std::ptr::write_unaligned(reply_ptr, reply);
                        handled = true;
                    },
                    8000 => {
                        // task_restartable_ranges_register. Fake return SUCCESS.
                        // Subsystem task_restartable (8000), 0th routine.
                        debug!("Returning KERN_SUCCESS for task_restartable_ranges_register");
                        unsafe {
                            let reply_ptr = args[0] as *mut MigReplyError;
                            let mut reply = std::ptr::read_unaligned(reply_ptr);
                            // Incoming msgh_bits is 0x1513.
                            // On a real system, reply is 0x1200.
                            // idk, maybe the remote bits (0x13=MACH_MSG_TYPE_COPY_SEND) gets reduced to
                            // MACH_MSG_TYPE_PORT_SEND (0x12)?
                            reply.hdr.msgh_bits = 0x1200;
                            reply.hdr.msgh_size = std::mem::size_of::<MigReplyError>() as _;
                            reply.hdr.msgh_remote_port = 0;
                            reply.hdr.msgh_reserved = 0;
                            reply.hdr.msgh_id += 100;
                            reply.ndr = 0x100000000;
                            reply.ret_code = KERN_SUCCESS as _;
                            std::ptr::write_unaligned(reply_ptr, reply);
                        }
                        ret0 = KERN_SUCCESS;
                        ret1 = 0;
                        cflags = 0;
                        handled = true;
                    }
                    _ => {}
                }
            }
            0x8000_0000 => {
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
            if let Some((addr, size)) = released_fixed_map_range {
                if cflags & (1 << 29) != 0 {
                    self.restore_fixed_map_range(addr, size)?;
                }
            }
        }

        // Stage 2.5: map newly allocated memory into the VM as necessary.
        match num {
            syscalls::SYS_munmap => {
                if cflags & (1 << 29) == 0 {
                    self.unmap_from_vm(vma, loader, args[0], args[1])?;
                }
            }
            syscalls::TRAP_mach_vm_deallocate => {
                if ret0 == KERN_SUCCESS && args[0] == unsafe { nix::libc::mach_task_self() } as u64
                {
                    self.unmap_from_vm(vma, loader, args[1], args[2])?;
                }
            }
            syscalls::SYS_mmap => {
                if cflags & (1 << 29) == 0 {
                    trace!("1:1 map of {:x} {:x} due to mmap", ret0, args[1]);
                    let flags = args[3] as i32;
                    // An unwritten page of a file mapping is the file's page-cache page, shared
                    // with every other mapping of that file. If any process (including us) has
                    // the file mapped executable, e.g. a dylib outside the shared cache, SPTM
                    // types the page XNU_USER_EXEC, and handing it to hv_vm_map panics the kernel.
                    // For private mappings, map lazily so pages get copied before reaching the VM.
                    // Shared file mappings can't be copied without breaking sharing, so an
                    // executable file mapped MAP_SHARED by the guest can still panic.
                    if flags & nix::libc::MAP_ANON == 0 && flags & nix::libc::MAP_PRIVATE != 0 {
                        // Lazy fault-in writes each page to force the copy.
                        let ret = unsafe {
                            nix::libc::mprotect(
                                ret0 as _,
                                args[1] as _,
                                nix::libc::PROT_READ | nix::libc::PROT_WRITE,
                            )
                        };
                        if ret != 0 {
                            return Err(io::Error::last_os_error()).context(format!(
                                "failed to make private file mapping {:#x} writable",
                                ret0
                            ));
                        }
                        vma.map_1to1_lazy(ret0, args[1] as _, av::MemPerms::RWX)?;
                    } else {
                        vma.map_1to1(ret0, args[1] as _, av::MemPerms::RWX)?;
                    }
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
    let mut readable_pages = HashMap::new();
    let mut queue = entry_points
        .iter()
        .filter_map(|&addr| {
            if check_ptr(vma, addr, &mut readable_pages) {
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
                if !check_ptr(vma, addr, &mut readable_pages) {
                    break;
                }
                pages.insert((addr + 7) & !0xfff);
            }
            let maybe_ptr = vma.read_qword(addr).unwrap();
            if !readable_page(vma, maybe_ptr & !0xfff, &mut readable_pages) {
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

fn check_ptr(vma: &VirtMemAllocator, ptr: u64, readable_pages: &mut HashMap<u64, bool>) -> bool {
    readable_page(vma, ptr & !0xfff, readable_pages)
        && readable_page(vma, (ptr + 7) & !0xfff, readable_pages)
}

/// Whether `page` is mapped into the guest and readable on the host. Guest mappings can be
/// inaccessible on the host (e.g. PROT_NONE guard ranges), and reading those through the
/// VirtMemAllocator, which dereferences host memory directly, would crash.
fn readable_page(
    vma: &VirtMemAllocator,
    page: u64,
    readable_pages: &mut HashMap<u64, bool>,
) -> bool {
    *readable_pages
        .entry(page)
        .or_insert_with(|| read_guest(vma, page, &mut [0u8]).is_some())
}

/// Copies guest memory at `addr` into `buf`, translating through the guest's page tables and
/// without risking a fault on the host. `None` if any of it isn't mapped into the guest or isn't
/// readable on the host.
fn read_guest(vma: &VirtMemAllocator, addr: u64, buf: &mut [u8]) -> Option<()> {
    let mut done = 0;
    while done < buf.len() {
        let cur = addr.checked_add(done as u64)?;
        let page_end = (cur | 0xfff).checked_add(1)?;
        let len = ((page_end - cur) as usize).min(buf.len() - done);
        let host_addr = vma.host_addr(cur).ok()?;
        let mut read = 0u64;
        let kr = unsafe {
            mach_vm_read_overwrite(
                nix::libc::mach_task_self(),
                host_addr as u64,
                len as u64,
                buf[done..].as_mut_ptr() as u64,
                &mut read,
            )
        };
        if kr != KERN_SUCCESS as i32 {
            return None;
        }
        done += len;
    }
    Some(())
}

// Same as the kernel's ARG_MAX.
const GUEST_STRINGS_MAX: usize = 1 << 20;

fn read_guest_cstring(vma: &VirtMemAllocator, addr: u64) -> Option<String> {
    let mut bytes = Vec::new();
    let mut cur = addr;
    while bytes.len() < GUEST_STRINGS_MAX {
        let mut chunk = vec![0u8; ((cur | 0xfff) + 1 - cur) as usize];
        read_guest(vma, cur, &mut chunk)?;
        if let Some(nul) = chunk.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..nul]);
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk);
        cur += chunk.len() as u64;
    }
    None
}

/// Reads a NULL-terminated array of C strings like `argv`. A NULL array is empty.
fn read_guest_cstring_array(vma: &VirtMemAllocator, addr: u64) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    if addr == 0 {
        return Some(strings);
    }
    for index in 0..GUEST_STRINGS_MAX / 8 {
        let mut ptr = [0u8; 8];
        read_guest(vma, addr.checked_add(index as u64 * 8)?, &mut ptr)?;
        let ptr = u64::from_le_bytes(ptr);
        if ptr == 0 {
            return Some(strings);
        }
        strings.push(read_guest_cstring(vma, ptr)?);
    }
    None
}

// See bsd/sys/spawn.h, bsd/sys/spawn_internal.h and osfmk/mach/machine.h in xnu.
const POSIX_SPAWN_SETEXEC: i16 = 0x0040;
const CPU_TYPE_ARM64: i32 = 0x0100_000c;
const CPU_TYPE_ANY: i32 = -1;
const EBADARCH: i32 = 86;

/// A guest `posix_spawn()` call, read from guest memory.
pub(crate) struct PosixSpawn {
    pub(crate) request: ExecRequest,
    pub(crate) flags: i16,
    pub(crate) sigdefault: u32,
    pub(crate) sigmask: u32,
    pub(crate) pgroup: i32,
    /// Guest pointer to the `struct _posix_spawn_file_actions`, which is usable as is on the host
    /// since guest memory is mapped 1:1.
    pub(crate) file_actions: Option<u64>,
}

fn read_posix_spawn(vma: &VirtMemAllocator, args: &[u64; 16]) -> Result<PosixSpawn, i32> {
    let (path, argv, envp) =
        read_exec_args(vma, args[1], args[3], args[4]).ok_or(nix::libc::EFAULT)?;
    let read_u64 = |addr: u64| {
        let mut bytes = [0u8; 8];
        read_guest(vma, addr, &mut bytes).map(|_| u64::from_le_bytes(bytes))
    };
    let read_i32 = |addr: u64| {
        let mut bytes = [0u8; 4];
        read_guest(vma, addr, &mut bytes).map(|_| i32::from_le_bytes(bytes))
    };
    // Both action structs start with (alloc, count).
    let action_count = |actions: u64| read_i32(actions + 4).ok_or(nix::libc::EFAULT);

    // struct _posix_spawn_args_desc: (size, pointer) pairs, starting with attributes, file
    // actions and port actions.
    let desc = args[2];
    let mut spawn = PosixSpawn {
        request: ExecRequest { path, argv, envp },
        flags: 0,
        sigdefault: 0,
        sigmask: 0,
        pgroup: 0,
        file_actions: None,
    };
    let mut binprefs = [0i32; 4];
    if desc != 0 {
        let attrs = read_u64(desc + 8).ok_or(nix::libc::EFAULT)?;
        let file_actions = read_u64(desc + 24).ok_or(nix::libc::EFAULT)?;
        let port_actions = read_u64(desc + 40).ok_or(nix::libc::EFAULT)?;
        if port_actions != 0 && action_count(port_actions)? != 0 {
            return Err(nix::libc::ENOTSUP);
        }
        if file_actions != 0 && action_count(file_actions)? != 0 {
            spawn.file_actions = Some(file_actions);
        }
        if attrs != 0 {
            // struct _posix_spawnattr: psa_flags, padding, psa_sigdefault, psa_sigmask,
            // psa_pgroup, psa_binprefs[4].
            let field = |offset: u64| read_i32(attrs + offset).ok_or(nix::libc::EFAULT);
            spawn.flags = field(0)? as i16;
            spawn.sigdefault = field(4)? as u32;
            spawn.sigmask = field(8)? as u32;
            spawn.pgroup = field(12)?;
            for (i, binpref) in binprefs.iter_mut().enumerate() {
                *binpref = field(16 + 4 * i as u64)?;
            }
        }
    }
    let binprefs: Vec<i32> = binprefs.into_iter().take_while(|&p| p != 0).collect();
    if !binprefs.is_empty()
        && !binprefs
            .iter()
            .any(|&p| p == CPU_TYPE_ARM64 || p == CPU_TYPE_ANY)
    {
        return Err(EBADARCH);
    }
    let ExecRequest { path, argv, envp } = spawn.request;
    spawn.request = ExecRequest::resolve(path, argv, envp)?;
    Ok(spawn)
}

fn read_exec_args(
    vma: &VirtMemAllocator,
    path: u64,
    argv: u64,
    envp: u64,
) -> Option<(std::path::PathBuf, Vec<String>, Vec<String>)> {
    Some((
        read_guest_cstring(vma, path)?.into(),
        read_guest_cstring_array(vma, argv)?,
        read_guest_cstring_array(vma, envp)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::VM_TEST_LOCK;
    use crate::vm::VmManager;

    #[test]
    fn align_size_rounds_up_to_guest_page_size() {
        assert_eq!(DefaultTrapHandler::align_size(0), 0);
        assert_eq!(DefaultTrapHandler::align_size(1), PAGE_ALIGN);
        assert_eq!(DefaultTrapHandler::align_size(PAGE_ALIGN), PAGE_ALIGN);
        assert_eq!(
            DefaultTrapHandler::align_size(PAGE_ALIGN + 1),
            PAGE_ALIGN * 2
        );
    }

    #[test]
    fn remove_mapping_handles_partial_unmaps() {
        let mut handler = DefaultTrapHandler::new().unwrap();
        handler.record_mapping(0x1000, 0x4000);
        handler.record_mapping(0x8000, 0x1000);

        handler.remove_mapping(0x2000, 0x1000);
        assert_eq!(
            handler.mappings,
            vec![(0x1000, 0x1000), (0x3000, 0x2000), (0x8000, 0x1000)]
        );

        handler.remove_mapping(0x0, 0x4000);
        assert_eq!(handler.mappings, vec![(0x4000, 0x1000), (0x8000, 0x1000)]);

        handler.remove_mapping(0x4000, 0x5000);
        assert!(handler.mappings.is_empty());
    }

    #[test]
    fn explore_pointers_follows_pointer_chains_across_pages() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut vm = VmManager::new()?;
        let page1 = 0x1000_0000;
        let page2 = 0x1000_1000;
        let page3 = 0x1000_2000;

        for page in [page1, page2, page3] {
            vm.vma.map(page, 0x1000, av::MemPerms::RWX)?;
        }

        vm.vma.write_qword(page1, page2 + 0x20)?;
        vm.vma.write_qword(page1 + 8, 0xdead_beef)?;
        vm.vma.write_qword(page2 + 0x20, page3 + 0x40)?;

        let pages = explore_pointers(&vm.vma, &[page1]);

        assert_eq!(pages, HashSet::from([page1, page2, page3]));
        Ok(())
    }

    #[test]
    fn reads_posix_spawn_arguments() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let region = mmap_fixed_fixed::MemoryMap::new(
            PAGE_ALIGN as usize,
            &[
                mmap_fixed_fixed::MapOption::MapReadable,
                mmap_fixed_fixed::MapOption::MapWritable,
            ],
        )?;
        let mut vm = VmManager::new()?;
        let base = region.data() as u64;
        vm.vma.map_1to1(base, region.len(), av::MemPerms::RWX)?;

        let (path, arg0, arg1, argv, attrs, file_actions, desc) = (
            base,
            base + 0x100,
            base + 0x108,
            base + 0x200,
            base + 0x300,
            base + 0x400,
            base + 0x500,
        );
        vm.vma.write(path, b"/bin/echo\0")?;
        vm.vma.write(arg0, b"echo\0")?;
        vm.vma.write(arg1, b"hi\0")?;
        for (i, ptr) in [arg0, arg1, 0].into_iter().enumerate() {
            vm.vma.write_qword(argv + 8 * i as u64, ptr)?;
        }
        for (i, value) in [0x100, attrs, 0x100, file_actions, 0, 0]
            .into_iter()
            .enumerate()
        {
            vm.vma.write_qword(desc + 8 * i as u64, value)?;
        }
        let args = {
            let mut args = [0u64; 16];
            args[1..5].copy_from_slice(&[path, desc, argv, 0]);
            args
        };
        let set_attrs = |vm: &mut VmManager, flags: u32, binpref: u32| -> Result<()> {
            vm.vma.write_dword(attrs, flags)?;
            vm.vma.write_dword(attrs + 16, binpref)?;
            Ok(())
        };
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;

        set_attrs(&mut vm, POSIX_SPAWN_SETEXEC as u32, CPU_TYPE_ARM64 as u32)?;
        let spawn = read_posix_spawn(&vm.vma, &args).unwrap();
        assert_eq!(spawn.flags, POSIX_SPAWN_SETEXEC);
        assert_eq!(spawn.request.path, std::path::PathBuf::from("/bin/echo"));
        assert_eq!(
            spawn.request.argv,
            vec!["echo".to_string(), "hi".to_string()]
        );
        assert_eq!(spawn.file_actions, None);

        set_attrs(&mut vm, 0, 0)?;
        assert_eq!(read_posix_spawn(&vm.vma, &args).unwrap().flags, 0);

        set_attrs(&mut vm, POSIX_SPAWN_SETEXEC as u32, CPU_TYPE_X86_64)?;
        assert_eq!(read_posix_spawn(&vm.vma, &args).err(), Some(EBADARCH));

        set_attrs(&mut vm, 0, 0)?;
        vm.vma.write_dword(file_actions + 4, 1)?;
        assert_eq!(
            read_posix_spawn(&vm.vma, &args).unwrap().file_actions,
            Some(file_actions)
        );
        Ok(())
    }

    #[test]
    fn explore_pointers_skips_host_inaccessible_pages() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let mut vm = VmManager::new()?;
        let page = 0x1000_0000;
        vm.vma.map(page, 0x1000, av::MemPerms::RWX)?;

        // Like a guest guard range: mapped into the guest, but PROT_NONE on the host.
        let guard = mmap_fixed_fixed::MemoryMap::new(PAGE_ALIGN as usize, &[])?;
        vm.vma
            .map_1to1_lazy(guard.data() as u64, guard.len(), av::MemPerms::RWX)?;
        vm.vma.write_qword(page, guard.data() as u64)?;

        assert_eq!(explore_pointers(&vm.vma, &[page]), HashSet::from([page]));
        Ok(())
    }

    #[test]
    fn explore_pointers_ignores_values_at_the_top_of_the_address_space() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let vm = VmManager::new()?;
        assert!(explore_pointers(&vm.vma, &[u64::MAX, u64::MAX - 0x800]).is_empty());
        Ok(())
    }
}
