//! Checkpoints of a guest that it can later be restored to, e.g. for going backwards while
//! replaying a recording.
//!
//! A checkpoint covers guest memory (tracked copy-on-write; see
//! [`VmManager::checkpoint_memory`]), the vCPU's registers, and the trap handler's own state. The
//! handler also journals the host resources the guest creates or drops after a checkpoint
//! (mappings and descriptors), so restoring can undo those too.
//!
//! Checkpoints are only supported while the guest runs a single thread and no workqueue, as when
//! warpspeed replays a recording (and drives thread switches itself): other threads' syscalls in
//! flight on the host can't be undone.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{ensure, Context, Result};
use log::debug;

use crate::applevisor as av;
use crate::fds::GuestFds;
use crate::hyperpom::memory::VirtMemAllocator;
use crate::layout::Reservation;
use crate::mach::{
    mach_vm_allocate, mach_vm_deallocate, KERN_SUCCESS, VM_FLAGS_FIXED, VM_FLAGS_OVERWRITE,
};
use crate::threads::Registers;
use crate::trap::{
    read_guest, DefaultTrapHandler, GuestSigaction, PthreadRegistration, FIXED_MAP_BASE,
    FIXED_MAP_SIZE, NSIG,
};
use crate::vm::{MemoryCheckpoint, VmManager};

/// A state of the guest that [`DefaultTrapHandler::restore`] can go back to.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    id: u64,
    memory: MemoryCheckpoint,
    registers: Registers,
}

/// The trap handler's state that a checkpoint restores wholesale.
#[derive(Clone)]
pub(crate) struct HandlerState {
    pub(crate) map_fixed_next: u64,
    pub(crate) mappings: Vec<(u64, usize)>,
    pub(crate) pthread: Option<PthreadRegistration>,
    pub(crate) signals: [GuestSigaction; NSIG],
    pub(crate) exit_status: Option<i32>,
    pub(crate) fds: GuestFds,
    pub(crate) tsd: u64,
}

/// How to undo something the guest did to host resources since a checkpoint.
enum Undo {
    /// It mapped memory here.
    Created {
        addr: u64,
        size: u64,
    },
    /// Memory mapped here (with these contents) went away.
    Removed {
        addr: u64,
        contents: Vec<u8>,
    },
    /// It took the malloc heap reservation.
    ReservationTaken(Reservation),
    FdOpened(i32),
    /// Descriptor `fd` was closed (or replaced); `stash` is a duplicate of what it was.
    FdClosed {
        fd: i32,
        stash: OwnedFd,
        cloexec: bool,
    },
}

/// A checkpoint, and what to undo to get back to it from the next (or now).
pub(crate) struct HandlerInterval {
    id: u64,
    state: HandlerState,
    undo: Vec<Undo>,
}

fn host_page_size() -> u64 {
    0x4000
}

/// The host pages spanning `addr..addr + size`, as a range.
fn host_pages(addr: u64, size: u64) -> (u64, u64) {
    let page = host_page_size();
    let start = addr / page * page;
    (start, addr.saturating_add(size).div_ceil(page) * page)
}

/// Stashed descriptors go at or above this, out of the way of the guest's, whose numbers must
/// stay as they were.
const STASH_FD_MIN: i32 = 4096;

/// Makes room for stashed descriptors above [`STASH_FD_MIN`].
fn raise_fd_limit() -> Result<()> {
    let mut limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_NOFILE, &mut limit) };
    let wanted = (2 * STASH_FD_MIN) as u64;
    if limit.rlim_cur < wanted {
        limit.rlim_cur = wanted.min(limit.rlim_max);
        let ret = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &limit) };
        ensure!(
            ret == 0,
            "raising the descriptor limit: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

impl DefaultTrapHandler {
    pub(crate) fn checkpointing(&self) -> bool {
        !self.checkpoints.is_empty()
    }

    /// Records the guest's state (in `vm` and this handler) to [`Self::restore`] later.
    ///
    /// Host resources the guest uses outside of what appbox tracks aren't covered, e.g. files'
    /// contents, or anything done through another process.
    pub fn checkpoint(&mut self, vm: &mut VmManager) -> Result<Checkpoint> {
        ensure!(
            !self.threads.others_alive() && !self.workq.has_event_sources(),
            "checkpoints need a single-threaded guest without a workqueue"
        );
        if !self.checkpointing() {
            raise_fd_limit()?;
        }
        let memory = vm.checkpoint_memory()?;
        let id = self.next_checkpoint;
        self.next_checkpoint += 1;
        self.checkpoints.push(HandlerInterval {
            id,
            state: self.handler_state(),
            undo: Vec::new(),
        });
        Ok(Checkpoint {
            id,
            memory,
            registers: Registers::save(&vm.vcpu)?,
        })
    }

    /// Puts the guest back how it was at `checkpoint`, discarding later checkpoints.
    pub fn restore(&mut self, vm: &mut VmManager, checkpoint: &Checkpoint) -> Result<()> {
        let index = self.checkpoint_index(checkpoint)?;
        // Breakpoints are in guest memory, but not part of the guest's state.
        let breakpoints = vm.hooks().breakpoints();
        for &addr in &breakpoints {
            vm.hooks().remove_breakpoint(addr, &mut vm.vma())?;
        }

        let mut intervals = self.checkpoints.split_off(index);
        for interval in intervals.iter_mut().rev() {
            for undo in std::mem::take(&mut interval.undo).into_iter().rev() {
                self.undo(vm, undo)?;
            }
        }
        vm.restore_memory(checkpoint.memory)?;
        let target = intervals.swap_remove(0);
        self.restore_handler_state(target.state.clone());
        self.checkpoints.push(target);
        checkpoint.registers.restore(&vm.vcpu)?;

        for addr in breakpoints {
            vm.hooks().add_breakpoint(addr, &mut vm.vma())?;
        }
        debug!("restored checkpoint {}", checkpoint.id);
        Ok(())
    }

    /// Forgets `checkpoint`, which can't be restored any more (but those around it still can).
    pub fn discard_checkpoint(
        &mut self,
        vm: &mut VmManager,
        checkpoint: &Checkpoint,
    ) -> Result<()> {
        let index = self.checkpoint_index(checkpoint)?;
        let interval = self.checkpoints.remove(index);
        // The previous interval now runs on to the next checkpoint. Without one, there's nothing
        // to undo back to.
        if index > 0 {
            self.checkpoints[index - 1].undo.extend(interval.undo);
        }
        vm.discard_memory_checkpoint(checkpoint.memory)
    }

    fn checkpoint_index(&self, checkpoint: &Checkpoint) -> Result<usize> {
        self.checkpoints
            .iter()
            .position(|interval| interval.id == checkpoint.id)
            .context("no such checkpoint (discarded, or after one since restored)")
    }

    fn handler_state(&self) -> HandlerState {
        HandlerState {
            map_fixed_next: self.map_fixed_next,
            mappings: self.mappings.clone(),
            pthread: self.pthread,
            signals: self.signals,
            exit_status: self.exit_status,
            fds: self.fds.clone(),
            tsd: self.threads.tsd(),
        }
    }

    fn restore_handler_state(&mut self, state: HandlerState) {
        self.map_fixed_next = state.map_fixed_next;
        self.mappings = state.mappings;
        self.pthread = state.pthread;
        self.signals = state.signals;
        self.exit_status = state.exit_status;
        self.fds = state.fds;
        self.threads.set_tsd(state.tsd);
    }

    fn undo(&mut self, vm: &mut VmManager, undo: Undo) -> Result<()> {
        let task = unsafe { nix::libc::mach_task_self() };
        match undo {
            Undo::Created { addr, size } => {
                vm.vma().unmap_1to1(addr, size as usize)?;
                unsafe { mach_vm_deallocate(task, addr, size) };
                if addr >= FIXED_MAP_BASE && addr + size <= FIXED_MAP_BASE + FIXED_MAP_SIZE {
                    self.restore_fixed_map_range(addr, size)?;
                }
            }
            Undo::ReservationTaken(reservation) => reservation.give_back()?,
            Undo::Removed { addr, contents } => {
                let size = contents.len() as u64;
                let mut allocated = addr;
                let kr = unsafe {
                    mach_vm_allocate(
                        task,
                        &mut allocated,
                        size,
                        VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    )
                };
                ensure!(
                    kr == KERN_SUCCESS && allocated == addr,
                    "recreating guest memory at {addr:#x}: kern_return_t={kr}"
                );
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        contents.as_ptr(),
                        addr as *mut u8,
                        contents.len(),
                    )
                };
                vm.vma().map_1to1(addr, size as usize, av::MemPerms::RWX)?;
            }
            Undo::FdOpened(fd) => {
                unsafe { nix::libc::close(fd) };
            }
            Undo::FdClosed { fd, stash, cloexec } => {
                let ret = unsafe { nix::libc::dup2(stash.as_raw_fd(), fd) };
                ensure!(
                    ret == fd,
                    "restoring descriptor {fd}: {}",
                    std::io::Error::last_os_error()
                );
                let flags = if cloexec { nix::libc::FD_CLOEXEC } else { 0 };
                unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, flags) };
            }
        }
        Ok(())
    }

    fn journal(&mut self, undo: Undo) {
        if let Some(interval) = self.checkpoints.last_mut() {
            interval.undo.push(undo);
        }
    }

    pub(crate) fn journal_reservation_taken(&mut self, reservation: Reservation) {
        self.journal(Undo::ReservationTaken(reservation));
    }

    /// Journals the guest mapping memory at `addr..addr + size`.
    pub(crate) fn journal_created(&mut self, addr: u64, size: u64) {
        let (addr, end) = host_pages(addr, size);
        self.journal(Undo::Created {
            addr,
            size: end - addr,
        });
    }

    /// Journals guest memory in `addr..addr + size` going away (or being replaced), saving its
    /// contents. Call it before.
    ///
    /// Covers whatever the guest has mapped there, including what appbox mapped for it (e.g. its
    /// images), which the guest can map over.
    pub(crate) fn journal_removing(&mut self, vma: &VirtMemAllocator, addr: u64, size: u64) {
        if !self.checkpointing() {
            return;
        }
        // Like the host, which unmaps whole pages.
        let (addr, end) = host_pages(addr, size);
        let page = host_page_size();
        let pages = vma.one_to_one_host_pages(addr, (end - addr) as usize);
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for page_addr in pages {
            match runs.last_mut() {
                Some((_, run_end)) if *run_end == page_addr => *run_end += page,
                _ => runs.push((page_addr, page_addr + page)),
            }
        }
        for (from, to) in runs {
            let mut contents = vec![0u8; (to - from) as usize];
            // Page by page: some may not be readable on the host (e.g. guard pages).
            for (i, chunk) in contents.chunks_mut(page as usize).enumerate() {
                let _ = read_guest(vma, from + i as u64 * page, chunk);
            }
            self.journal(Undo::Removed {
                addr: from,
                contents,
            });
        }
    }

    /// Journals the guest's descriptor `fd` being closed (or replaced), stashing a duplicate.
    /// Call it before.
    pub(crate) fn journal_closing(&mut self, fd: i32) {
        if !self.checkpointing() || !self.fds.contains_fd(fd) {
            return;
        }
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
        let stash = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, STASH_FD_MIN) };
        if flags < 0 || stash < 0 {
            return;
        }
        self.journal(Undo::FdClosed {
            fd,
            stash: unsafe { OwnedFd::from_raw_fd(stash) },
            cloexec: flags & nix::libc::FD_CLOEXEC != 0,
        });
    }

    /// Journals the guest opening descriptors.
    pub(crate) fn journal_opened(&mut self, fds: Vec<i32>) {
        for fd in fds {
            self.journal(Undo::FdOpened(fd));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperpom::crash::ExitKind;
    use crate::loader::{load_macho, Loader};
    use crate::test_support::VM_TEST_LOCK;
    use crate::trap::{read_syscall_context, write_syscall_result, TrapHandler};
    use crate::vm::VmRunResult;
    use std::path::Path;

    /// Each syscall's number and results.
    type SyscallTrace = Vec<(u64, u64, u64, u64)>;

    /// Runs the guest's next `limit` syscalls, or until it exits.
    fn run_syscalls(
        vm: &mut VmManager,
        handler: &mut DefaultTrapHandler,
        loader: &Loader,
        limit: usize,
    ) -> Result<SyscallTrace> {
        let mut trace = Vec::new();
        while trace.len() < limit {
            let result = vm.run()?;
            let VmRunResult::Svc = result else {
                let (esr, far, elr) = (
                    vm.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?,
                    vm.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?,
                    vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?,
                );
                let exit = match result {
                    VmRunResult::Other(exit) => {
                        format!("{:?} {:#x}", exit.reason, exit.exception.syndrome)
                    }
                    _ => "other".into(),
                };
                anyhow::bail!(
                    "after {} syscalls, guest stopped for something other than a syscall: {exit}, \
                     ESR_EL1 {esr:#x} FAR_EL1 {far:#x} ELR_EL1 {elr:#x}",
                    trace.len()
                );
            };
            let ctx = read_syscall_context(&mut vm.vcpu)?;
            let result = handler.handle_syscall(&ctx, vm, loader)?;
            // On arm64, traps -3 and -4 are mach_absolute_time and mach_continuous_time.
            let is_clock = ctx.num == (-3i64) as u64 || ctx.num == (-4i64) as u64;
            let ret0 = if is_clock { 0 } else { result.ret0 };
            trace.push((ctx.num, ret0, result.ret1, result.cflags));
            if result.exit != ExitKind::Continue {
                break;
            }
            if result.write_back {
                write_syscall_result(
                    &mut vm.vcpu,
                    ctx.elr,
                    result.ret0,
                    result.ret1,
                    result.cflags,
                )?;
            }
        }
        Ok(trace)
    }

    fn memory_dump(vm: &VmManager) -> std::collections::BTreeMap<u64, Vec<u8>> {
        vm.vma()
            .lower_table
            .mapped_one_to_one_host_pages()
            .into_iter()
            .map(|page| {
                let mut contents = vec![0u8; 0x4000];
                // Pages not yet (lazily) mapped into the VM are read from the host directly.
                let mut read = 0u64;
                let kr = unsafe {
                    crate::mach::mach_vm_read_overwrite(
                        nix::libc::mach_task_self(),
                        page,
                        contents.len() as u64,
                        contents.as_mut_ptr() as u64,
                        &mut read,
                    )
                };
                if kr != KERN_SUCCESS {
                    contents.clear();
                }
                (page, contents)
            })
            .collect()
    }

    /// A live guest also changes host state a checkpoint doesn't cover (e.g. mach ports it
    /// allocates), so running it again after restoring needn't repeat exactly. What must hold is
    /// that everything checkpoints do cover is as it was.
    #[test]
    fn restoring_a_checkpoint_restores_memory_mappings_and_descriptors() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut vm = VmManager::new()?;
        let loader = load_macho(
            &mut vm,
            Path::new("/bin/echo"),
            vec!["echo".into(), "checkpointed".into()],
            vec![],
        )?;
        vm.vcpu.set_reg(av::Reg::PC, loader.entry_point)?;
        vm.vcpu
            .set_sys_reg(av::SysReg::SP_EL0, loader.stack_pointer)?;
        let mut handler = DefaultTrapHandler::new()?;

        run_syscalls(&mut vm, &mut handler, &loader, 30).context("before checkpointing")?;
        let checkpoint = handler.checkpoint(&mut vm)?;
        let memory = memory_dump(&vm);
        let mappings = handler.mappings.clone();
        let fds = crate::fds::open_fds();
        let pc = vm.vcpu.get_reg(av::Reg::PC)?;

        // Maps and unmaps memory, opens and closes files...
        let first =
            run_syscalls(&mut vm, &mut handler, &loader, usize::MAX).context("first run")?;
        assert!(first.len() > 100, "{}", first.len());
        assert!(vm.checkpointed_bytes() > 0);
        let created: Vec<(u64, usize)> = handler
            .mappings
            .iter()
            .filter(|mapping| !mappings.contains(mapping))
            .copied()
            .collect();
        assert!(!created.is_empty());

        handler.restore(&mut vm, &checkpoint)?;
        let restored = memory_dump(&vm);
        let differing: Vec<_> = memory
            .iter()
            .filter(|(page, contents)| restored.get(page) != Some(contents))
            .map(|(page, _)| *page)
            .collect();
        assert!(
            differing.is_empty(),
            "{} of {} pages differ: {differing:x?}",
            differing.len(),
            memory.len()
        );
        // (Lazily mapped pages faulted in since stay mapped, with their original contents. And
        // memory mapped over what was there at the checkpoint is back to what was there.)
        let was_mapped = |addr: u64, size: usize| {
            (addr..addr + size as u64)
                .step_by(0x4000)
                .any(|page| memory.contains_key(&page))
        };
        for &(addr, size) in created
            .iter()
            .filter(|&&(addr, size)| !was_mapped(addr, size))
        {
            assert!(
                vm.vma().one_to_one_host_pages(addr, size).is_empty(),
                "{addr:#x}+{size:#x}, mapped since, is still mapped"
            );
        }
        assert_eq!(handler.mappings, mappings);
        assert_eq!(crate::fds::open_fds(), fds);
        assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, pc);

        let second =
            run_syscalls(&mut vm, &mut handler, &loader, usize::MAX).context("after restoring")?;
        assert_eq!(second.last().map(|s| s.0), Some(crate::syscalls::SYS_exit));

        handler.restore(&mut vm, &checkpoint)?;
        handler.discard_checkpoint(&mut vm, &checkpoint)?;
        assert_eq!(vm.checkpointed_bytes(), 0);
        Ok(())
    }
}
