use std::sync::MutexGuard;

use anyhow::Result;

use super::{
    Checkpoint, GuestMemoryChanges, Memory, Registers, Symbolication, ThreadId, ThreadingModel,
    Watchpoint,
};
use crate::applevisor as av;
use crate::loader::Loader;
use crate::runner::GuestThread;
use crate::trap::DefaultTrapHandler;
use crate::vm::VmManager;

/// Hardware breakpoint slot finding [`super::Slice::At`] targets uses; hooks get the others.
pub(super) const LANDING_SLOT: usize = 0;

/// A guest thread, as [`super::Hooks`] and [`super::Scheduler`] see it: its registers and
/// memory, debugging aids, and checkpoints.
pub struct ThreadCx<'a> {
    pub(super) vm: &'a mut VmManager,
    pub(super) thread: &'a GuestThread,
    pub(super) loader: &'a Loader,
    /// Whether [`Self::restore`] was called, so whatever was under way no longer is.
    pub(super) restored: bool,
}

impl ThreadCx<'_> {
    /// The guest thread (time-shared: the one on the vCPU).
    pub fn thread(&self) -> ThreadId {
        self.thread.current_thread()
    }

    /// Its registers, as it'll resume with them (in a syscall: as it made it).
    pub fn registers(&self) -> Result<Registers> {
        const PSTATE_MODE: u64 = 0xf;
        if self.vm.vcpu.get_reg(av::Reg::CPSR)? & PSTATE_MODE != 0 {
            // In appbox's exception vectors, on the way to a syscall.
            Registers::save_at_syscall(&self.vm.vcpu)
        } else {
            Registers::save(&self.vm.vcpu)
        }
    }

    /// Replaces the registers it resumes with.
    pub fn set_registers(&mut self, registers: &Registers) -> Result<()> {
        registers.restore(&self.vm.vcpu)
    }

    /// Guest memory (the whole guest's).
    pub fn memory(&self) -> Memory<'_> {
        Memory(self.vm.vma())
    }

    /// The vCPU it's on, for what this doesn't cover.
    pub fn vcpu(&self) -> &av::Vcpu {
        &self.vm.vcpu
    }

    pub fn symbolicate(&self, addr: u64) -> Option<Symbolication> {
        self.loader.symbolicate(addr)
    }

    /// Its call stack's return addresses, innermost first (at most `depth`).
    pub fn stack(&self, depth: usize) -> Vec<u64> {
        crate::unwind_user_stack(self.vm, depth)
    }

    /// The instructions the guest has retired on this vCPU, as an upper bound, if counting (see
    /// [`super::GuestBuilder::count_instructions`]).
    pub fn guest_instructions(&self) -> u64 {
        self.vm.guest_instructions()
    }

    /// Whether another thread could run (or might, once events arrive).
    pub fn contended(&self) -> bool {
        self.handler().contended()
    }

    /// How the guest's threads run (which a guest spawned inherits, whatever its embedder asked
    /// for).
    pub fn threading(&self) -> ThreadingModel {
        self.handler().threading()
    }

    fn handler(&self) -> MutexGuard<'_, DefaultTrapHandler> {
        self.thread.handler()
    }

    /// Allocates `size` bytes of guest memory on the guest's behalf, as appbox does for e.g.
    /// thread stacks (see [`Self::take_guest_memory_changes`]).
    pub fn allocate_guest_memory(&mut self, size: u64) -> Result<u64> {
        self.handler().allocate_guest_memory(&mut self.vm.vma(), size)
    }

    /// Memory appbox allocated or wrote on the guest's behalf since last asked, beyond what
    /// syscalls' arguments point to (e.g. workqueue threads' stacks).
    pub fn take_guest_memory_changes(&mut self) -> GuestMemoryChanges {
        self.handler().take_guest_memory_changes()
    }

    /// Stops threads with [`super::Stop::Breakpoint`] whenever they're about to execute `addr`:
    /// with a hardware breakpoint while there are any left, then with a `brk` planted there
    /// (which reads of guest memory don't see). Hardware breakpoints are the thread's own vCPU's,
    /// so in parallel only planted ones stop other threads.
    pub fn add_breakpoint(&mut self, addr: u64) -> Result<()> {
        if self.breakpoints().contains(&addr) {
            return Ok(());
        }
        let hardware = self.vm.hardware_breakpoints();
        let free = (LANDING_SLOT + 1..self.vm.breakpoint_slots()?)
            .find(|&slot| hardware.get(slot).is_none_or(Option::is_none));
        match free {
            Some(slot) => self.vm.set_hardware_breakpoint_slot(slot, Some(addr)),
            None => Ok(self.vm.vma().plant_breakpoint(addr)?),
        }
    }

    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let slot = self.vm.hardware_breakpoints().iter().position(|&b| b == Some(addr));
        if let Some(slot) = slot.filter(|&slot| slot != LANDING_SLOT) {
            return self.vm.set_hardware_breakpoint_slot(slot, None);
        }
        anyhow::ensure!(
            self.vm.vma().remove_breakpoint(addr)?,
            "no breakpoint at {addr:#x}"
        );
        Ok(())
    }

    /// The addresses of the breakpoints added with [`Self::add_breakpoint`].
    pub fn breakpoints(&self) -> Vec<u64> {
        let hardware = self.vm.hardware_breakpoints();
        let hardware = hardware.iter().skip(LANDING_SLOT + 1).flatten().copied();
        hardware.chain(self.vm.vma().planted_breakpoints()).collect()
    }

    /// Stops the thread with [`super::Stop::Watchpoint`] right after it accesses what
    /// `watchpoint` covers, with one of its vCPU's few hardware watchpoints.
    pub fn add_watchpoint(&mut self, watchpoint: Watchpoint) -> Result<()> {
        let watchpoints = self.vm.hardware_watchpoints().to_vec();
        if watchpoints.contains(&Some(watchpoint)) {
            return Ok(());
        }
        let free = (0..self.vm.watchpoint_slots()?)
            .find(|&slot| watchpoints.get(slot).is_none_or(Option::is_none))
            .ok_or_else(|| anyhow::anyhow!("no hardware watchpoints left"))?;
        self.vm.set_hardware_watchpoint(free, Some(watchpoint))
    }

    pub fn remove_watchpoint(&mut self, watchpoint: Watchpoint) -> Result<()> {
        let slot = self.vm.hardware_watchpoints().iter().position(|&w| w == Some(watchpoint));
        let slot = slot.ok_or_else(|| anyhow::anyhow!("no such watchpoint"))?;
        self.vm.set_hardware_watchpoint(slot, None)
    }

    pub fn watchpoints(&self) -> Vec<Watchpoint> {
        self.vm.hardware_watchpoints().iter().flatten().copied().collect()
    }

    /// Records the guest's state, to [`Self::restore`] later. Only for a time-shared guest with a
    /// single thread.
    pub fn checkpoint(&mut self) -> Result<Checkpoint> {
        let thread = self.thread;
        thread.handler().checkpoint(self.vm)
    }

    /// Puts the guest back how it was at `checkpoint`, discarding later checkpoints. Whatever
    /// was under way (e.g. a syscall being handled, or a slice) is abandoned: once the hook
    /// returns, the thread resumes from the checkpoint.
    pub fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        let thread = self.thread;
        thread.handler().restore(self.vm, checkpoint)?;
        self.restored = true;
        Ok(())
    }

    /// Forgets `checkpoint`, which can't be restored any more (but those around it still can).
    pub fn discard_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        let thread = self.thread;
        thread.handler().discard_checkpoint(self.vm, checkpoint)
    }
}
