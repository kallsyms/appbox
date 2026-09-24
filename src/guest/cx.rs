use std::sync::MutexGuard;

use anyhow::Result;

use super::{Registers, ThreadId, Watchpoint};
use crate::applevisor as av;
use crate::checkpoint::Checkpoint;
use crate::hyperpom::memory::VirtMemAllocator;
use crate::loader::Loader;
use crate::runner::GuestThread;
use crate::symbols::Symbolication;
use crate::trap::{DefaultTrapHandler, GuestMemoryChanges};
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
    pub fn memory(&self) -> MutexGuard<'_, VirtMemAllocator> {
        self.vm.vma()
    }

    /// The vCPU it's on, for what this doesn't cover.
    pub fn vcpu(&self) -> &av::Vcpu {
        &self.vm.vcpu
    }

    pub fn loader(&self) -> &Loader {
        self.loader
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

    /// The trap handler the guest's threads share, for what this doesn't cover (e.g. its exit
    /// status so far).
    pub fn handler(&self) -> MutexGuard<'_, DefaultTrapHandler> {
        self.thread.handler()
    }

    /// Memory appbox allocated or wrote on the guest's behalf since last asked, beyond what
    /// syscalls' arguments point to (e.g. workqueue threads' stacks).
    pub fn take_guest_memory_changes(&mut self) -> GuestMemoryChanges {
        self.handler().take_guest_memory_changes()
    }

    /// How many hardware breakpoints there are for [`Self::set_hardware_breakpoint`].
    pub fn hardware_breakpoint_slots(&self) -> Result<usize> {
        Ok(self.vm.breakpoint_slots()? - 1)
    }

    /// Stops the thread with [`super::Stop::Breakpoint`] whenever it's about to execute `addr`
    /// (or stops doing so, with `None`).
    pub fn set_hardware_breakpoint(&mut self, slot: usize, addr: Option<u64>) -> Result<()> {
        self.vm.set_hardware_breakpoint_slot(slot + 1, addr)
    }

    /// The breakpoints set with [`Self::set_hardware_breakpoint`], by slot.
    pub fn hardware_breakpoints(&self) -> Vec<Option<u64>> {
        let breakpoints = self.vm.hardware_breakpoints();
        breakpoints.get(1..).map_or_else(Vec::new, <[_]>::to_vec)
    }

    pub fn hardware_watchpoint_slots(&self) -> Result<usize> {
        self.vm.watchpoint_slots()
    }

    /// Stops the thread with [`super::Stop::Watchpoint`] right after it accesses what
    /// `watchpoint` covers (or stops doing so, with `None`).
    pub fn set_hardware_watchpoint(&mut self, slot: usize, watchpoint: Option<Watchpoint>) -> Result<()> {
        self.vm.set_hardware_watchpoint(slot, watchpoint)
    }

    pub fn hardware_watchpoints(&self) -> Vec<Option<Watchpoint>> {
        self.vm.hardware_watchpoints().to_vec()
    }

    /// Records the guest's state, to [`Self::restore`] later. Only for a time-shared guest with a
    /// single thread (see [`crate::checkpoint`]).
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

    /// Forgets `checkpoint` (see [`DefaultTrapHandler::discard_checkpoint`]).
    pub fn discard_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        let thread = self.thread;
        thread.handler().discard_checkpoint(self.vm, checkpoint)
    }
}
