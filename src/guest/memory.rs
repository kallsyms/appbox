use std::collections::HashSet;
use std::sync::MutexGuard;

use anyhow::Result;

use crate::hyperpom::memory::VirtMemAllocator;

/// The guest's memory (all its threads'), from [`super::ThreadCx::memory`]. Other threads can't
/// touch it while this is held.
pub struct Memory<'a>(pub(super) MutexGuard<'a, VirtMemAllocator>);

impl Memory<'_> {
    /// Fills `buf` from guest address `addr`.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read(addr, buf)?;
        Ok(())
    }

    pub fn read_byte(&self, addr: u64) -> Result<u8> {
        Ok(self.0.read_byte(addr)?)
    }

    /// Writes `data` at guest address `addr` (so that checkpoints see it).
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.0.log_host_write(addr, data.len());
        self.0.write(addr, data)?;
        Ok(())
    }

    /// Like [`Self::write`], for code the guest may already have run (e.g. to plant a breakpoint
    /// instruction), which the vCPUs' instruction caches must then forget.
    pub fn write_code(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.0.log_host_write(addr, data.len());
        self.0.write_code(addr, data)?;
        Ok(())
    }

    /// Whether guest address `addr` is mapped.
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.0.host_addr(addr).is_ok()
    }

    /// The pages `pointers` point into, and those that pointers found there point into in turn:
    /// what a syscall given `pointers` as arguments might access.
    pub fn pages_reachable(&self, pointers: &[u64]) -> HashSet<u64> {
        crate::trap::explore_pointers(&self.0, pointers)
    }
}
