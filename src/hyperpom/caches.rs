//! Handles everything related to ARMv8 cache and TLB maintenance.

use applevisor as av;

use crate::hyperpom::error::*;
use crate::hyperpom::memory::*;

/// Size of a cache maintenance handler.
pub const HANDLER_SIZE: usize = 0x80;
/// Total size available to map the handlers.
pub const HANDLERS_MEM_SIZE: usize = 0x1000;
/// Maximum number of handlers.
pub const HANDLERS_COUNT: usize = HANDLERS_MEM_SIZE / HANDLER_SIZE;
/// Cache maintenant handler location in memory.
pub const HANDLERS_ADDR: u64 = 0xffff_ffff_fffe_0000;
/// Handlers stack size.
pub const STACK_SIZE: usize = 0x1000;
/// Handlers stack address.
pub const STACK_ADDR: u64 = 0xffff_ffff_fffe_1000;

const IC_IVAU_HANDLER: &[u32] = &[
    0xd518d080, 0xd2800020, 0xd5184200, 0xf94007e0, 0xd5184000, 0xf94003e0, 0xd5184020,
    0xd50b7520, 0xd5033b9f, 0xd5033fdf, 0xd538d080, 0xd69f03e0,
];

const TLBI_VMALLE1_IC_IALLUIS_HANDLER: &[u32] = &[
    0xd508871f, 0xd5033b9f, 0xd508711f, 0xd5033b9f, 0xd5033fdf, 0xd518d080, 0xd2800020,
    0xd5184200, 0xf94007e0, 0xd5184000, 0xf94003e0, 0xd5184020, 0xd538d080, 0xd69f03e0,
];

const TLBI_VAAE1_ON_FAULT_HANDLER: &[u32] = &[
    0xd518d080, 0xd2800020, 0xd5184200, 0xf94007e0, 0xd5184000, 0xf94003e0, 0xd5184020,
    0xd5386000, 0xd34cfc00, 0xd5033a9f, 0xd5088760, 0xd5033b9f, 0xd5033fdf, 0xd538d080,
    0xd69f03e0,
];

const TLBI_VAAE1_HANDLER: &[u32] = &[
    0xd518d080, 0xd2800020, 0xd5184200, 0xf94007e0, 0xd5184000, 0xf94003e0, 0xd5184020,
    0xf9400be0, 0xd34cfc00, 0xd5033a9f, 0xd5088760, 0xd5033b9f, 0xd538d080, 0xd69f03e0,
];

fn write_handler(vma: &mut VirtMemAllocator, addr: u64, words: &[u32]) -> Result<()> {
    assert!(words.len() * 4 < HANDLER_SIZE);
    for (i, word) in words.iter().enumerate() {
        vma.write_dword(addr + (i * 4) as u64, *word)?;
    }
    Ok(())
}

/// Cache maintenance functions.
///
/// # Role of Cache Maintenance in the Fuzzer
///
/// The fuzzer does a lot of modifications on the virtual address space of fuzzed programs at
/// runtime (e.g. adding breakpoints for hooks) and for these changes to be taken into account,
/// we need to flush caches.
///
/// # Fuzzer Cache Maintenance
///
/// The hypervisor doesn't allow cache maintenance outside of the [`applevisor::Vcpu`], which
/// forces us to create handlers for this purpose in the Vcpu's address space.
///
/// These handlers are found at address [`HANDLERS_ADDR`].
///
/// ```text
/// +---------------+ <--- HANDLERS_ADDR + 0x000
/// |               |
/// |    IC IVAU    |
/// |    handler    |
/// |               |
/// +---------------+ <--- HANDLERS_ADDR + 0x080
/// |               |
/// |  TLBI  VAAE1  |
/// |    handler    |
/// |               |
/// +---------------+ <--- HANDLERS_ADDR + 0x100
/// |               |
/// •               •
/// •               •
/// •               •
/// ```
///
/// In order to keep the number of context-switches between the fuzzer and the hypervisor to a
/// minimum, the handlers are written in such a way that they jump back to where we originally
/// stopped the exectution.
///
/// ```text
///
///           +-----------------+
///           |     NORMAL      |
///           |    EXECUTION    |<-----------------+
///           +--------+--------+                  |
/// EL0                |                           |
/// -------------------|---------------------------|-----------------------
/// EL1                |                           |
///                    v                           |
///           +--------+--------+         +--------+--------+
///           | EXCEPTION  FROM |         |      CACHE      |
///           |    THE GUEST    |         |   MAINTENANCE   |
///           +--------+--------+         +--------+--------+
///                    |                           ^
/// FUZZER             |                           |
/// -------------------|---------------------------|-----------------------
/// HYPERVISOR         |                           |
///                    v                           |
///           +--------+--------+         +--------+--------+
///           |    EXCEPTION    |-------->|   SETUP CACHE   |
///           |    HANDLING     |         |   MAINTENANCE   |
///           +-----------------+         +-----------------+
/// ```
///
/// Before resuming the execution of the Vcpu and entering the cache maintenance handler, we
/// store the address we want to return to, as well as other state registers, on a dedicated stack
/// mapped at address [`STACK_ADDR`]. The handler is entered at EL1, the cache maintenance
/// operation is performed, the original state is loaded and we perform an `eret` instruction to
/// resume the execution at the original exception level.
pub struct Caches;

impl Caches {
    /// Maps and writes the cache maintenance handlers at address [`HANDLERS_ADDR`].
    pub fn init(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        // EL1 stack initialization
        vma.map_privileged(STACK_ADDR, STACK_SIZE, av::MemPerms::RW)?;
        vcpu.set_sys_reg(av::SysReg::SP_EL1, STACK_ADDR)?;
        // Executable page containing the cache maintenance handlers.
        vma.map_privileged(HANDLERS_ADDR, HANDLERS_MEM_SIZE, av::MemPerms::RX)?;
        let handlers = [
            IC_IVAU_HANDLER,
            TLBI_VMALLE1_IC_IALLUIS_HANDLER,
            TLBI_VAAE1_ON_FAULT_HANDLER,
            TLBI_VAAE1_HANDLER,
        ];
        assert!(handlers.len() < HANDLERS_COUNT);
        for (i, handler) in handlers.iter().enumerate() {
            write_handler(vma, HANDLERS_ADDR + (i * HANDLER_SIZE) as u64, handler)?;
        }
        Ok(())
    }

    /// Instruction cache invalidation handler.
    ///
    /// Executes a `IC IVAU` instruction, which invalidates the instruction cache by virtual
    /// address to point of unification.
    #[inline]
    pub fn ic_ivau(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        // Saving the current context so the handler can use it to return from the exception
        // and resume the execution at the right address and exception level.
        vma.write_qword(STACK_ADDR, vcpu.get_reg(av::Reg::PC)?)?;
        vma.write_qword(STACK_ADDR + 8, vcpu.get_reg(av::Reg::CPSR)?)?;
        // Sets CPSR so that we switch the exception level to EL1 and mask exceptions.
        vcpu.set_reg(av::Reg::CPSR, 0x3c4)?;
        // Sets PC to the instruction cache invalidation handler.
        vcpu.set_reg(av::Reg::PC, HANDLERS_ADDR)?;
        Ok(())
    }

    /// Translation Lookaside Buffer invalidation and instruction cache invalidation handler.
    ///
    /// Executes a `TLBI VMALLE1` instruction to invalidate the whole TLB followed by a `IC ALLUIS`
    /// instruction to flush the entire instruction cache.
    #[inline]
    pub fn tlbi_vmalle1_ic_ialluis(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        // Saving the current context so the handler can use it to return from the exception
        // and resume the execution at the right address and exception level.
        vma.write_qword(STACK_ADDR, vcpu.get_reg(av::Reg::PC)?)?;
        vma.write_qword(STACK_ADDR + 8, vcpu.get_reg(av::Reg::CPSR)?)?;
        // Sets CPSR so that we switch the exception level to EL1 and mask exceptions.
        vcpu.set_reg(av::Reg::CPSR, 0x3c4)?;
        // Sets PC to the TLB invalidation handler.
        vcpu.set_reg(av::Reg::PC, HANDLERS_ADDR + HANDLER_SIZE as u64)?;
        Ok(())
    }

    /// Translation Lookaside Buffer entry invalidation handler used during a data abort.
    ///
    /// Executes a `TLBI VAAE1` instruction, which invalidates cached copies of translation table
    /// entries from TLBs.
    #[inline]
    pub fn tlbi_vaae1_on_fault(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        // Saving the current context so the handler can use it to return from the exception
        // and resume the execution at the right address and exception level.
        // We store SPSR_EL1 instead of CPSR, because the data abort that brought us here has
        // already changed the original CPSR.
        vma.write_qword(STACK_ADDR, vcpu.get_reg(av::Reg::PC)?)?;
        vma.write_qword(STACK_ADDR + 8, vcpu.get_sys_reg(av::SysReg::SPSR_EL1)?)?;
        // We should be at EL1 since this handler is only called when a data abort occurs, so
        // we only set PC to the tlb invalidation handler.
        vcpu.set_reg(av::Reg::PC, HANDLERS_ADDR + (HANDLER_SIZE * 2) as u64)?;
        Ok(())
    }

    /// Translation Lookaside Buffer entry invalidation handler.
    ///
    /// Executes a `TLBI VAAE1` instruction, which invalidates cached copies of translation table
    /// entries from TLBs.
    #[inline]
    pub fn tlbi_vaae1(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator, addr: u64) -> Result<()> {
        // Saving the current context so the handler can use it to return from the exception
        // and resume the execution at the right address and exception level.
        vma.write_qword(STACK_ADDR, vcpu.get_reg(av::Reg::PC)?)?;
        vma.write_qword(STACK_ADDR + 8, vcpu.get_reg(av::Reg::CPSR)?)?;
        // Stores the address we want to flush on the stack.
        vma.write_qword(STACK_ADDR + 0x10, addr)?;
        // Sets CPSR so that we switch the exception level to EL1 and mask exceptions.
        vcpu.set_reg(av::Reg::CPSR, 0x3c4)?;
        // Sets PC to the TLB invalidation handler.
        vcpu.set_reg(av::Reg::PC, HANDLERS_ADDR + (HANDLER_SIZE * 3) as u64)?;
        Ok(())
    }
}
