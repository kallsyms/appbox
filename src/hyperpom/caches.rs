//! TLB and instruction cache maintenance, which Hypervisor.framework only lets the guest do.

use applevisor as av;

use crate::hyperpom::error::*;
use crate::hyperpom::memory::*;

/// Where the maintenance routine is mapped (privileged).
pub const ROUTINE_ADDR: u64 = 0xffff_ffff_fffe_0000;

/// `tlbi vmalle1is; dsb ish; ic ialluis; dsb ish; isb; hvc #0`: invalidates every stage-1
/// translation and the instruction caches, of every vCPU (being inner shareable), then exits.
const INVALIDATE_ROUTINE: &[u32] = &[
    0xd508871f, 0xd5033b9f, 0xd508711f, 0xd5033b9f, 0xd5033fdf, 0xd4000002,
];

/// Where [`REWRITE_ROUTINE`] is.
const REWRITE_ADDR: u64 = ROUTINE_ADDR + 0x80;

/// `ldtr x17, [x16]; sttr x17, [x16]; dsb ish; hvc #0`: rewrites the word at `x16` with its own
/// value, as EL0 would (PAN keeps EL1 from plain accesses to EL0's memory), so the stage-2 fault a
/// first write takes happens now.
const REWRITE_ROUTINE: &[u32] = &[0xf8400a11, 0xf8000a11, 0xd5033b9f, 0xd4000002];

pub struct Caches;

impl Caches {
    /// Maps and writes the maintenance routine at [`ROUTINE_ADDR`].
    pub fn init(vma: &mut VirtMemAllocator) -> Result<()> {
        vma.map_privileged(ROUTINE_ADDR, VIRT_PAGE_SIZE, av::MemPerms::RX)?;
        for (addr, routine) in [(ROUTINE_ADDR, INVALIDATE_ROUTINE), (REWRITE_ADDR, REWRITE_ROUTINE)] {
            for (i, insn) in routine.iter().enumerate() {
                vma.write_dword(addr + (i * 4) as u64, *insn)?;
            }
        }
        Ok(())
    }

    /// Rewrites the (8-byte aligned) word at guest virtual address `addr` with its own value, from
    /// `vcpu`, which must be the only one running.
    pub fn rewrite(vcpu: &mut av::Vcpu, addr: u64) -> Result<()> {
        let saved = [vcpu.get_reg(av::Reg::X16)?, vcpu.get_reg(av::Reg::X17)?];
        vcpu.set_reg(av::Reg::X16, addr & !7)?;
        let ran = Self::run_routine(vcpu, REWRITE_ADDR);
        vcpu.set_reg(av::Reg::X16, saved[0])?;
        vcpu.set_reg(av::Reg::X17, saved[1])?;
        ran
    }

    /// Runs the invalidation routine on `vcpu`.
    pub fn invalidate(vcpu: &mut av::Vcpu) -> Result<()> {
        Self::run_routine(vcpu, ROUTINE_ADDR)
    }

    /// Runs the routine at `addr` on `vcpu` at EL1, with interrupts masked, then puts back its pc
    /// and PSTATE.
    fn run_routine(vcpu: &mut av::Vcpu, addr: u64) -> Result<()> {
        let pc = vcpu.get_reg(av::Reg::PC)?;
        let cpsr = vcpu.get_reg(av::Reg::CPSR)?;
        vcpu.set_reg(av::Reg::PC, addr)?;
        vcpu.set_reg(av::Reg::CPSR, 0x3c5)?;
        vcpu.run()?;
        let exit = vcpu.get_exit_info();
        let finished = exit.reason == av::ExitReason::EXCEPTION
            && exit.exception.syndrome >> 26 == 0b010110;
        vcpu.set_reg(av::Reg::PC, pc)?;
        vcpu.set_reg(av::Reg::CPSR, cpsr)?;
        if !finished {
            return Err(Error::Exception(ExceptionError::UnimplementedException(
                exit.exception.syndrome,
            )));
        }
        Ok(())
    }
}
