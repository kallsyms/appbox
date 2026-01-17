//! Minimal exception types and vector table initialization.

use applevisor as av;

use crate::hyperpom::error::Result;
use crate::hyperpom::memory::VirtMemAllocator;

/// Exception vector table address.
pub const EVTABLE_ADDR: u64 = 0xffff_ffff_ffff_0000;

/// Represents the ARMv8 exception classes.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExceptionClass {
    /// Unknown reason.
    Unknown(u64),
    /// Trapped WF* instruction execution.
    WfTrap,
    /// Trapped MCR or MRC access with (coproc==0b1111).
    McrMrcTrap0,
    /// Trapped MCRR or MRRC access with (coproc==0b1111).
    McrrMrrcTrap,
    /// Trapped MCR or MRC access with (coproc==0b1110).
    McrMrcTrap1,
    /// Trapped LDC or STC access.
    LdcStcTrap,
    /// Access to SVE, Advanced SIMD or floating-point functionality trapped by CPACR_EL1.FPEN,
    /// CPTR_EL2.FPEN, CPTR_EL2.TFP, or CPTR_EL3.TFP control.
    SveSimdFpTrap,
    /// Trapped execution of an LD64B, ST64B, ST64BV, or ST64BV0 instruction.
    Ld64St64Trap,
    /// Trapped MRRC access with (coproc==0b1110).
    MrrcTrap,
    /// Branch Target Exception.
    BranchTargetException,
    /// Illegal Execution state.
    IllegalExecutionState,
    /// SVC instruction execution in AArch32 state.
    SvcA32,
    /// SVC instruction execution in AArch64 state.
    SvcA64,
    /// HVC instruction execution in AArch64 state.
    HvcA64,
    /// Trapped MSR, MRS or System instruction execution in AArch64 state.
    MsrMrsSysTrap,
    /// Access to SVE functionality trapped as a result of CPACR_EL1.ZEN, CPTR_EL2.ZEN,
    /// CPTR_EL2.TZ, or CPTR_EL3.EZ.
    SveTrap,
    /// Exception from a Pointer Authentication instruction authentication failure.
    PacAuthFailure,
    /// Instruction Abort from a lower Exception level.
    InsAbortLowerEl,
    /// Instruction Abort taken without a change in Exception level.
    InsAbortCurEl,
    /// PC alignment fault exception.
    PcALignmentFault,
    /// Data Abort from a lower Exception level.
    DataAbortLowerEl,
    /// Data Abort taken without a change in Exception level.
    DataAbortCurEl,
    /// SP alignment fault exception.
    SpALignmentFault,
    /// Trapped floating-point exception taken from AArch32 state.
    FpTrapA32,
    /// Trapped floating-point exception taken from AArch64 state.
    FpTrapA64,
    /// SError interrupt.
    SerrorInterrupt,
    /// Breakpoint exception from a lower Exception level.
    BreakpointLowerEl,
    /// Breakpoint exception taken without a change in Exception level.
    BreakpointCurEl,
    /// Software Step exception from a lower Exception level.
    SoftwareStepLowerEL,
    /// Software Step exception taken without a change in Exception level.
    SoftwareStepCurEL,
    /// Watchpoint exception from a lower Exception level.
    WatchpointLowerEL,
    /// Watchpoint exception taken without a change in Exception level.
    WatchpointCurEL,
    /// BKPT instruction execution in AArch32 state.
    BkptA32,
    /// BRK instruction execution in AArch64 state.
    BrkA64,
}

impl From<u64> for ExceptionClass {
    fn from(val: u64) -> Self {
        match val & 0x3f {
            0b000000 => Self::Unknown(val),
            0b000001 => Self::WfTrap,
            0b000011 => Self::McrMrcTrap0,
            0b000100 => Self::McrrMrrcTrap,
            0b000101 => Self::McrMrcTrap1,
            0b000110 => Self::LdcStcTrap,
            0b000111 => Self::SveSimdFpTrap,
            0b001000 => Self::Ld64St64Trap,
            0b001010 => Self::MrrcTrap,
            0b001100 => Self::BranchTargetException,
            0b001110 => Self::IllegalExecutionState,
            0b010001 => Self::SvcA32,
            0b010101 => Self::SvcA64,
            0b010110 => Self::HvcA64,
            0b011000 => Self::MsrMrsSysTrap,
            0b011001 => Self::SveTrap,
            0b011100 => Self::PacAuthFailure,
            0b100000 => Self::InsAbortLowerEl,
            0b100001 => Self::InsAbortCurEl,
            0b100010 => Self::PcALignmentFault,
            0b100100 => Self::DataAbortLowerEl,
            0b100101 => Self::DataAbortCurEl,
            0b100110 => Self::SpALignmentFault,
            0b101000 => Self::FpTrapA32,
            0b101100 => Self::FpTrapA64,
            0b101111 => Self::SerrorInterrupt,
            0b110000 => Self::BreakpointLowerEl,
            0b110001 => Self::BreakpointCurEl,
            0b110010 => Self::SoftwareStepLowerEL,
            0b110011 => Self::SoftwareStepCurEL,
            0b110100 => Self::WatchpointLowerEL,
            0b110101 => Self::WatchpointCurEL,
            0b111000 => Self::BkptA32,
            0b111100 => Self::BrkA64,
            _ => Self::Unknown(val),
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Exceptions;

impl Exceptions {
    pub fn init(vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        vma.map_privileged(EVTABLE_ADDR, 0x1000, av::MemPerms::RX)?;
        for i in 0..16u16 {
            let insn = hvc_insn(i);
            vma.write_dword(EVTABLE_ADDR + (i as u64 * 0x80), insn)?;
        }
        vcpu.set_sys_reg(av::SysReg::VBAR_EL1, EVTABLE_ADDR)?;
        Ok(())
    }
}

fn hvc_insn(imm: u16) -> u32 {
    0xd4000002u32 | ((imm as u32) << 5)
}
