use anyhow::{bail, Result};
use bitfield::bitfield;
use hyperpom::applevisor as av;
use hyperpom::caches::*;
use hyperpom::memory::VirtMemAllocator;
use std::collections::{hash_map::Entry, HashMap};

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum HookType {
    Stage1,
    Stage2,
    Exit,
    Unknown(u16),
}

impl From<u16> for HookType {
    fn from(val: u16) -> Self {
        match val {
            0 => Self::Stage1,
            1 => Self::Stage2,
            0xffff => Self::Exit,
            u => Self::Unknown(u),
        }
    }
}

#[derive(Clone)]
struct Hook {
    insn: [u8; 4],
    next_insn: Option<[u8; 4]>,
    applied: bool,
}

impl Hook {
    fn new() -> Self {
        Self {
            insn: [0; 4],
            next_insn: None,
            applied: false,
        }
    }
}

#[derive(Clone)]
pub struct Hooks {
    hooks: HashMap<u64, Hook>,
}

impl Hooks {
    const BRK_STAGE_1: u32 = 0xd4200000;
    const BRK_STAGE_2: u32 = 0xd4200020;

    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    pub fn add_breakpoint(&mut self, addr: u64, vma: &mut VirtMemAllocator) -> Result<()> {
        if let Entry::Vacant(e) = self.hooks.entry(addr) {
            let mut hook = Hook::new();
            vma.read(addr, &mut hook.insn)?;
            vma.write_dword(addr, Self::BRK_STAGE_1)?;
            hook.applied = true;
            e.insert(hook);
        }
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, addr: u64, vma: &mut VirtMemAllocator) -> Result<()> {
        if let Some(hook) = self.hooks.remove(&addr) {
            if hook.applied {
                vma.write(addr, &hook.insn)?;
            }
        }
        Ok(())
    }

    pub fn handle(&mut self, vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        let exit = vcpu.get_exit_info();
        match HookType::from(exit.exception.syndrome as u16) {
            HookType::Stage1 => self.hook_stage1(vcpu, vma),
            HookType::Stage2 => self.hook_stage2(vcpu, vma),
            HookType::Exit => bail!("Exit hook hit"),
            HookType::Unknown(u) => bail!("Unknown hook type: {}", u),
        }
    }

    fn hook_stage1(&mut self, vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        let addr = vcpu.get_reg(av::Reg::PC)?;
        let hook = self.hooks.get_mut(&addr).unwrap();
        let insn = u32::from_le_bytes(hook.insn);

        let emu_res = Emulator::emulate(insn, vcpu)?;
        match emu_res {
            EmulationResult::BranchRel(offset) => {
                let addr = if offset >= 0 {
                    addr + offset as u64
                } else {
                    (addr as i64 + offset as i64) as u64
                };
                vcpu.set_reg(av::Reg::PC, addr)?;
            }
            EmulationResult::BranchAbs(addr) => vcpu.set_reg(av::Reg::PC, addr)?,
            EmulationResult::Other => {
                let mut next_insn = [0; 4];
                vma.read(addr + 4, &mut next_insn)?;
                hook.next_insn = Some(next_insn);
                vma.write_dword(addr + 4, Self::BRK_STAGE_2)?;
                vma.write(addr, &hook.insn)?;
                vcpu.set_reg(av::Reg::PC, addr)?;
                Caches::ic_ivau(vcpu, vma)?;
            }
        };
        Ok(())
    }

    fn hook_stage2(&mut self, vcpu: &mut av::Vcpu, vma: &mut VirtMemAllocator) -> Result<()> {
        let addr = vcpu.get_reg(av::Reg::PC)?;
        let stage1_addr = addr - 4;
        let hook = self.hooks.get(&stage1_addr).unwrap();
        vma.write(addr, &hook.next_insn.unwrap())?;
        vma.write_dword(stage1_addr, Self::BRK_STAGE_1)?;
        Caches::ic_ivau(vcpu, vma)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------------
// Hooks - ARM Emulator
// -----------------------------------------------------------------------------------------------

bitfield! {
    /// Current Program Status Register
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    struct Cpsr(u32);
    impl Debug;
    get_m, set_m: 3, 0;
    get_f, set_f: 6;
    get_i, set_i: 7;
    get_a, set_a: 8;
    get_e, set_e: 9;
    get_ge, set_ge: 19, 16;
    get_dit, set_dit: 21;
    get_pan, set_pan: 22;
    get_ssbs, set_ssbs: 23;
    get_q, set_q: 27;
    get_v, set_v: 28;
    get_c, set_c: 29;
    get_z, set_z: 30;
    get_n, set_n: 31;
}

/// Returns what type of instruction was disassembled, in order for the hook handler to update
/// the Vcpu registers accordingly (e.g. PC is set directly when `BranchAbs` is returned, while
/// a value is added if `BranchRel` is returned).
#[derive(Debug)]
enum EmulationResult {
    BranchRel(i32),
    BranchAbs(u64),
    Other,
}

/// Empty structure that represents the branch emulator of the fuzzer.
struct Emulator;

impl Emulator {
    /// This function takes an instruction as argument, disassembles it and returns to the hook
    /// handler an [`EmulationResult`].
    #[inline]
    fn emulate(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        match insn {
            // -----------------------------------------------------------------------------------
            // Conditional branch
            // -----------------------------------------------------------------------------------
            // B.cond
            i if (i >> 24) == 0b01010100 => Self::b_cond(i, vcpu),
            // CBNZ
            i if (i >> 24) == 0b10110101 || (i >> 24) == 0b00110101 => Self::cbnz(i, vcpu),
            // CBZ
            i if (i >> 24) == 0b10110100 || (i >> 24) == 0b00110100 => Self::cbz(i, vcpu),
            // TBNZ
            i if (i >> 24) == 0b10110111 || (i >> 24) == 0b00110111 => Self::tbnz(i, vcpu),
            // TBZ
            i if (i >> 24) == 0b10110110 || (i >> 24) == 0b00110110 => Self::tbz(i, vcpu),
            // -----------------------------------------------------------------------------------
            // Unconditional branch (immediate)
            // -----------------------------------------------------------------------------------
            // B
            i if (i >> 26) == 0b000101 => Self::b(i),
            // BL
            i if (i >> 26) == 0b100101 => Self::bl(i, vcpu),
            // BLR
            i if (i >> 10) == 0b1101011000111111000000 && i & 0x1f == 0 => Self::blr(i, vcpu),
            // BR
            i if (i >> 10) == 0b1101011000011111000000 && i & 0x1f == 0 => Self::br(i, vcpu),
            // RET
            i if (i >> 10) == 0b1101011001011111000000 && i & 0x1f == 0 => Self::ret(i, vcpu),
            _ => Ok(EmulationResult::Other),
        }
    }

    /// Evaluates an instruction condition based on CPSR flags.
    #[inline]
    fn evaluate_condition(cond: u32, cpsr: Cpsr) -> bool {
        let ret = match cond >> 1 {
            // EQ or NE
            0b000 => cpsr.get_z(),
            // CS or CC
            0b001 => cpsr.get_c(),
            // MI or PL
            0b010 => cpsr.get_n(),
            // VS or VC
            0b011 => cpsr.get_v(),
            // HI or LS
            0b100 => cpsr.get_c() && !cpsr.get_z(),
            // GE or LT
            0b101 => cpsr.get_n() == cpsr.get_v(),
            // GT or LE
            0b110 => cpsr.get_n() == cpsr.get_v() && !cpsr.get_z(),
            // AL
            0b111 => true,
            _ => unreachable!("invalid instruction condition"),
        };
        if cond & 1 == 1 && cond != 0b1111 {
            !ret
        } else {
            ret
        }
    }

    /// Sign extend a `size`-bit number (stored in a u32) to an i32.
    ///
    /// Taken from [bitutils](https://crates.io/crates/bitutils).
    #[inline]
    fn sign_extend32(data: u32, size: u32) -> i32 {
        assert!(size > 0 && size <= 32);
        ((data << (32 - size)) as i32) >> (32 - size)
    }

    /// Returns the value stored in a register based on an instruction operand value.
    #[inline]
    fn get_operand(vcpu: &av::Vcpu, rd: u32) -> Result<u64> {
        match rd {
            0 => Ok(vcpu.get_reg(av::Reg::X0)?),
            1 => Ok(vcpu.get_reg(av::Reg::X1)?),
            2 => Ok(vcpu.get_reg(av::Reg::X2)?),
            3 => Ok(vcpu.get_reg(av::Reg::X3)?),
            4 => Ok(vcpu.get_reg(av::Reg::X4)?),
            5 => Ok(vcpu.get_reg(av::Reg::X5)?),
            6 => Ok(vcpu.get_reg(av::Reg::X6)?),
            7 => Ok(vcpu.get_reg(av::Reg::X7)?),
            8 => Ok(vcpu.get_reg(av::Reg::X8)?),
            9 => Ok(vcpu.get_reg(av::Reg::X9)?),
            10 => Ok(vcpu.get_reg(av::Reg::X10)?),
            11 => Ok(vcpu.get_reg(av::Reg::X11)?),
            12 => Ok(vcpu.get_reg(av::Reg::X12)?),
            13 => Ok(vcpu.get_reg(av::Reg::X13)?),
            14 => Ok(vcpu.get_reg(av::Reg::X14)?),
            15 => Ok(vcpu.get_reg(av::Reg::X15)?),
            16 => Ok(vcpu.get_reg(av::Reg::X16)?),
            17 => Ok(vcpu.get_reg(av::Reg::X17)?),
            18 => Ok(vcpu.get_reg(av::Reg::X18)?),
            19 => Ok(vcpu.get_reg(av::Reg::X19)?),
            20 => Ok(vcpu.get_reg(av::Reg::X20)?),
            21 => Ok(vcpu.get_reg(av::Reg::X21)?),
            22 => Ok(vcpu.get_reg(av::Reg::X22)?),
            23 => Ok(vcpu.get_reg(av::Reg::X23)?),
            24 => Ok(vcpu.get_reg(av::Reg::X24)?),
            25 => Ok(vcpu.get_reg(av::Reg::X25)?),
            26 => Ok(vcpu.get_reg(av::Reg::X26)?),
            27 => Ok(vcpu.get_reg(av::Reg::X27)?),
            28 => Ok(vcpu.get_reg(av::Reg::X28)?),
            29 => Ok(vcpu.get_reg(av::Reg::X29)?),
            30 => Ok(vcpu.get_reg(av::Reg::LR)?),
            31 => Ok(vcpu.get_reg(av::Reg::PC)?),
            _ => unreachable!("invalid operand"),
        }
    }

    // -------------------------------------------------------------------------------------------
    // Conditional branch
    // -------------------------------------------------------------------------------------------

    /// Emulates a `b.cond` instruction.
    #[inline]
    fn b_cond(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let cpsr = Cpsr(vcpu.get_reg(av::Reg::CPSR)? as u32);
        let cond = insn & 0xf;
        if Self::evaluate_condition(cond, cpsr) {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `cbnz` instruction.
    #[inline]
    fn cbnz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if op != 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `cbz` instruction.
    #[inline]
    fn cbz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if op == 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3ffff, 18) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `tbnz` instruction.
    #[inline]
    fn tbnz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let bit_pos = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f);
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if (op >> bit_pos) & 1 != 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3fff, 14) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    /// Emulates a `tbz` instruction.
    #[inline]
    fn tbz(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn & 0x1f;
        let bit_pos = ((insn >> 31) << 5) | ((insn >> 19) & 0x1f);
        let op = if insn >> 31 == 1 {
            Self::get_operand(vcpu, rd)?
        } else {
            Self::get_operand(vcpu, rd)? as u32 as u64
        };
        if (op >> bit_pos) & 1 == 0 {
            Ok(EmulationResult::BranchRel(
                Self::sign_extend32((insn >> 5) & 0x3fff, 14) * 4,
            ))
        } else {
            Ok(EmulationResult::BranchRel(4))
        }
    }

    // -------------------------------------------------------------------------------------------
    // Unconditional branch
    // -------------------------------------------------------------------------------------------

    /// Emulates a `b` instruction.
    #[inline]
    fn b(insn: u32) -> Result<EmulationResult> {
        Ok(EmulationResult::BranchRel(
            Self::sign_extend32(insn & 0x3ffffff, 26) * 4,
        ))
    }

    /// Emulates a `bl` instruction.
    #[inline]
    fn bl(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        vcpu.set_reg(av::Reg::LR, vcpu.get_reg(av::Reg::PC)? + 4)?;
        Self::b(insn)
    }

    /// Emulates a `br` instruction.
    #[inline]
    fn br(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        let rd = insn >> 5 & 0x1f;
        let target = Self::get_operand(vcpu, rd)?;
        Ok(EmulationResult::BranchAbs(target))
    }

    /// Emulates a `blr` instruction.
    #[inline]
    fn blr(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        vcpu.set_reg(av::Reg::LR, vcpu.get_reg(av::Reg::PC)? + 4)?;
        Self::br(insn, vcpu)
    }

    /// Emulates a `ret` instruction.
    #[inline]
    fn ret(insn: u32, vcpu: &av::Vcpu) -> Result<EmulationResult> {
        Self::br(insn, vcpu)
    }
}
