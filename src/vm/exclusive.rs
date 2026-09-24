//! Exclusive sequences (a load-exclusive, a few instructions, then a store-exclusive) fail when
//! anything clears the exclusive monitor in between, and every VM exit does. Which exits happen
//! differs from run to run (faults for lazy mapping, dirty tracking and checkpoints; timers), so
//! whether a sequence's store succeeds would too, which record/replay can't tolerate. So a guest
//! resuming inside a sequence is rewound to its load-exclusive, as if the exit had come just
//! before it, as long as the sequence is safe to re-execute.

const MAX_SEQUENCE: u64 = 8;

const SP: u32 = 32;
const FLAGS: u32 = 33;

/// The registers an instruction reads and writes, as bitmasks (see [`SP`], [`FLAGS`]).
#[derive(Default)]
struct Effects {
    reads: u64,
    writes: u64,
}

impl Effects {
    fn read(mut self, reg: u32) -> Self {
        self.reads |= 1 << reg;
        self
    }

    fn write(mut self, reg: u32) -> Self {
        self.writes |= 1 << reg;
        self
    }
}

fn rd(insn: u32) -> u32 {
    insn & 0x1f
}

fn rn(insn: u32) -> u32 {
    (insn >> 5) & 0x1f
}

fn rm(insn: u32) -> u32 {
    (insn >> 16) & 0x1f
}

impl Effects {
    /// Register 31 as a general-purpose operand is the zero register, which has no effects.
    fn read_gpr(self, reg: u32) -> Self {
        if reg == 31 {
            self
        } else {
            self.read(reg)
        }
    }

    fn write_gpr(self, reg: u32) -> Self {
        if reg == 31 {
            self
        } else {
            self.write(reg)
        }
    }
}

fn is_load_exclusive(insn: u32) -> bool {
    insn & 0x3fe0_0000 == 0x0840_0000
}

fn is_store_exclusive(insn: u32) -> bool {
    insn & 0x3fe0_0000 == 0x0800_0000
}

/// The effects of the instructions that may come between a load- and store-exclusive, or `None`
/// for anything else (stores, calls, ...), which isn't safe to re-execute.
fn effects(insn: u32) -> Option<Effects> {
    let effects = Effects::default();
    if is_load_exclusive(insn) {
        return Some(effects.read(if rn(insn) == 31 { SP } else { rn(insn) }).write_gpr(rd(insn)));
    }
    // CBZ/CBNZ
    if insn & 0x7e00_0000 == 0x3400_0000 {
        return Some(effects.read_gpr(rd(insn)));
    }
    // B.cond
    if insn & 0xff00_0010 == 0x5400_0000 {
        return Some(effects.read(FLAGS));
    }
    // NOP
    if insn == 0xd503_201f {
        return Some(effects);
    }
    let sets_flags = insn & (1 << 29) != 0;
    // ADD/SUB (immediate), where register 31 is SP except as ADDS/SUBS's destination.
    if insn & 0x1f80_0000 == 0x1100_0000 {
        let source = if rn(insn) == 31 { SP } else { rn(insn) };
        let effects = effects.read(source);
        return Some(match (sets_flags, rd(insn)) {
            (true, rd) => effects.write_gpr(rd).write(FLAGS),
            (false, 31) => effects.write(SP),
            (false, rd) => effects.write(rd),
        });
    }
    // ADD/SUB (shifted register), and logical (shifted register), where only ANDS/BICS set flags.
    let add_sub = insn & 0x1f20_0000 == 0x0b00_0000;
    let logical = insn & 0x1f00_0000 == 0x0a00_0000;
    if add_sub || logical {
        let sets_flags = if logical {
            (insn >> 29) & 3 == 3
        } else {
            sets_flags
        };
        let effects = effects
            .read_gpr(rn(insn))
            .read_gpr(rm(insn))
            .write_gpr(rd(insn));
        return Some(if sets_flags { effects.write(FLAGS) } else { effects });
    }
    // MOVN/MOVZ
    if insn & 0x1f80_0000 == 0x1280_0000 && (insn >> 29) & 3 != 1 && (insn >> 29) & 3 != 3 {
        return Some(effects.write_gpr(rd(insn)));
    }
    None
}

/// If `pc` is inside an exclusive sequence (after its load-exclusive, up to and including its
/// store-exclusive) that's safe to re-execute, returns the load-exclusive's address. `read`
/// fetches the instruction at an address.
pub(crate) fn rewind_target(read: impl Fn(u64) -> Option<u32>, pc: u64) -> Option<u64> {
    let load = (1..=MAX_SEQUENCE).find_map(|back| {
        let addr = pc.checked_sub(4 * back)?;
        let insn = read(addr)?;
        if is_load_exclusive(insn) {
            Some(Some(addr))
        } else if effects(insn).is_some() {
            None
        } else {
            Some(None)
        }
    })??;

    // Re-executing from the load is safe if nothing in the sequence overwrites a value the
    // sequence started with.
    let mut live_in = 0u64;
    let mut written = 0u64;
    for addr in (load..).step_by(4).take(MAX_SEQUENCE as usize + 1) {
        let insn = read(addr)?;
        if is_store_exclusive(insn) {
            return (addr >= pc).then_some(load);
        }
        let effects = effects(insn)?;
        live_in |= effects.reads & !written;
        if effects.writes & live_in != 0 {
            return None;
        }
        written |= effects.writes;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn program(base: u64, insns: &[u32]) -> HashMap<u64, u32> {
        insns
            .iter()
            .enumerate()
            .map(|(i, insn)| (base + 4 * i as u64, *insn))
            .collect()
    }

    fn target(code: &HashMap<u64, u32>, pc: u64) -> Option<u64> {
        rewind_target(|addr| code.get(&addr).copied(), pc)
    }

    #[test]
    fn rewinds_inside_a_compare_and_swap() {
        // ldxr w10, [x9]; cbnz w10, +8; stxr wzr, w0, [x9]; ret
        let code = program(0x1000, &[0x885f7d2a, 0x3500004a, 0x881f7d20, 0xd65f03c0]);
        assert_eq!(target(&code, 0x1000), None);
        assert_eq!(target(&code, 0x1004), Some(0x1000));
        assert_eq!(target(&code, 0x1008), Some(0x1000));
        assert_eq!(target(&code, 0x100c), None);
    }

    #[test]
    fn rewinds_an_increment_of_the_loaded_value() {
        // ldxr x8, [x0]; add x8, x8, #1; stxr w9, x8, [x0]
        let code = program(0x1000, &[0xc85f7c08, 0x91000508, 0xc8097c08]);
        assert_eq!(target(&code, 0x1008), Some(0x1000));
    }

    #[test]
    fn leaves_sequences_that_overwrite_their_inputs() {
        // ldxr x8, [x0]; add x1, x1, #1; stxr w9, x8, [x0]
        let code = program(0x1000, &[0xc85f7c08, 0x91000421, 0xc8097c08]);
        assert_eq!(target(&code, 0x1008), None);
        // ldxr x0, [x0]; stxr w9, x8, [x1]
        let code = program(0x1000, &[0xc85f7c00, 0xc8097c28]);
        assert_eq!(target(&code, 0x1004), None);
    }

    #[test]
    fn leaves_sequences_with_other_instructions() {
        // ldxr x8, [x0]; str x8, [x1]; stxr w9, x8, [x0]
        let code = program(0x1000, &[0xc85f7c08, 0xf9000028, 0xc8097c08]);
        assert_eq!(target(&code, 0x1008), None);
    }
}
