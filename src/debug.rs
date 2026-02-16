use crate::hyperpom::applevisor as av;
use crate::vm::VmManager;
use std::convert::TryInto;
use std::fmt::Write as _;

const REG_NAME_WIDTH: usize = 24;

const GENERAL_REGS: &[(&str, av::Reg)] = &[
    ("X0", av::Reg::X0),
    ("X1", av::Reg::X1),
    ("X2", av::Reg::X2),
    ("X3", av::Reg::X3),
    ("X4", av::Reg::X4),
    ("X5", av::Reg::X5),
    ("X6", av::Reg::X6),
    ("X7", av::Reg::X7),
    ("X8", av::Reg::X8),
    ("X9", av::Reg::X9),
    ("X10", av::Reg::X10),
    ("X11", av::Reg::X11),
    ("X12", av::Reg::X12),
    ("X13", av::Reg::X13),
    ("X14", av::Reg::X14),
    ("X15", av::Reg::X15),
    ("X16", av::Reg::X16),
    ("X17", av::Reg::X17),
    ("X18", av::Reg::X18),
    ("X19", av::Reg::X19),
    ("X20", av::Reg::X20),
    ("X21", av::Reg::X21),
    ("X22", av::Reg::X22),
    ("X23", av::Reg::X23),
    ("X24", av::Reg::X24),
    ("X25", av::Reg::X25),
    ("X26", av::Reg::X26),
    ("X27", av::Reg::X27),
    ("X28", av::Reg::X28),
    ("X29/FP", av::Reg::X29),
    ("X30/LR", av::Reg::X30),
    ("PC", av::Reg::PC),
    ("FPCR", av::Reg::FPCR),
    ("FPSR", av::Reg::FPSR),
    ("CPSR", av::Reg::CPSR),
];

const SYS_REGS: &[(&str, av::SysReg)] = &[
    ("MIDR_EL1", av::SysReg::MIDR_EL1),
    ("MPIDR_EL1", av::SysReg::MPIDR_EL1),
    ("ID_AA64PFR0_EL1", av::SysReg::ID_AA64PFR0_EL1),
    ("ID_AA64PFR1_EL1", av::SysReg::ID_AA64PFR1_EL1),
    ("ID_AA64DFR0_EL1", av::SysReg::ID_AA64DFR0_EL1),
    ("ID_AA64DFR1_EL1", av::SysReg::ID_AA64DFR1_EL1),
    ("ID_AA64ISAR0_EL1", av::SysReg::ID_AA64ISAR0_EL1),
    ("ID_AA64ISAR1_EL1", av::SysReg::ID_AA64ISAR1_EL1),
    ("ID_AA64MMFR0_EL1", av::SysReg::ID_AA64MMFR0_EL1),
    ("ID_AA64MMFR1_EL1", av::SysReg::ID_AA64MMFR1_EL1),
    ("ID_AA64MMFR2_EL1", av::SysReg::ID_AA64MMFR2_EL1),
    ("SCTLR_EL1", av::SysReg::SCTLR_EL1),
    ("CPACR_EL1", av::SysReg::CPACR_EL1),
    ("TTBR0_EL1", av::SysReg::TTBR0_EL1),
    ("TTBR1_EL1", av::SysReg::TTBR1_EL1),
    ("TCR_EL1", av::SysReg::TCR_EL1),
    ("SPSR_EL1", av::SysReg::SPSR_EL1),
    ("ELR_EL1", av::SysReg::ELR_EL1),
    ("SP_EL0", av::SysReg::SP_EL0),
    ("AFSR0_EL1", av::SysReg::AFSR0_EL1),
    ("AFSR1_EL1", av::SysReg::AFSR1_EL1),
    ("ESR_EL1", av::SysReg::ESR_EL1),
    ("FAR_EL1", av::SysReg::FAR_EL1),
    ("PAR_EL1", av::SysReg::PAR_EL1),
    ("MAIR_EL1", av::SysReg::MAIR_EL1),
    ("AMAIR_EL1", av::SysReg::AMAIR_EL1),
    ("VBAR_EL1", av::SysReg::VBAR_EL1),
    ("CONTEXTIDR_EL1", av::SysReg::CONTEXTIDR_EL1),
    ("TPIDR_EL1", av::SysReg::TPIDR_EL1),
    ("CNTKCTL_EL1", av::SysReg::CNTKCTL_EL1),
    ("CSSELR_EL1", av::SysReg::CSSELR_EL1),
    ("TPIDR_EL0", av::SysReg::TPIDR_EL0),
    ("TPIDRRO_EL0", av::SysReg::TPIDRRO_EL0),
    ("CNTV_CTL_EL0", av::SysReg::CNTV_CTL_EL0),
    ("CNTV_CVAL_EL0", av::SysReg::CNTV_CVAL_EL0),
    ("SP_EL1", av::SysReg::SP_EL1),
];

pub fn format_vm_state(vm: &VmManager) -> String {
    let vcpu = &vm.vcpu;
    let mut out = String::new();

    out.push_str("== General Registers ==\n");
    for (name, reg) in GENERAL_REGS {
        write_reg_line(&mut out, name, vcpu.get_reg(*reg));
    }

    out.push_str("\n== CPSR Decode ==\n");
    match vcpu.get_reg(av::Reg::CPSR) {
        Ok(cpsr) => append_cpsr_decode(&mut out, cpsr as u32),
        Err(err) => {
            let _ = writeln!(
                out,
                "{:width$} <err: {}>",
                "CPSR",
                err,
                width = REG_NAME_WIDTH
            );
        }
    }

    out.push_str("\n== System Registers ==\n");
    for (name, reg) in SYS_REGS {
        write_reg_line(&mut out, name, vcpu.get_sys_reg(*reg));
    }

    out
}

pub fn unwind_user_stack(vm: &VmManager, max_frames: usize) -> Vec<u64> {
    let mut frames = Vec::new();
    let mut fp = vm.vcpu.get_reg(av::Reg::X29).unwrap_or(0);
    let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap_or(0);
    if pc != 0 {
        frames.push(pc);
    }

    for _ in 0..max_frames {
        if fp == 0 || fp & 0x7 != 0 {
            break;
        }

        let mut buf = [0u8; 16];
        if vm.vma.read(fp, &mut buf).is_err() {
            break;
        }

        let prev_fp = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let lr = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        if lr == 0 {
            break;
        }
        frames.push(lr);
        if prev_fp <= fp {
            break;
        }
        fp = prev_fp;
    }

    frames
}

pub fn format_user_stack(vm: &VmManager, max_frames: usize) -> String {
    let mut out = String::new();
    out.push_str("== User Stack ==\n");
    for (idx, addr) in unwind_user_stack(vm, max_frames).iter().enumerate() {
        let _ = writeln!(out, "{:02} 0x{:016x}", idx, addr);
    }
    out
}

fn write_reg_line(out: &mut String, name: &str, value: av::Result<u64>) {
    match value {
        Ok(val) => {
            let _ = writeln!(
                out,
                "{:width$} 0x{:016x}",
                name,
                val,
                width = REG_NAME_WIDTH
            );
        }
        Err(err) => {
            let _ = writeln!(
                out,
                "{:width$} <err: {}>",
                name,
                err,
                width = REG_NAME_WIDTH
            );
        }
    }
}

fn append_cpsr_decode(out: &mut String, cpsr: u32) {
    let n = (cpsr >> 31) & 1;
    let z = (cpsr >> 30) & 1;
    let c = (cpsr >> 29) & 1;
    let v = (cpsr >> 28) & 1;
    let q = (cpsr >> 27) & 1;
    let ssbs = (cpsr >> 23) & 1;
    let pan = (cpsr >> 22) & 1;
    let dit = (cpsr >> 21) & 1;
    let ge = (cpsr >> 16) & 0x0f;
    let e = (cpsr >> 9) & 1;
    let a = (cpsr >> 8) & 1;
    let i = (cpsr >> 7) & 1;
    let f = (cpsr >> 6) & 1;
    let m = cpsr & 0x0f;

    let _ = writeln!(
        out,
        "{:width$} 0x{:08x}",
        "CPSR",
        cpsr,
        width = REG_NAME_WIDTH
    );
    let _ = writeln!(
        out,
        "{:width$} N={} Z={} C={} V={} Q={}",
        "FLAGS",
        n,
        z,
        c,
        v,
        q,
        width = REG_NAME_WIDTH
    );
    let _ = writeln!(
        out,
        "{:width$} F={} I={} A={} E={}",
        "MASKS",
        f,
        i,
        a,
        e,
        width = REG_NAME_WIDTH
    );
    let _ = writeln!(
        out,
        "{:width$} GE=0x{:x} DIT={} PAN={} SSBS={}",
        "STATE",
        ge,
        dit,
        pan,
        ssbs,
        width = REG_NAME_WIDTH
    );
    let _ = writeln!(out, "{:width$} M=0x{:x}", "MODE", m, width = REG_NAME_WIDTH);
}
