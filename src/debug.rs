use crate::hyperpom::applevisor as av;
use crate::vm::VmManager;
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
    ("X29", av::Reg::X29),
    ("X30", av::Reg::X30),
    ("PC", av::Reg::PC),
    ("FPCR", av::Reg::FPCR),
    ("FPSR", av::Reg::FPSR),
    ("CPSR", av::Reg::CPSR),
];

const SYS_REGS: &[(&str, av::SysReg)] = &[
    ("DBGBVR0_EL1", av::SysReg::DBGBVR0_EL1),
    ("DBGBCR0_EL1", av::SysReg::DBGBCR0_EL1),
    ("DBGWVR0_EL1", av::SysReg::DBGWVR0_EL1),
    ("DBGWCR0_EL1", av::SysReg::DBGWCR0_EL1),
    ("DBGBVR1_EL1", av::SysReg::DBGBVR1_EL1),
    ("DBGBCR1_EL1", av::SysReg::DBGBCR1_EL1),
    ("DBGWVR1_EL1", av::SysReg::DBGWVR1_EL1),
    ("DBGWCR1_EL1", av::SysReg::DBGWCR1_EL1),
    ("MDCCINT_EL1", av::SysReg::MDCCINT_EL1),
    ("MDSCR_EL1", av::SysReg::MDSCR_EL1),
    ("DBGBVR2_EL1", av::SysReg::DBGBVR2_EL1),
    ("DBGBCR2_EL1", av::SysReg::DBGBCR2_EL1),
    ("DBGWVR2_EL1", av::SysReg::DBGWVR2_EL1),
    ("DBGWCR2_EL1", av::SysReg::DBGWCR2_EL1),
    ("DBGBVR3_EL1", av::SysReg::DBGBVR3_EL1),
    ("DBGBCR3_EL1", av::SysReg::DBGBCR3_EL1),
    ("DBGWVR3_EL1", av::SysReg::DBGWVR3_EL1),
    ("DBGWCR3_EL1", av::SysReg::DBGWCR3_EL1),
    ("DBGBVR4_EL1", av::SysReg::DBGBVR4_EL1),
    ("DBGBCR4_EL1", av::SysReg::DBGBCR4_EL1),
    ("DBGWVR4_EL1", av::SysReg::DBGWVR4_EL1),
    ("DBGWCR4_EL1", av::SysReg::DBGWCR4_EL1),
    ("DBGBVR5_EL1", av::SysReg::DBGBVR5_EL1),
    ("DBGBCR5_EL1", av::SysReg::DBGBCR5_EL1),
    ("DBGWVR5_EL1", av::SysReg::DBGWVR5_EL1),
    ("DBGWCR5_EL1", av::SysReg::DBGWCR5_EL1),
    ("DBGBVR6_EL1", av::SysReg::DBGBVR6_EL1),
    ("DBGBCR6_EL1", av::SysReg::DBGBCR6_EL1),
    ("DBGWVR6_EL1", av::SysReg::DBGWVR6_EL1),
    ("DBGWCR6_EL1", av::SysReg::DBGWCR6_EL1),
    ("DBGBVR7_EL1", av::SysReg::DBGBVR7_EL1),
    ("DBGBCR7_EL1", av::SysReg::DBGBCR7_EL1),
    ("DBGWVR7_EL1", av::SysReg::DBGWVR7_EL1),
    ("DBGWCR7_EL1", av::SysReg::DBGWCR7_EL1),
    ("DBGBVR8_EL1", av::SysReg::DBGBVR8_EL1),
    ("DBGBCR8_EL1", av::SysReg::DBGBCR8_EL1),
    ("DBGWVR8_EL1", av::SysReg::DBGWVR8_EL1),
    ("DBGWCR8_EL1", av::SysReg::DBGWCR8_EL1),
    ("DBGBVR9_EL1", av::SysReg::DBGBVR9_EL1),
    ("DBGBCR9_EL1", av::SysReg::DBGBCR9_EL1),
    ("DBGWVR9_EL1", av::SysReg::DBGWVR9_EL1),
    ("DBGWCR9_EL1", av::SysReg::DBGWCR9_EL1),
    ("DBGBVR10_EL1", av::SysReg::DBGBVR10_EL1),
    ("DBGBCR10_EL1", av::SysReg::DBGBCR10_EL1),
    ("DBGWVR10_EL1", av::SysReg::DBGWVR10_EL1),
    ("DBGWCR10_EL1", av::SysReg::DBGWCR10_EL1),
    ("DBGBVR11_EL1", av::SysReg::DBGBVR11_EL1),
    ("DBGBCR11_EL1", av::SysReg::DBGBCR11_EL1),
    ("DBGWVR11_EL1", av::SysReg::DBGWVR11_EL1),
    ("DBGWCR11_EL1", av::SysReg::DBGWCR11_EL1),
    ("DBGBVR12_EL1", av::SysReg::DBGBVR12_EL1),
    ("DBGBCR12_EL1", av::SysReg::DBGBCR12_EL1),
    ("DBGWVR12_EL1", av::SysReg::DBGWVR12_EL1),
    ("DBGWCR12_EL1", av::SysReg::DBGWCR12_EL1),
    ("DBGBVR13_EL1", av::SysReg::DBGBVR13_EL1),
    ("DBGBCR13_EL1", av::SysReg::DBGBCR13_EL1),
    ("DBGWVR13_EL1", av::SysReg::DBGWVR13_EL1),
    ("DBGWCR13_EL1", av::SysReg::DBGWCR13_EL1),
    ("DBGBVR14_EL1", av::SysReg::DBGBVR14_EL1),
    ("DBGBCR14_EL1", av::SysReg::DBGBCR14_EL1),
    ("DBGWVR14_EL1", av::SysReg::DBGWVR14_EL1),
    ("DBGWCR14_EL1", av::SysReg::DBGWCR14_EL1),
    ("DBGBVR15_EL1", av::SysReg::DBGBVR15_EL1),
    ("DBGBCR15_EL1", av::SysReg::DBGBCR15_EL1),
    ("DBGWVR15_EL1", av::SysReg::DBGWVR15_EL1),
    ("DBGWCR15_EL1", av::SysReg::DBGWCR15_EL1),
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
    ("APIAKEYLO_EL1", av::SysReg::APIAKEYLO_EL1),
    ("APIAKEYHI_EL1", av::SysReg::APIAKEYHI_EL1),
    ("APIBKEYLO_EL1", av::SysReg::APIBKEYLO_EL1),
    ("APIBKEYHI_EL1", av::SysReg::APIBKEYHI_EL1),
    ("APDAKEYLO_EL1", av::SysReg::APDAKEYLO_EL1),
    ("APDAKEYHI_EL1", av::SysReg::APDAKEYHI_EL1),
    ("APDBKEYLO_EL1", av::SysReg::APDBKEYLO_EL1),
    ("APDBKEYHI_EL1", av::SysReg::APDBKEYHI_EL1),
    ("APGAKEYLO_EL1", av::SysReg::APGAKEYLO_EL1),
    ("APGAKEYHI_EL1", av::SysReg::APGAKEYHI_EL1),
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
    let _ = writeln!(
        out,
        "{:width$} M=0x{:x}",
        "MODE",
        m,
        width = REG_NAME_WIDTH
    );
}
