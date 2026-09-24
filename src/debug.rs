use crate::hyperpom::applevisor as av;
use crate::vm::VmManager;

pub fn unwind_user_stack(vm: &VmManager, max_frames: usize) -> Vec<u64> {
    let mut frames = Vec::new();
    let mut fp = vm.vcpu.get_reg(av::Reg::X29).unwrap_or(0);
    let pc = vm.vcpu.get_reg(av::Reg::PC).unwrap_or(0);
    if pc != 0 {
        frames.push(pc);
    }
    let vbar = vm.vcpu.get_sys_reg(av::SysReg::VBAR_EL1).unwrap_or(0);
    if vbar != 0 && pc >= vbar && pc < vbar + 0x1000 {
        let elr = vm.vcpu.get_sys_reg(av::SysReg::ELR_EL1).unwrap_or(0);
        if elr != 0 {
            frames.push(elr);
        }
        let lr = vm.vcpu.get_reg(av::Reg::X30).unwrap_or(0);
        if lr != 0 {
            frames.push(lr);
        }
    }

    for _ in 0..max_frames {
        if fp == 0 || fp & 0x7 != 0 {
            break;
        }

        let mut buf = [0u8; 16];
        if vm.vma().read(fp, &mut buf).is_err() {
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
