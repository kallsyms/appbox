use self::hooks::Hooks;
use anyhow::Result;
use crate::hyperpom::applevisor as av;
use crate::hyperpom::caches::Caches;
use crate::hyperpom::error::{Error as HyperpomError, MemoryError};
use crate::hyperpom::exceptions::ExceptionClass;
use crate::hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
use mmap_fixed_fixed::MemoryMap;
use std::rc::Rc;

pub mod hooks;

pub enum VmRunResult {
    Svc,
    Brk,
    Other(av::VcpuExit),
}

pub struct VmManager {
    pub vcpu: av::Vcpu,
    _vm: av::VirtualMachine,
    pub vma: VirtMemAllocator,
    pub hooks: Hooks,
    pub(crate) mappings: Vec<Rc<MemoryMap>>,
    stopped: bool,
}

impl VmManager {
    pub fn new() -> Result<Self> {
        let vm = av::VirtualMachine::new()?;
        let mut vcpu = av::Vcpu::new()?;
        let pma = PhysMemAllocator::new(0x1000_0000)?;
        let mut vma = VirtMemAllocator::new(pma)?;
        let hooks = Hooks::new();

        vma.init(&mut vcpu, true)?;
        crate::hyperpom::caches::Caches::init(&mut vcpu, &mut vma)?;
        vcpu.set_reg(av::Reg::LR, 0xdeadf000)?;

        Ok(Self {
            vcpu,
            _vm: vm,
            vma,
            hooks,
            mappings: Vec::new(),
            stopped: false,
        })
    }

    pub fn run(&mut self) -> Result<VmRunResult> {
        loop {
            self.vcpu.run()?;
            let exit_info = self.vcpu.get_exit_info();
            if exit_info.reason == av::ExitReason::EXCEPTION {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::DataAbortLowerEl => {
                        if self.handle_dirty_fault()? {
                            continue;
                        }
                    }
                    ExceptionClass::HvcA64 => {
                        let esr = self.vcpu.get_sys_reg(av::SysReg::ESR_EL1)?;
                        match ExceptionClass::from(esr >> 26) {
                            ExceptionClass::DataAbortLowerEl => {
                                if self.handle_dirty_fault()? {
                                    continue;
                                }
                            }
                            _ => {
                                if esr == 0x56000080 {
                                    return Ok(VmRunResult::Svc);
                                }
                            }
                        }
                    }
                    ExceptionClass::BrkA64 => return Ok(VmRunResult::Brk),
                    _ => {}
                }
            }
            return Ok(VmRunResult::Other(exit_info));
        }
    }

    fn handle_dirty_fault(&mut self) -> Result<bool> {
        let far = self.vcpu.get_sys_reg(av::SysReg::FAR_EL1)?;
        match self.vma.page_fault_dirty_state_handler(far) {
            Ok(true) => {
                let elr = self.vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
                self.vcpu.set_reg(av::Reg::PC, elr)?;
                Caches::tlbi_vaae1_on_fault(&mut self.vcpu, &mut self.vma)?;
                Ok(true)
            }
            Err(HyperpomError::Memory(MemoryError::UnallocatedMemoryAccess(_))) => Ok(false),
            Err(HyperpomError::Memory(MemoryError::InvalidAddress(_))) => Ok(false),
            Err(e) => Err(e.into()),
            _ => Ok(false),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        av::Vcpu::stop(&[self.vcpu.get_instance()])?;
        self.stopped = true;
        Ok(())
    }
}

impl Drop for VmManager {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
