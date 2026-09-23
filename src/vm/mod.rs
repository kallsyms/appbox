use self::hooks::Hooks;
use crate::hyperpom::applevisor as av;
use crate::hyperpom::caches::Caches;
use crate::hyperpom::error::{Error as HyperpomError, MemoryError};
use crate::hyperpom::exceptions::ExceptionClass;
use crate::hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
use anyhow::Result;
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
    pub vma: VirtMemAllocator,
    pub hooks: Hooks,
    pub(crate) mappings: Vec<Rc<MemoryMap>>,
    stopped: bool,
    // Drop vCPU before VM; VM teardown fails if vCPU is still alive.
    _vm: av::VirtualMachine,
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
            vma,
            hooks,
            mappings: Vec::new(),
            stopped: false,
            _vm: vm,
        })
    }

    pub fn run(&mut self) -> Result<VmRunResult> {
        loop {
            self.vcpu.run()?;
            let exit_info = self.vcpu.get_exit_info();
            if exit_info.reason == av::ExitReason::EXCEPTION {
                match ExceptionClass::from(exit_info.exception.syndrome >> 26) {
                    ExceptionClass::DataAbortLowerEl | ExceptionClass::InsAbortLowerEl
                        if self
                            .vma
                            .fault_in_lazy_1to1(exit_info.exception.physical_address)? =>
                    {
                        continue;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::VM_TEST_LOCK;
    use mmap_fixed_fixed::MapOption;

    const LDR_X1_X2: u32 = 0xf9400041;
    const BRK_0: u32 = 0xd4200000;

    const HOST_PAGE: usize = 0x4000;

    fn host_map(addr: Option<*mut u8>, size: usize) -> Result<MemoryMap> {
        let mut options = vec![MapOption::MapReadable, MapOption::MapWritable];
        if let Some(addr) = addr {
            options.push(MapOption::MapAddr(addr));
        }
        Ok(MemoryMap::new(size, &options)?)
    }

    #[test]
    fn unmap_1to1_then_remap_sees_new_memory() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let code_region = host_map(None, HOST_PAGE)?;
        let code = code_region.data() as *mut u32;
        unsafe {
            code.write(LDR_X1_X2);
            code.add(1).write(BRK_0);
        }
        let data_region = host_map(None, HOST_PAGE)?;
        let data_addr = data_region.data();
        unsafe { (data_addr as *mut u64).write(1) };

        let mut vm = VmManager::new()?;
        vm.vma
            .map_1to1(code as u64, code_region.len(), av::MemPerms::RWX)?;
        vm.vma
            .map_1to1(data_addr as u64, HOST_PAGE, av::MemPerms::RWX)?;
        let cpsr = vm.vcpu.get_reg(av::Reg::CPSR)?;
        let mut run_load = |vm: &mut VmManager| -> Result<VmRunResult> {
            vm.vcpu.set_reg(av::Reg::CPSR, cpsr)?;
            vm.vcpu.set_reg(av::Reg::PC, code as u64)?;
            vm.vcpu.set_reg(av::Reg::X2, data_addr as u64)?;
            vm.run()
        };

        assert!(matches!(run_load(&mut vm)?, VmRunResult::Brk));
        assert_eq!(vm.vcpu.get_reg(av::Reg::X1)?, 1);

        vm.vma.unmap_1to1(data_addr as u64, HOST_PAGE)?;
        drop(data_region);
        assert!(matches!(run_load(&mut vm)?, VmRunResult::Other(_)));

        let new_data_region = host_map(Some(data_addr), HOST_PAGE)?;
        unsafe { (new_data_region.data() as *mut u64).write(2) };
        vm.vma
            .map_1to1(data_addr as u64, HOST_PAGE, av::MemPerms::RWX)?;
        assert!(matches!(run_load(&mut vm)?, VmRunResult::Brk));
        assert_eq!(vm.vcpu.get_reg(av::Reg::X1)?, 2);
        Ok(())
    }

    #[test]
    fn lazy_1to1_fault_in_skips_unmapped_pages() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // One lazy chunk: code in page 0, data in page 2, everything else unmapped (on the host
        // too, so faulting the chunk in would crash if it touched those pages).
        let region = host_map(None, 0x10_0000)?;
        let code = region.data() as *mut u32;
        let data = unsafe { region.data().add(2 * HOST_PAGE) } as *mut u64;
        unsafe {
            code.write(LDR_X1_X2);
            code.add(1).write(BRK_0);
            data.write(0x1234);
        }

        let mut vm = VmManager::new()?;
        vm.vma
            .map_1to1_lazy(region.data() as _, region.len(), av::MemPerms::RWX)?;
        for (start, end) in [(HOST_PAGE, 2 * HOST_PAGE), (3 * HOST_PAGE, region.len())] {
            let addr = unsafe { region.data().add(start) };
            vm.vma.unmap_1to1(addr as u64, end - start)?;
            assert_eq!(unsafe { nix::libc::munmap(addr as _, end - start) }, 0);
        }
        vm.vcpu.set_reg(av::Reg::PC, code as u64)?;
        vm.vcpu.set_reg(av::Reg::X2, data as u64)?;

        assert!(matches!(vm.run()?, VmRunResult::Brk));
        assert_eq!(vm.vcpu.get_reg(av::Reg::X1)?, 0x1234);
        Ok(())
    }

    #[test]
    fn lazy_1to1_mapping_faults_in_on_execute_and_load() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Spans two lazy chunks: code in the first, data in the second.
        let region = MemoryMap::new(0x20_0000, &[MapOption::MapReadable, MapOption::MapWritable])?;
        let code = region.data() as *mut u32;
        let data = unsafe { region.data().add(0x10_0000) } as *mut u64;
        unsafe {
            code.write(LDR_X1_X2);
            code.add(1).write(BRK_0);
            data.write(0x1234_5678_9abc_def0);
        }

        let mut vm = VmManager::new()?;
        vm.vma
            .map_1to1_lazy(region.data() as _, region.len(), av::MemPerms::RWX)?;
        vm.vcpu.set_reg(av::Reg::PC, code as u64)?;
        vm.vcpu.set_reg(av::Reg::X2, data as u64)?;

        assert!(matches!(vm.run()?, VmRunResult::Brk));
        assert_eq!(vm.vcpu.get_reg(av::Reg::X1)?, 0x1234_5678_9abc_def0);
        assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, code as u64 + 4);
        Ok(())
    }
}
