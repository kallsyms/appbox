use self::hooks::Hooks;
use anyhow::Result;
use hyperpom::applevisor as av;
use hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};

pub mod hooks;

pub struct VmManager {
    _vm: av::VirtualMachine,
    pub vcpu: av::Vcpu,
    pub vma: VirtMemAllocator,
    pub hooks: Hooks,
}

impl VmManager {
    pub fn new() -> Result<Self> {
        let vm = av::VirtualMachine::new()?;
        let vcpu = av::Vcpu::new()?;
        let pma = PhysMemAllocator::new(0x1000_0000)?;
        let vma = VirtMemAllocator::new(pma)?;
        let hooks = Hooks::new();

        Ok(Self {
            _vm: vm,
            vcpu,
            vma,
            hooks,
        })
    }
}
