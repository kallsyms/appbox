use self::hooks::Hooks;
use anyhow::Result;
use crate::hyperpom::applevisor as av;
use crate::hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
use mmap_fixed_fixed::MemoryMap;
use std::rc::Rc;

pub mod hooks;

pub struct VmManager {
    _vm: av::VirtualMachine,
    pub vcpu: av::Vcpu,
    pub vma: VirtMemAllocator,
    pub hooks: Hooks,
    pub(crate) mappings: Vec<Rc<MemoryMap>>,
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
            _vm: vm,
            vcpu,
            vma,
            hooks,
            mappings: Vec::new(),
        })
    }
}
