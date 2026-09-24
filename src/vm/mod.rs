use self::hooks::Hooks;
use crate::hyperpom::applevisor as av;
use crate::hyperpom::caches::Caches;
use crate::hyperpom::error::{Error as HyperpomError, MemoryError};
use crate::hyperpom::exceptions::ExceptionClass;
use crate::hyperpom::memory::{PhysMemAllocator, VirtMemAllocator};
use anyhow::Result;
use mmap_fixed_fixed::MemoryMap;
use std::rc::Rc;
use std::time::Duration;

pub mod hooks;

pub enum VmRunResult {
    Svc,
    Brk,
    /// The timer set with [`VmManager::arm_timer`] (or [`arm_vtimer`]) went off.
    Timer,
    /// The guest reached the address set with [`VmManager::set_hardware_breakpoint`].
    HardwareBreakpoint,
    /// The guest executed the instruction [`VmManager::single_step`] was asked for.
    Step,
    Other(av::VcpuExit),
}

unsafe extern "C" {
    fn thread_selfcounts(kind: i32, buf: *mut u64, size: usize) -> i32;
}

/// Instructions the calling thread has retired, including guest instructions its vCPU ran.
fn thread_instructions() -> u64 {
    // THSC_CPI: { instructions, cycles }. See bsd/sys/resource_private.h in xnu.
    let mut counts = [0u64; 2];
    let ret = unsafe { thread_selfcounts(1, counts.as_mut_ptr(), std::mem::size_of_val(&counts)) };
    assert_eq!(ret, 0, "thread_selfcounts: {}", std::io::Error::last_os_error());
    counts[0]
}

fn mach_ticks(duration: Duration) -> u64 {
    let mut timebase = nix::libc::mach_timebase_info { numer: 0, denom: 0 };
    unsafe { nix::libc::mach_timebase_info(&mut timebase) };
    (duration.as_nanos() * timebase.denom as u128 / timebase.numer as u128) as u64
}

/// Has `vcpu`'s run return [`VmRunResult::Timer`] once `after` has passed. This uses the guest's
/// virtual timer, which macOS guests don't use themselves, so it fires on the vCPU's own core:
/// much more promptly than another thread could interrupt it.
pub fn arm_vtimer(vcpu: &av::Vcpu, after: Duration) -> Result<()> {
    let now = unsafe { nix::libc::mach_absolute_time() } - vcpu.get_vtimer_offset()?;
    vcpu.set_sys_reg(av::SysReg::CNTV_CVAL_EL0, now + mach_ticks(after))?;
    vcpu.set_sys_reg(av::SysReg::CNTV_CTL_EL0, CNTV_CTL_ENABLE)?;
    // Hypervisor.framework masks the timer each time it fires.
    vcpu.set_vtimer_mask(false)?;
    Ok(())
}

pub fn disarm_vtimer(vcpu: &av::Vcpu) -> Result<()> {
    vcpu.set_sys_reg(av::SysReg::CNTV_CTL_EL0, 0)?;
    Ok(())
}

const CNTV_CTL_ENABLE: u64 = 1;

// See the Arm ARM's MDSCR_EL1, DBGBCR<n>_EL1 and SPSR descriptions.
const MDSCR_SS: u64 = 1 << 0;
const MDSCR_MDE: u64 = 1 << 15;
const DBGBCR_EL0_ALL_BYTES: u64 = 1 | (0b10 << 1) | (0xf << 5);
const PSTATE_SS: u64 = 1 << 21;

pub struct VmManager {
    pub vcpu: av::Vcpu,
    pub vma: VirtMemAllocator,
    pub hooks: Hooks,
    pub(crate) mappings: Vec<Rc<MemoryMap>>,
    stopped: bool,
    /// See [`Self::count_instructions`]: the host instructions each run costs on top of the
    /// guest's, once calibrated.
    run_overhead: Option<u64>,
    guest_instructions: u64,
    hardware_breakpoint: Option<u64>,
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
            run_overhead: None,
            guest_instructions: 0,
            hardware_breakpoint: None,
            _vm: vm,
        })
    }

    fn run_once(&mut self) -> Result<()> {
        let Some(overhead) = self.run_overhead else {
            self.vcpu.run()?;
            return Ok(());
        };
        let before = thread_instructions();
        self.vcpu.run()?;
        self.guest_instructions += (thread_instructions() - before).saturating_sub(overhead);
        Ok(())
    }

    /// Starts counting the instructions the guest retires (see [`Self::guest_instructions`]).
    ///
    /// There's no guest PMU, so this uses the host's count of the instructions this (the vCPU's)
    /// thread retires, which includes the guest's. Each run's fixed overhead is calibrated and
    /// subtracted, which leaves the count exact, give or take a few hundred instructions per run
    /// depending on how the run ends, except for host interrupts handled meanwhile, which only
    /// ever inflate it (by thousands of instructions each).
    pub fn count_instructions(&mut self) -> Result<()> {
        const RUNS: usize = 1000;
        let pc = self.vcpu.get_reg(av::Reg::PC)?;
        let cpsr = self.vcpu.get_reg(av::Reg::CPSR)?;
        // Runs a single `hvc` from the exception vectors, at EL1 with everything masked.
        let mut samples = Vec::with_capacity(RUNS);
        for _ in 0..RUNS {
            self.vcpu
                .set_reg(av::Reg::PC, crate::hyperpom::exceptions::EVTABLE_ADDR)?;
            self.vcpu.set_reg(av::Reg::CPSR, 0x3c5)?;
            let before = thread_instructions();
            self.vcpu.run()?;
            samples.push(thread_instructions() - before);
        }
        self.vcpu.set_reg(av::Reg::PC, pc)?;
        self.vcpu.set_reg(av::Reg::CPSR, cpsr)?;
        samples.sort_unstable();
        self.run_overhead = Some(samples[RUNS / 2] - 1);
        Ok(())
    }

    /// The guest instructions retired since [`Self::count_instructions`], as an upper bound (see
    /// there), or 0 if not counting.
    pub fn guest_instructions(&self) -> u64 {
        self.guest_instructions
    }

    /// Has [`Self::run`] return [`VmRunResult::Timer`] once `after` has passed.
    pub fn arm_timer(&mut self, after: Duration) -> Result<()> {
        arm_vtimer(&self.vcpu, after)
    }

    pub fn disarm_timer(&mut self) -> Result<()> {
        disarm_vtimer(&self.vcpu)
    }

    /// Has [`Self::run`] return [`VmRunResult::HardwareBreakpoint`] whenever the guest is about
    /// to execute `addr` at EL0, or stops doing so.
    pub fn set_hardware_breakpoint(&mut self, addr: Option<u64>) -> Result<()> {
        self.hardware_breakpoint = addr;
        self.arm_hardware_breakpoint()
    }

    fn arm_hardware_breakpoint(&mut self) -> Result<()> {
        match self.hardware_breakpoint {
            Some(addr) => {
                self.vcpu.set_sys_reg(av::SysReg::DBGBVR0_EL1, addr)?;
                self.vcpu
                    .set_sys_reg(av::SysReg::DBGBCR0_EL1, DBGBCR_EL0_ALL_BYTES)?;
                self.vcpu.set_sys_reg(av::SysReg::MDSCR_EL1, MDSCR_MDE)?;
            }
            None => {
                self.vcpu.set_sys_reg(av::SysReg::DBGBCR0_EL1, 0)?;
                self.vcpu.set_sys_reg(av::SysReg::MDSCR_EL1, 0)?;
            }
        }
        Ok(())
    }

    /// Has the next [`Self::run`] execute one guest (EL0) instruction and return
    /// [`VmRunResult::Step`], ignoring any hardware breakpoint on it.
    pub fn single_step(&mut self) -> Result<()> {
        self.vcpu.set_sys_reg(av::SysReg::DBGBCR0_EL1, 0)?;
        self.vcpu
            .set_sys_reg(av::SysReg::MDSCR_EL1, MDSCR_MDE | MDSCR_SS)?;
        let cpsr = self.vcpu.get_reg(av::Reg::CPSR)?;
        self.vcpu.set_reg(av::Reg::CPSR, cpsr | PSTATE_SS)?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<VmRunResult> {
        loop {
            self.run_once()?;
            let exit_info = self.vcpu.get_exit_info();
            if exit_info.reason == av::ExitReason::VTIMER_ACTIVATED {
                disarm_vtimer(&self.vcpu)?;
                return Ok(VmRunResult::Timer);
            }
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
                    ExceptionClass::BreakpointLowerEl => {
                        return Ok(VmRunResult::HardwareBreakpoint)
                    }
                    ExceptionClass::SoftwareStepLowerEL => {
                        self.arm_hardware_breakpoint()?;
                        return Ok(VmRunResult::Step);
                    }
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
    const SUBS_X0_1: u32 = 0xf1000400;
    const BNE_BACK_1: u32 = 0x54ffffe1;
    const B_SELF: u32 = 0x14000000;

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

    /// A VM running `code` at EL0.
    fn vm_running(code: &[u32]) -> Result<(VmManager, MemoryMap)> {
        let region = host_map(None, HOST_PAGE)?;
        for (i, insn) in code.iter().enumerate() {
            unsafe { (region.data() as *mut u32).add(i).write(*insn) };
        }
        let mut vm = VmManager::new()?;
        vm.vma
            .map_1to1(region.data() as u64, HOST_PAGE, av::MemPerms::RWX)?;
        vm.vcpu.set_reg(av::Reg::PC, region.data() as u64)?;
        Ok((vm, region))
    }

    #[test]
    fn timer_interrupts_the_guest() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, region) = vm_running(&[B_SELF])?;
        vm.arm_timer(Duration::from_millis(1))?;
        assert!(matches!(vm.run()?, VmRunResult::Timer));
        assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, region.data() as u64);
        Ok(())
    }

    #[test]
    fn counts_guest_instructions() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, _region) = vm_running(&[SUBS_X0_1, BNE_BACK_1, BRK_0])?;
        vm.count_instructions()?;
        vm.vcpu.set_reg(av::Reg::X0, 1_000_000)?;
        assert!(matches!(vm.run()?, VmRunResult::Brk));
        // Exact but for host interrupts, which only add, and a little per-run bias.
        let counted = vm.guest_instructions() as i64;
        assert!((2_000_000 - 500..2_000_000 + 200_000).contains(&counted), "{counted}");
        Ok(())
    }

    #[test]
    fn hardware_breakpoints_and_single_steps() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, region) = vm_running(&[SUBS_X0_1, BNE_BACK_1, BRK_0])?;
        let loop_branch = region.data() as u64 + 4;
        vm.vcpu.set_reg(av::Reg::X0, 10)?;
        vm.set_hardware_breakpoint(Some(loop_branch))?;
        let mut hits = 0;
        loop {
            match vm.run()? {
                VmRunResult::HardwareBreakpoint => {
                    hits += 1;
                    assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, loop_branch);
                    assert_eq!(vm.vcpu.get_reg(av::Reg::X0)?, 10 - hits);
                    vm.single_step()?;
                    assert!(matches!(vm.run()?, VmRunResult::Step));
                }
                VmRunResult::Brk => break,
                _ => panic!("unexpected exit"),
            }
        }
        assert_eq!(hits, 10);
        Ok(())
    }
}
