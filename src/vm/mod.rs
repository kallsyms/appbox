use self::hooks::Hooks;
use crate::hyperpom::applevisor as av;
use crate::hyperpom::caches::Caches;
use crate::hyperpom::error::{Error as HyperpomError, MemoryError};
use crate::hyperpom::exceptions::ExceptionClass;
pub use crate::hyperpom::memory::MemoryCheckpoint;
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
    /// The guest is about to access `addr`, watched with [`VmManager::set_hardware_watchpoint`].
    /// The access hasn't happened: stepping over it with [`VmManager::single_step`] completes it.
    Watchpoint {
        addr: u64,
    },
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
    assert_eq!(
        ret,
        0,
        "thread_selfcounts: {}",
        std::io::Error::last_os_error()
    );
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

// See the Arm ARM's MDSCR_EL1, DBGBCR<n>_EL1, DBGWCR<n>_EL1 and SPSR descriptions.
const MDSCR_SS: u64 = 1 << 0;
const MDSCR_MDE: u64 = 1 << 15;
const DBGBCR_EL0_ALL_BYTES: u64 = 1 | (0b10 << 1) | (0xf << 5);
const DBGWCR_EL0: u64 = 1 | (0b10 << 1);
const PSTATE_SS: u64 = 1 << 21;

const DBGWVR: [av::SysReg; 16] = {
    use av::SysReg::*;
    [
        DBGWVR0_EL1,
        DBGWVR1_EL1,
        DBGWVR2_EL1,
        DBGWVR3_EL1,
        DBGWVR4_EL1,
        DBGWVR5_EL1,
        DBGWVR6_EL1,
        DBGWVR7_EL1,
        DBGWVR8_EL1,
        DBGWVR9_EL1,
        DBGWVR10_EL1,
        DBGWVR11_EL1,
        DBGWVR12_EL1,
        DBGWVR13_EL1,
        DBGWVR14_EL1,
        DBGWVR15_EL1,
    ]
};
const DBGWCR: [av::SysReg; 16] = {
    use av::SysReg::*;
    [
        DBGWCR0_EL1,
        DBGWCR1_EL1,
        DBGWCR2_EL1,
        DBGWCR3_EL1,
        DBGWCR4_EL1,
        DBGWCR5_EL1,
        DBGWCR6_EL1,
        DBGWCR7_EL1,
        DBGWCR8_EL1,
        DBGWCR9_EL1,
        DBGWCR10_EL1,
        DBGWCR11_EL1,
        DBGWCR12_EL1,
        DBGWCR13_EL1,
        DBGWCR14_EL1,
        DBGWCR15_EL1,
    ]
};

/// Which accesses a [`Watchpoint`] catches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatchKind {
    Read,
    Write,
    Access,
}

/// A range of guest (EL0) memory to catch accesses to: either at most 8 bytes within an aligned
/// doubleword, or an aligned power of two bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Watchpoint {
    pub addr: u64,
    pub len: u64,
    pub kind: WatchKind,
}

impl Watchpoint {
    /// DBGWVR<n>_EL1 and DBGWCR<n>_EL1 values for it, if the hardware can watch it.
    fn registers(&self) -> Option<(u64, u64)> {
        let lsc = match self.kind {
            WatchKind::Read => 0b01,
            WatchKind::Write => 0b10,
            WatchKind::Access => 0b11,
        } << 3;
        let offset = self.addr & 7;
        if self.len > 0 && offset + self.len <= 8 {
            let bas = ((1u64 << self.len) - 1) << offset;
            return Some((self.addr & !7, DBGWCR_EL0 | lsc | bas << 5));
        }
        if self.len.is_power_of_two() && self.len >= 8 && self.addr % self.len == 0 {
            let mask = self.len.trailing_zeros() as u64;
            if mask <= 31 {
                return Some((self.addr, DBGWCR_EL0 | lsc | 0xff << 5 | mask << 24));
            }
        }
        None
    }
}

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
    watchpoints: Vec<Option<Watchpoint>>,
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
            watchpoints: Vec::new(),
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
        self.arm_debug_registers()
    }

    /// How many hardware watchpoints there are.
    pub fn watchpoint_slots(&self) -> Result<usize> {
        let dfr0 = self.vcpu.get_sys_reg(av::SysReg::ID_AA64DFR0_EL1)?;
        Ok(((dfr0 >> 20 & 0xf) as usize + 1).min(DBGWVR.len()))
    }

    /// Has [`Self::run`] return [`VmRunResult::Watchpoint`] when the guest is about to access
    /// memory `watchpoint` covers, or stops (with `None`) watchpoint `slot`.
    pub fn set_hardware_watchpoint(
        &mut self,
        slot: usize,
        watchpoint: Option<Watchpoint>,
    ) -> Result<()> {
        anyhow::ensure!(slot < self.watchpoint_slots()?, "no watchpoint {slot}");
        if let Some(watchpoint) = watchpoint {
            anyhow::ensure!(
                watchpoint.registers().is_some(),
                "can't watch {watchpoint:x?} with a hardware watchpoint"
            );
        }
        if self.watchpoints.len() <= slot {
            self.watchpoints.resize(slot + 1, None);
        }
        self.watchpoints[slot] = watchpoint;
        self.arm_debug_registers()
    }

    /// The watchpoints set with [`Self::set_hardware_watchpoint`], by slot.
    pub fn hardware_watchpoints(&self) -> &[Option<Watchpoint>] {
        &self.watchpoints
    }

    fn arm_debug_registers(&mut self) -> Result<()> {
        match self.hardware_breakpoint {
            Some(addr) => {
                self.vcpu.set_sys_reg(av::SysReg::DBGBVR0_EL1, addr)?;
                self.vcpu
                    .set_sys_reg(av::SysReg::DBGBCR0_EL1, DBGBCR_EL0_ALL_BYTES)?;
            }
            None => self.vcpu.set_sys_reg(av::SysReg::DBGBCR0_EL1, 0)?,
        }
        for (slot, watchpoint) in self.watchpoints.iter().enumerate() {
            let (wvr, wcr) = watchpoint
                .and_then(|watchpoint| watchpoint.registers())
                .unwrap_or((0, 0));
            self.vcpu.set_sys_reg(DBGWVR[slot], wvr)?;
            self.vcpu.set_sys_reg(DBGWCR[slot], wcr)?;
        }
        let enabled =
            self.hardware_breakpoint.is_some() || self.watchpoints.iter().any(Option::is_some);
        self.vcpu
            .set_sys_reg(av::SysReg::MDSCR_EL1, if enabled { MDSCR_MDE } else { 0 })?;
        Ok(())
    }

    /// Has the next [`Self::run`] execute one guest (EL0) instruction and return
    /// [`VmRunResult::Step`], ignoring hardware breakpoints and watchpoints on it.
    pub fn single_step(&mut self) -> Result<()> {
        self.vcpu.set_sys_reg(av::SysReg::DBGBCR0_EL1, 0)?;
        for slot in 0..self.watchpoints.len() {
            self.vcpu.set_sys_reg(DBGWCR[slot], 0)?;
        }
        self.vcpu
            .set_sys_reg(av::SysReg::MDSCR_EL1, MDSCR_MDE | MDSCR_SS)?;
        let cpsr = self.vcpu.get_reg(av::Reg::CPSR)?;
        self.vcpu.set_reg(av::Reg::CPSR, cpsr | PSTATE_SS)?;
        Ok(())
    }

    /// Records the current state of guest memory, to [`Self::restore_memory`] later; see
    /// [`VirtMemAllocator::checkpoint_memory`].
    pub fn checkpoint_memory(&mut self) -> Result<MemoryCheckpoint> {
        Ok(self.vma.checkpoint_memory()?)
    }

    /// Announces a write to guest memory that won't go through the VM; see
    /// [`VirtMemAllocator::log_host_write`].
    pub fn log_host_write(&mut self, addr: u64, size: usize) {
        self.vma.log_host_write(addr, size)
    }

    /// Puts guest memory back how it was at `checkpoint`, discarding later checkpoints.
    pub fn restore_memory(&mut self, checkpoint: MemoryCheckpoint) -> Result<()> {
        anyhow::ensure!(
            self.vma.restore_memory(checkpoint)?,
            "no memory checkpoint {checkpoint:?}"
        );
        Ok(())
    }

    /// Forgets `checkpoint`, which can't be restored any more (but those around it still can).
    pub fn discard_memory_checkpoint(&mut self, checkpoint: MemoryCheckpoint) -> Result<()> {
        anyhow::ensure!(
            self.vma.discard_memory_checkpoint(checkpoint)?,
            "no memory checkpoint {checkpoint:?}"
        );
        Ok(())
    }

    /// The memory checkpoints' saved pages' total size.
    pub fn checkpointed_bytes(&self) -> usize {
        self.vma.checkpointed_bytes()
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
                    ExceptionClass::DataAbortLowerEl
                        if self.vma.handle_checkpoint_write_fault(
                            exit_info.exception.physical_address,
                        )? =>
                    {
                        continue;
                    }
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
                        self.arm_debug_registers()?;
                        return Ok(VmRunResult::Step);
                    }
                    ExceptionClass::WatchpointLowerEL => {
                        return Ok(VmRunResult::Watchpoint {
                            addr: exit_info.exception.virtual_address,
                        })
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
    /// Stores x0 at x1, x1 + 16K, ... (x2 host pages), then traps.
    const STORE_PER_PAGE: [u32; 5] = [
        0xf9000020, // str x0, [x1]
        0x91401021, // add x1, x1, #0x4000
        0xf1000442, // subs x2, x2, #1
        0x54ffffa1, // b.ne .-12
        BRK_0,
    ];

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
        assert!(
            (2_000_000 - 500..2_000_000 + 200_000).contains(&counted),
            "{counted}"
        );
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

    /// Runs [`STORE_PER_PAGE`] from its start.
    fn store_per_page(
        vm: &mut VmManager,
        code: u64,
        value: u64,
        data: u64,
        pages: u64,
    ) -> Result<()> {
        vm.vcpu.set_reg(av::Reg::PC, code)?;
        vm.vcpu.set_reg(av::Reg::X0, value)?;
        vm.vcpu.set_reg(av::Reg::X1, data)?;
        vm.vcpu.set_reg(av::Reg::X2, pages)?;
        assert!(matches!(vm.run()?, VmRunResult::Brk));
        Ok(())
    }

    fn first_words(data: &MemoryMap, pages: usize) -> Vec<u64> {
        (0..pages)
            .map(|p| unsafe { (data.data().add(p * HOST_PAGE) as *const u64).read() })
            .collect()
    }

    #[test]
    fn memory_checkpoints_restore_guest_and_host_writes() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, code) = vm_running(&STORE_PER_PAGE)?;
        let code = code.data() as u64;
        let data = host_map(None, 4 * HOST_PAGE)?;
        unsafe { std::ptr::write_bytes(data.data(), 0xaa, data.len()) };
        vm.vma
            .map_1to1(data.data() as u64, data.len(), av::MemPerms::RWX)?;
        let data_addr = data.data() as u64;
        let original = u64::from_ne_bytes([0xaa; 8]);

        let first = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 1, data_addr, 4)?;
        let second = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 2, data_addr, 2)?;
        let last_page = data_addr + 3 * HOST_PAGE as u64;
        vm.log_host_write(last_page, 8);
        unsafe { (last_page as *mut u64).write(3) };
        assert_eq!(first_words(&data, 4), [2, 2, 1, 3]);

        vm.restore_memory(second)?;
        assert_eq!(first_words(&data, 4), [1, 1, 1, 1]);
        // Still tracking writes after restoring.
        store_per_page(&mut vm, code, 4, data_addr, 1)?;
        vm.restore_memory(second)?;
        assert_eq!(first_words(&data, 4), [1, 1, 1, 1]);
        vm.restore_memory(first)?;
        assert_eq!(first_words(&data, 4), [original; 4]);
        Ok(())
    }

    #[test]
    fn discarding_memory_checkpoints_keeps_the_others_restorable() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, code) = vm_running(&STORE_PER_PAGE)?;
        let code = code.data() as u64;
        let data = host_map(None, 2 * HOST_PAGE)?;
        vm.vma
            .map_1to1(data.data() as u64, data.len(), av::MemPerms::RWX)?;
        let data_addr = data.data() as u64;

        let first = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 1, data_addr, 1)?;
        let second = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 2, data_addr, 2)?;
        let third = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 3, data_addr, 2)?;

        vm.discard_memory_checkpoint(second)?;
        vm.restore_memory(third)?;
        assert_eq!(first_words(&data, 2), [2, 2]);
        vm.restore_memory(first)?;
        assert_eq!(first_words(&data, 2), [0, 0]);
        vm.discard_memory_checkpoint(first)?;
        assert_eq!(vm.checkpointed_bytes(), 0);
        // With no checkpoints left, writes aren't tracked.
        store_per_page(&mut vm, code, 4, data_addr, 2)?;
        assert_eq!(vm.checkpointed_bytes(), 0);
        Ok(())
    }

    #[test]
    fn memory_checkpoints_cover_lazily_mapped_pages() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, code) = vm_running(&STORE_PER_PAGE)?;
        let code = code.data() as u64;
        let data = host_map(None, 2 * HOST_PAGE)?;
        vm.vma
            .map_1to1_lazy(data.data() as u64, data.len(), av::MemPerms::RWX)?;
        let data_addr = data.data() as u64;

        // Not yet faulted in when checkpointed.
        let checkpoint = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 5, data_addr, 2)?;
        assert_eq!(first_words(&data, 2), [5, 5]);
        vm.restore_memory(checkpoint)?;
        assert_eq!(first_words(&data, 2), [0, 0]);
        Ok(())
    }

    #[test]
    fn memory_checkpoints_cover_lazy_ranges_faulted_in_piecemeal() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, code) = vm_running(&STORE_PER_PAGE)?;
        let code = code.data() as u64;
        // Three 1MB lazy chunks, each faulted in (so mapped into the VM) separately.
        let data = host_map(None, 0x30_0000)?;
        vm.vma
            .map_1to1_lazy(data.data() as u64, data.len(), av::MemPerms::RWX)?;
        let pages = data.len() / HOST_PAGE;
        let data_addr = data.data() as u64;
        store_per_page(&mut vm, code, 1, data_addr, pages as u64)?;

        let checkpoint = vm.checkpoint_memory()?;
        store_per_page(&mut vm, code, 2, data_addr, pages as u64)?;
        assert_eq!(first_words(&data, pages), vec![2; pages]);
        vm.restore_memory(checkpoint)?;
        assert_eq!(first_words(&data, pages), vec![1; pages]);
        Ok(())
    }

    #[test]
    fn hardware_watchpoints_stop_before_the_access() -> Result<()> {
        let _guard = VM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut vm, code) = vm_running(&STORE_PER_PAGE)?;
        let code = code.data() as u64;
        let data = host_map(None, 4 * HOST_PAGE)?;
        vm.vma
            .map_1to1(data.data() as u64, data.len(), av::MemPerms::RWX)?;
        let data_addr = data.data() as u64;
        assert!(vm.watchpoint_slots()? >= 2);

        let watched = data_addr + 2 * HOST_PAGE as u64;
        vm.set_hardware_watchpoint(
            1,
            Some(Watchpoint {
                addr: watched,
                len: 8,
                kind: WatchKind::Write,
            }),
        )?;
        vm.vcpu.set_reg(av::Reg::PC, code)?;
        vm.vcpu.set_reg(av::Reg::X0, 7)?;
        vm.vcpu.set_reg(av::Reg::X1, data_addr)?;
        vm.vcpu.set_reg(av::Reg::X2, 4)?;
        assert!(matches!(vm.run()?, VmRunResult::Watchpoint { addr } if addr == watched));
        assert_eq!(vm.vcpu.get_reg(av::Reg::PC)?, code);
        assert_eq!(first_words(&data, 4), [7, 7, 0, 0]);

        vm.single_step()?;
        assert!(matches!(vm.run()?, VmRunResult::Step));
        assert_eq!(first_words(&data, 4), [7, 7, 7, 0]);
        assert!(matches!(vm.run()?, VmRunResult::Brk));
        assert_eq!(first_words(&data, 4), [7; 4]);

        vm.set_hardware_watchpoint(1, None)?;
        assert!(vm.hardware_watchpoints().iter().all(Option::is_none));
        Ok(())
    }
}
