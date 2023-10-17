use log::{debug, error, info, trace, warn};
use mmap_fixed_fixed::{MapOption, MemoryMap};
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;

use hyperpom::applevisor as av;
use hyperpom::core::*;
use hyperpom::corpus::*;
use hyperpom::coverage::*;
use hyperpom::crash::*;
use hyperpom::error::*;
use hyperpom::loader::*;
use hyperpom::memory::*;
use hyperpom::tracer::*;
use hyperpom::utils::*;
use hyperpom::*;
use mach_object::{LoadCommand, MachCommand, MachHeader, OFile, CPU_TYPE_ARM64, MH_EXECUTE};

mod dyld;

// TODO: these could equally be in localdata and avoid the RwLock.
#[derive(Clone, Default)]
pub struct GlobalData {
    // Base address of the shared cache, required to be here in a Data struct so hooks can access it.
    pub shared_cache_base: u64,
}

// Empty local data.
#[derive(Clone, Default)]
pub struct LocalData;

fn pthread_hook(args: &mut hooks::HookArgs<LocalData, GlobalData>) -> Result<ExitKind> {
    debug!("pthread token == 0 hook");
    args.vcpu
        .set_reg(av::Reg::PC, args.vcpu.get_reg(av::Reg::PC).unwrap() + 4)?;
    Ok(ExitKind::Continue)
}

fn objc_restartable_ranges_hook(
    args: &mut hooks::HookArgs<LocalData, GlobalData>,
) -> Result<ExitKind> {
    debug!("objc task_restartable_ranges_register hook");
    args.vcpu.set_reg(
        av::Reg::PC,
        args.gdata.read().unwrap().shared_cache_base + 0x5e570,
    )?;
    Ok(ExitKind::Continue)
}

#[derive(Clone)]
pub struct AppBoxLoader {
    // Path to the executable.
    executable: PathBuf,
    // Arguments to pass to the executable, including argv[0].
    arguments: Vec<String>,
    // Envvars to pass to the executable.
    environment: Vec<String>,

    shared_cache: dyld::SharedCache,

    // Entry point of the executable.
    entry_point: u64,
    // Starting stack pointer.
    stack_pointer: u64,
    // Address of thread local storage.
    tls: u64,
    // Base address of the shared cache.
    shared_cache_base: u64,
}

impl AppBoxLoader {
    pub fn new(executable: &Path, argv: &Vec<String>, envp: &Vec<String>) -> Result<Self> {
        // TODO: parse macho, check for arm64 and error accordingly
        Ok(Self {
            executable: executable.to_path_buf(),
            arguments: argv.clone(),
            environment: envp.clone(),
            shared_cache: dyld::SharedCache::new_system_cache()?,
            entry_point: 0,
            stack_pointer: 0,
            tls: 0,
            shared_cache_base: 0,
        })
    }

    fn map_1to1(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
        mapping: &MemoryMap,
    ) -> Result<()> {
        executor
            .vma
            .map_1to1(mapping.data() as _, mapping.len(), av::MemPerms::RWX)
    }

    fn load_macho(&mut self, executor: &mut Executor<Self, LocalData, GlobalData>) -> Result<()> {
        let executable_file = File::open(self.executable).unwrap();
        let mut executable = Vec::new();
        let size = executable_file.read_to_end(&mut executable).unwrap();

        let mut cur = Cursor::new(&executable[..size]);

        let (mach_header, mach_commands) = match OFile::parse(&mut cur).unwrap() {
            OFile::MachFile { header, commands } => match header {
                MachHeader {
                    cputype: CPU_TYPE_ARM64,
                    filetype: MH_EXECUTE,
                    ..
                } => Ok((header, commands)),
                _ => return Err("not an arm64 executable".to_string()),
            },
            OFile::FatFile { magic, files } => files
                .iter()
                .find_map(|&(arch, file)| match (arch.cputype, file) {
                    (CPU_TYPE_ARM64, OFile::MachFile { header, commands }) => {
                        Some(Ok((header, commands)))
                    }
                    _ => None,
                })
                .unwrap_or(Err("no arm64 slice")),
            _ => Err("not a mach file".to_string()),
        }?;

        for MachCommand(cmd, _cmdsize) in mach_commands {
            match cmd {
                LoadCommand::Segment64 {
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    ..
                } => {
                    let maxprot = convert_prot(maxprot);
                    let initprot = convert_prot(initprot);
                    let useprot = if initprot.intersects(nix::sys::mman::ProtFlags::PROT_EXEC) {
                        maxprot
                    } else {
                        initprot
                    };

                    if vmaddr == 0 {
                        continue;
                    }
                    if filesize < vmsize {}

                    if filesize > 0 {
                        debug!("mapping {} bytes at 0x{:x}", filesize, vmaddr);
                        unsafe {
                            nix::sys::mman::mmap(
                                std::num::NonZeroUsize::new(vmaddr),
                                std::num::NonZeroUsize::new_unchecked(filesize),
                                useprot,
                                nix::sys::mman::MapFlags::MAP_PRIVATE
                                    | nix::sys::mman::MapFlags::MAP_FIXED,
                                executable_file.as_raw_fd(),
                                fileoff as i64, // TODO: plus fat offset
                            )
                            .unwrap();
                        };
                        regions.push((vmaddr, filesize, useprot));
                    }
                }
                LoadCommand::UnixThread { state, .. } => {
                    if let mach_object::ThreadState::Arm64 { __pc, .. } = state {
                        self.entry_point = __pc;
                    } else {
                        return Err("LC_UNIX_THREAD not arm64".to_string());
                    }
                }
                LoadCommand::LoadDyLinker(path) => {
                    // dyld is in the shared cache, nothing to do here.
                    // TODO: is this correct?
                    dbg!(path);
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn setup_stack(&mut self, executor: &mut Executor<Self, LocalData, GlobalData>) -> Result<()> {
        // MOXiI: Vol 1, Listing 7-1
        /*
         * C runtime startup for interface to the dynamic linker.
         * This is the same as the entry point in crt0.o with the addition of the
         * address of the mach header passed as the an extra first argument.
         *
         * Kernel sets up stack frame to look like:
         *
         *      | STRING AREA |
         *      +-------------+
         *      |      0      |
         *      +-------------+
         *      |  apple[n]   |
         *      +-------------+
         *             :
         *      +-------------+
         *      |  apple[0]   |
         *      +-------------+
         *      |      0      |
         *      +-------------+
         *      |    env[n]   |
         *      +-------------+
         *             :
         *      +-------------+
         *      |    env[0]   |
         *      +-------------+
         *      |      0      |
         *      +-------------+
         *      | arg[argc-1] |
         *      +-------------+
         *             :
         *      +-------------+
         *      |    arg[0]   |
         *      +-------------+
         *      |     argc    |
         *      +-------------+
         * sp-> |      mh     | address of where the a.out's file offset 0 is in memory
         *      +-------------+
         *
         *      Where arg[i] and env[i] point into the STRING AREA
         */

        // From darling loader:
        // TODO: produce stack_guard, e.g. stack_guard=0xcdd5c48c061b00fd (must contain 00 somewhere!)
        // TODO: produce malloc_entropy, e.g. malloc_entropy=0x9536cc569d9595cf,0x831942e402da316b
        // TODO: produce main_stack?
        let applep = vec![format!(
            "executable_path={}",
            self.executable.to_str().unwrap()
        )];

        let total_len = self.arguments.iter().map(|s| s.len() + 1).sum()
            + self.environment.iter().map(|s| s.len() + 1).sum()
            + applep.iter().map(|s| s.len() + 1).sum();
        let strings = MemoryMap::new(total_len, &[MapOption::MapReadable, MapOption::MapWritable])?;
        trace!("strings = {:?}", strings.data());
        self.map_1to1(executor, &strings)?;
        let mut strings_ptr: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(strings.data() as _, total_len) };

        // TODO: use rlimit stack size
        let stack = MemoryMap::new(0x100000, &[MapOption::MapReadable, MapOption::MapWritable])?;
        trace!("stack = {:?}", stack.data());
        self.map_1to1(executor, &stack)?;

        let stack_size_in_ptrs = stack.len() / std::mem::size_of::<*const u8>();

        // Number of pointers required at the top of the stack for the above described layout.
        let stack_top_offset =
            1 + 1 + self.arguments.len() + 1 + self.environment.len() + 1 + applep.len() + 1;

        // Pointer to where the first pointer will be stored.
        // TODO: it would be nice to use a vec-like thing here so we don't have to keep adjusting the slice.
        let mut stack_ptrs: &mut [*const u8] =
            unsafe { std::mem::transmute(stack.data()) }[stack_size_in_ptrs - stack_top_offset..];
        self.stack_pointer = stack_ptrs.as_ptr() as u64;

        stack_ptrs[0] = 0 as _; // TODO: mh
        stack_ptrs[1] = self.arguments.len() as _;
        stack_ptrs = &mut stack_ptrs[2..];

        for (i, &arg) in self.arguments.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..arg.len()].copy_from_slice(arg.as_bytes());
            strings_ptr = &mut strings_ptr[arg.len() + 1..];
        }
        stack_ptrs = &mut stack_ptrs[self.arguments.len()..];

        for (i, &env) in self.environment.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..env.len()].copy_from_slice(env.as_bytes());
            strings_ptr = &mut strings_ptr[env.len() + 1..];
        }
        stack_ptrs = &mut stack_ptrs[self.environment.len()..];

        for (i, &apple) in applep.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..apple.len()].copy_from_slice(apple.as_bytes());
            strings_ptr = &mut strings_ptr[apple.len() + 1..];
        }

        Ok(())
    }
}

impl Loader for AppBoxLoader {
    type LD = LocalData;
    type GD = GlobalData;

    // Creates the mapping needed for the binary and writes the instructions into it.
    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        let tls = MemoryMap::new(0x10000, &[MapOption::MapReadable, MapOption::MapWritable])?;
        self.map_1to1(executor, &tls)?;
        self.tls = tls.data() as _;
        trace!("tls_page = {:x}", self.tls);

        self.load_macho(executor)?;
        self.setup_stack(executor)?;

        for mapping in self.shared_cache.mappings {
            self.map_1to1(executor, &mapping)?;
        }

        trace!("map done");
        Ok(())
    }

    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        debug!("Entry point: {:x}", self.entry_point);
        debug!("Stack pointer: {:x}", self.stack_pointer);
        debug!("TLS: {:x}", self.tls);
        executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::SP_EL0, self.stack_pointer)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::TPIDRRO_EL0, self.tls)?;
        Ok(ExitKind::Continue)
    }

    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        // TODO: fix up applep so we don't need this
        executor.add_custom_hook(self.shared_cache_base + 0x3f9df8, pthread_hook);
        // TODO: figure out where the actual call to set restartable ranges is
        // and intercept that syscall instead
        executor.add_custom_hook(
            self.shared_cache_base + 0x5e554,
            objc_restartable_ranges_hook,
        );

        Ok(())
    }

    // Unused
    fn load_testcase(
        &mut self,
        _executor: &mut Executor<Self, LocalData, GlobalData>,
        _testcase: &[u8],
    ) -> Result<LoadTestcaseAction> {
        Ok(LoadTestcaseAction::NewAndReset)
    }

    // Unused
    fn symbols(&self) -> Result<Symbols> {
        Ok(Symbols::new())
    }

    // Unused
    fn code_ranges(&self) -> Result<Vec<CodeRange>> {
        Ok(vec![])
    }

    // Unused
    fn coverage_ranges(&self) -> Result<Vec<CoverageRange>> {
        Ok(vec![])
    }

    // Unused
    fn trace_ranges(&self) -> Result<Vec<TraceRange>> {
        Ok(vec![])
    }

    fn exception_handler_sync_curel_spx(
        &self,
        vcpu: &mut applevisor::Vcpu,
        _vma: &mut VirtMemAllocator,
        _ldata: &mut Self::LD,
        _gdata: &std::sync::RwLock<Self::GD>,
    ) -> Result<ExitKind> {
        let elr = vcpu.get_sys_reg(av::SysReg::ELR_EL1)?;
        trace!("ELR_EL1: {:#x}", elr);

        error!("SAME EL Fault!");
        error!("{}", vcpu);
        return Ok(ExitKind::Crash("Unhandled fault".to_string()));
    }

    fn exception_handler_sync_lowerel_aarch64(
        &self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        ldata: &mut Self::LD,
        _gdata: &std::sync::RwLock<Self::GD>,
    ) -> Result<ExitKind> {
        // TODO: expose as trap callback?
    }
}
