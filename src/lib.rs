use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

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

use anyhow::bail;
use log::{debug, error, trace, warn};
use mach_object::{LoadCommand, MachCommand, MachHeader, OFile};
use mmap_fixed_fixed::{MapOption, MemoryMap};

mod commpage;
mod dyld;
mod dyld_cache_format;

pub trait AppBoxTrapHandler: Send {
    fn trap_handler(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        load_info: &LoadInfo,
    ) -> Result<ExitKind>;
}

pub struct AppBox<Handler: AppBoxTrapHandler> {
    // Required to enable virtualization for this process.
    _vm: av::VirtualMachine,
    // Need a mutable reference to the Handler passed in at construction.
    // Can't be a simple &mut because &muts aren't Clone (which the Loader must be).
    // It would probably be sufficient to make this a newtype on Arc<Handler>,
    // but maybe we'll have multiple vCPUs or something idk.
    handler: Arc<Mutex<Handler>>,

    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

impl<Handler: AppBoxTrapHandler> AppBox<Handler> {
    pub fn new(
        executable: &Path,
        argv: &[String],
        envp: &[String],
        handler: Arc<Mutex<Handler>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            _vm: av::VirtualMachine::new()?,
            handler,
            executable: executable.to_path_buf(),
            argv: argv.to_owned(),
            envp: envp.to_owned(),
        })
    }

    pub fn run(&mut self) -> Result<ExitKind> {
        // dynamically allocated physical memory must be <0x1000_0000, which is where our 1:1 mappings begins
        let config = hyperpom::config::ExecConfig::builder(0x1000_0000)
            .coverage(false)
            .build();

        let ldata = LocalData::default();
        let gdata = GlobalData {};
        let mut executor = hyperpom::core::Executor::<_, _, _>::new(
            config,
            AppBoxLoader::new(
                &self.executable,
                &self.argv,
                &self.envp,
                self.handler.clone(),
            )
            .map_err(|e| hyperpom::error::LoaderError::Generic(e.to_string()))?,
            ldata,
            gdata,
        )
        .expect("could not create executor");

        executor.init().expect("could not init executor");
        executor
            .vcpu
            .set_reg(hyperpom::applevisor::Reg::LR, 0xdeadf000)
            .unwrap();

        let result = executor.run(None);
        if result.is_err() {
            debug!("pc: 0x{:x}", executor.vcpu.get_reg(av::Reg::PC).unwrap());
            debug!("lr: 0x{:x}", executor.vcpu.get_reg(av::Reg::LR).unwrap());
            for stack_off in 0..0x100 {
                let stack_val = executor
                    .vma
                    .read_qword(executor.vcpu.get_sys_reg(av::SysReg::SP_EL0)? + stack_off * 8)?;
                debug!("stack[0x{:x}] = 0x{:x}", stack_off * 8, stack_val);
            }
        }
        result
    }
}

#[derive(Clone, Default)]
pub struct LoadInfo {
    pub shared_cache_base: u64,
}

// Empty global data.
#[derive(Clone, Default)]
pub struct GlobalData;

// Local data with load info.
#[derive(Clone, Default)]
pub struct LocalData {
    pub load_info: LoadInfo,
}

#[derive(Clone)]
struct Mmap(Rc<MemoryMap>);
unsafe impl Send for Mmap {}

pub struct AppBoxLoader<Handler: AppBoxTrapHandler> {
    // Path to the executable.
    executable: PathBuf,
    // Arguments to pass to the executable, including argv[0].
    arguments: Vec<String>,
    // Envvars to pass to the executable.
    environment: Vec<String>,

    // The loaded shared cache.
    shared_cache: dyld::SharedCache,
    // Address of the loaded mach-o header.
    mh: u64,

    // Address to next be "allocated" by new_mapping.
    // Used to ensure that mappings are allocated at deterministic addresses.
    map_fixed_next: usize,
    // Vec of all mappings made by the loader (incl. stack, commpage, etc.).
    // N.B. Needs to use a newtype which is Send.
    mappings: Vec<Mmap>,

    // Below stored as u64 instead of *mut/const u8 as raw pointers aren't Send.

    // Entry point of the executable.
    entry_point: u64,
    // Starting stack pointer.
    stack_pointer: u64,

    handler: Arc<Mutex<Handler>>,
}

// Can't derive(Clone) due to https://github.com/rust-lang/rust/issues/26925.
impl<Handler: AppBoxTrapHandler> Clone for AppBoxLoader<Handler> {
    fn clone(&self) -> Self {
        Self {
            executable: self.executable.clone(),
            arguments: self.arguments.clone(),
            environment: self.environment.clone(),
            shared_cache: self.shared_cache.clone(),
            mh: self.mh,
            map_fixed_next: self.map_fixed_next,
            mappings: self.mappings.clone(),
            entry_point: self.entry_point,
            stack_pointer: self.stack_pointer,
            handler: self.handler.clone(),
        }
    }
}

impl<Handler: AppBoxTrapHandler> AppBoxLoader<Handler> {
    pub fn new(
        executable: &Path,
        argv: &[String],
        envp: &[String],
        handler: Arc<Mutex<Handler>>,
    ) -> anyhow::Result<Self> {
        // TODO: parse macho, check for arm64 and error accordingly.
        // Basically do the macho parsing from load_macho here.
        Ok(Self {
            executable: executable.to_path_buf(),
            arguments: argv.to_owned(),
            environment: envp.to_owned(),
            shared_cache: dyld::SharedCache::new_system_cache()?,
            mh: 0,
            map_fixed_next: 0x4_0000_0000, // Any address >= 0x4_0000_0000 should be fine.
            mappings: vec![],
            entry_point: 0,
            stack_pointer: 0,
            handler,
        })
    }

    // Map the given mapping 1:1 into the VM.
    // You are responsible for holding on to the mapping such that it doesn't
    // get dropped while it's mapped.
    fn map_1to1(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
        mapping: &MemoryMap,
    ) -> Result<()> {
        executor
            .vma
            .map_1to1(mapping.data() as _, mapping.len(), av::MemPerms::RWX)
    }

    fn new_mapping(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
        size: usize,
        options: &[MapOption],
    ) -> anyhow::Result<Rc<MemoryMap>> {
        let mut options = options.to_vec();
        let has_fixed = options.iter().any(|o| match o {
            MapOption::MapAddr(_) => true,
            _ => false,
        });
        if !has_fixed {
            options.push(MapOption::MapAddr(self.map_fixed_next as _));
        }
        let mapping = Rc::new(MemoryMap::new(size, &options)?);
        self.map_fixed_next += mapping.len();
        self.mappings.push(Mmap(mapping.clone()));
        self.map_1to1(executor, &mapping)?;
        Ok(mapping)
    }

    // Based on darling's mldr
    // https://github.com/darlinghq/darling/blob/fbcd182dfbadab5076b6a41c21688d9c53a29cc4/src/startup/mldr/loader.c#L50
    fn load_macho(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
        path: &Path,
    ) -> anyhow::Result<()> {
        debug!("loading mach-o {}", path.display());

        let mut executable_file = File::open(path).unwrap();
        let mut executable = Vec::new();
        let size = executable_file.read_to_end(&mut executable).unwrap();

        let mut cur = Cursor::new(&executable[..size]);

        let (arch_file_offset, mach_header, mach_commands) = match OFile::parse(&mut cur).unwrap() {
            OFile::MachFile { header, commands } => match header {
                MachHeader {
                    cputype: mach_object::CPU_TYPE_ARM64,
                    filetype: mach_object::MH_EXECUTE,
                    ..
                } => Ok((0, header, commands)),
                _ => bail!("not an arm64 executable"),
            },
            OFile::FatFile { files, .. } => files
                .iter()
                .find_map(|(arch, file)| match (arch.cputype, file) {
                    (mach_object::CPU_TYPE_ARM64, OFile::MachFile { header, commands }) => {
                        Some(Ok((arch.offset, header.clone(), commands.clone())))
                    }
                    _ => None,
                })
                .unwrap_or(Err(anyhow::anyhow!("no arm64 slice"))),
            _ => bail!("not a mach file"),
        }?;

        let segment_ranges: Vec<(u64, u64)> = mach_commands
            .iter()
            .filter_map(|cmd| match cmd {
                MachCommand(
                    LoadCommand::Segment64 {
                        segname,
                        vmaddr,
                        vmsize,
                        ..
                    },
                    _,
                ) if segname != "__PAGEZERO" => {
                    Some((*vmaddr as u64, *vmaddr as u64 + *vmsize as u64))
                }
                _ => None,
            })
            .collect();

        let minaddr = segment_ranges
            .iter()
            .map(|&(start, _)| start)
            .min()
            .unwrap();
        let maxaddr = segment_ranges.iter().map(|&(_, end)| end).max().unwrap();
        let va_size = maxaddr - minaddr;

        let reservation = if (mach_header.filetype == mach_object::MH_EXECUTE
            && mach_header.flags & mach_object::MH_PIE != 0)
            || mach_header.filetype == mach_object::MH_DYLINKER
        {
            trace!("mach-o va range 0x{:x}-0x{:x}, PIE", minaddr, maxaddr);
            self.new_mapping(
                executor,
                va_size as usize,
                &[MapOption::MapReadable, MapOption::MapWritable],
            )?
        } else {
            trace!("mach-o va range 0x{:x}-0x{:x}, static", minaddr, maxaddr);
            warn!("Non-PIE binary. There may be overlapping vaddrs which cause issues!");
            self.new_mapping(
                executor,
                va_size as usize,
                &[
                    MapOption::MapReadable,
                    MapOption::MapWritable,
                    MapOption::MapAddr(minaddr as _),
                ],
            )?
        };
        trace!("mapped to {:p}", reservation.data());
        let slide = reservation.data() as u64 - minaddr;

        let mut entrypoint: Option<u64> = None;
        for MachCommand(cmd, _cmdsize) in mach_commands {
            match cmd {
                LoadCommand::Segment64 {
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    ..
                } => {
                    if filesize > 0 {
                        let slid_addr = unsafe {
                            reservation
                                .data()
                                .offset(vmaddr as isize - minaddr as isize)
                                as _
                        };
                        trace!(
                            "mapping 0x{:x} bytes at {:p} from offset 0x{:x}",
                            filesize,
                            slid_addr,
                            arch_file_offset + fileoff as u64
                        );
                        // Map anonymous and read instead of mmaping the file directly in case
                        // filesize != vmsize.
                        let mapping = self.new_mapping(
                            executor,
                            vmsize,
                            &[
                                MapOption::MapReadable,
                                MapOption::MapWritable,
                                MapOption::MapAddr(slid_addr),
                            ],
                        )?;
                        executable_file.read_exact_at(
                            unsafe { std::slice::from_raw_parts_mut(mapping.data(), filesize) },
                            arch_file_offset + fileoff as u64,
                        )?;

                        if fileoff == 0 && mach_header.filetype == mach_object::MH_EXECUTE {
                            trace!("setting mh to {:p}", mapping.data());
                            self.mh = mapping.data() as _;
                        }
                    }
                }
                LoadCommand::UnixThread { state, .. } => {
                    if let mach_object::ThreadState::Arm64 { __pc, .. } = state {
                        entrypoint = Some(__pc + slide);
                    } else {
                        bail!("LC_UNIX_THREAD not arm64");
                    }
                }
                LoadCommand::EntryPoint { .. } => {
                    // XXX: entryoff ignored here?
                    // TODO
                }
                LoadCommand::LoadDyLinker(path) => {
                    self.load_macho(executor, &PathBuf::from(path.as_str()))?;
                }
                _ => {}
            }
        }

        // load is re-entrant with LoadDyLinker when coming from a MH_EXECUTE mach-o.
        // Since the dylinker will be fully loaded first (as part of processing the LC_LOAD_DYLINKER),
        // it will take precedence over the main executable.
        if self.entry_point == 0 {
            trace!(
                "setting entrypoint to 0x{:x} (in {})",
                entrypoint.unwrap(),
                path.display()
            );
            self.entry_point = entrypoint.unwrap();
        }

        Ok(())
    }

    fn setup_stack(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
    ) -> anyhow::Result<()> {
        debug!("setting up stack");

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
        let applep = vec![
            // TODO: this should be absolute path
            format!("executable_path={}", self.executable.to_str().unwrap()),
            // Numbers are whatever a test program happened to be launched with.
            //format!("pfz=0x{:x}", 0xfff7bc000u32),
            //format!("stack_guard=0x{:x}", 0xfaf7ad82aef8002bu64),
            //format!("malloc_entropy=0x{:x},0x{:x}", 0x90ccd126cb1ecd9u64, 0x51cba845df4738d5u64),
            format!("ptr_munge=0x{:x}", 0x44a5acc71e7f7fa2u64),
            //format!("main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"),
            //format!("executable_file=0x1a01000010,0x6e441eb"),
            //format!("dyld_file=0x1a01000010,0xfffffff000993c7"),
            //format!("executable_cdhash=ebae22199a9f34b644cf95cfb9c1112a78d5f921"),
            //format!("executable_boothash=099dd72229ca32cc646fbb086bd81fd465476d63"),
            //format!("arm64e_abi=os"),
            //format!("th_port=0x103"),
        ];
        trace!("applep = {:?}", applep);

        let total_len = self.arguments.iter().map(|s| s.len() + 1).sum::<usize>()
            + self.environment.iter().map(|s| s.len() + 1).sum::<usize>()
            + applep.iter().map(|s| s.len() + 1).sum::<usize>();
        let strings = self.new_mapping(
            executor,
            total_len,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        trace!("strings = {:?}", strings.data());
        let mut strings_ptr: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(strings.data() as _, total_len) };

        // TODO: use rlimit stack size
        let stack = self.new_mapping(
            executor,
            0x100000,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        trace!("stack = {:?}", stack.data());

        let stack_size_in_ptrs = stack.len() / std::mem::size_of::<*const u8>();

        // Number of pointers required at the top of the stack for the above described layout.
        let stack_top_offset = 1 /*mh*/ + 1 /*argc*/ + self.arguments.len() + 1 + self.environment.len() + 1 + applep.len() + 1;

        // Pointer to where the first pointer will be stored.
        // TODO: it would be nice to use a vec-like thing here so we don't have to keep adjusting the slice.
        let mut stack_ptrs: &mut [*const u8] =
            unsafe { std::slice::from_raw_parts_mut(stack.data() as _, stack_size_in_ptrs) };
        stack_ptrs = &mut stack_ptrs[stack_size_in_ptrs - stack_top_offset..];
        self.stack_pointer = stack_ptrs.as_ptr() as u64;

        stack_ptrs[0] = self.mh as _;
        stack_ptrs[1] = self.arguments.len() as _;
        stack_ptrs = &mut stack_ptrs[2..];

        for (i, arg) in self.arguments.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..arg.len()].copy_from_slice(arg.as_bytes());
            strings_ptr = &mut strings_ptr[arg.len() + 1..];
        }
        stack_ptrs = &mut stack_ptrs[self.arguments.len() + 1..];

        for (i, env) in self.environment.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..env.len()].copy_from_slice(env.as_bytes());
            strings_ptr = &mut strings_ptr[env.len() + 1..];
        }
        stack_ptrs = &mut stack_ptrs[self.environment.len() + 1..];

        for (i, apple) in applep.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..apple.len()].copy_from_slice(apple.as_bytes());
            strings_ptr = &mut strings_ptr[apple.len() + 1..];
        }

        Ok(())
    }

    fn setup_commpage(
        &mut self,
        executor: &mut Executor<Self, LocalData, GlobalData>,
    ) -> Result<()> {
        debug!("setting up commpage");

        executor.vma.map(
            commpage::_COMM_PAGE64_BASE_ADDRESS as _,
            0x1000,
            av::MemPerms::RW,
        )?;
        executor.vma.map(
            commpage::_COMM_PAGE64_RO_ADDRESS as _,
            0x1000,
            av::MemPerms::R,
        )?;

        executor
            .vma
            .write(commpage::_COMM_PAGE64_BASE_ADDRESS, b"commpage 64-bit")?;
        executor.vma.write_word(
            commpage::_COMM_PAGE_VERSION,
            commpage::_COMM_PAGE_THIS_VERSION as _,
        )?;

        executor.vma.write_byte(commpage::_COMM_PAGE_NCPUS, 1)?;
        executor
            .vma
            .write_byte(commpage::_COMM_PAGE_ACTIVE_CPUS, 1)?;
        executor
            .vma
            .write_byte(commpage::_COMM_PAGE_PHYSICAL_CPUS, 1)?;
        executor
            .vma
            .write_byte(commpage::_COMM_PAGE_LOGICAL_CPUS, 1)?;

        // N.B. These are in the RO page
        executor.vma.write_byte(
            commpage::_COMM_PAGE_USER_PAGE_SHIFT_64,
            14, // PAGE_SIZE = 0x4000
        )?;
        executor
            .vma
            .write_byte(commpage::_COMM_PAGE_KERNEL_PAGE_SHIFT, 14)?;

        executor
            .vma
            .write_dword(commpage::_COMM_PAGE_CPU_CAPABILITIES, commpage::kUP)?;
        executor
            .vma
            .write_qword(commpage::_COMM_PAGE_CPU_CAPABILITIES64, commpage::kUP as _)?;

        executor.vma.write_qword(
            commpage::_COMM_PAGE_MEMORY_SIZE,
            1 * 1024 * 1024 * 1024, // TODO: no idea if correct
        )?;

        Ok(())
    }
}

impl<Handler: AppBoxTrapHandler> Loader for AppBoxLoader<Handler> {
    type LD = LocalData;
    type GD = GlobalData;

    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        self.load_macho(executor, &self.executable.clone())
            .map_err(|e| hyperpom::error::MemoryError::Generic(e.to_string()))?;
        self.setup_stack(executor)
            .map_err(|e| hyperpom::error::MemoryError::Generic(e.to_string()))?;
        self.setup_commpage(executor)?;

        trace!("mapping shared cache");
        for mapping in self.shared_cache.mappings.clone().iter() {
            self.map_1to1(executor, mapping)?;
        }

        executor.ldata.load_info.shared_cache_base = self.shared_cache.base_address() as _;

        debug!("map done");
        Ok(())
    }

    fn pre_exec(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<ExitKind> {
        debug!("Entry point: {:x}", self.entry_point);
        debug!("Stack pointer: {:x}", self.stack_pointer);
        executor.vcpu.set_reg(av::Reg::PC, self.entry_point)?;
        executor
            .vcpu
            .set_sys_reg(av::SysReg::SP_EL0, self.stack_pointer)?;
        Ok(ExitKind::Continue)
    }

    fn hooks(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
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
        Ok(ExitKind::Crash("Unhandled fault".to_string()))
    }

    fn exception_handler_sync_lowerel_aarch64(
        &self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        ldata: &mut Self::LD,
        _gdata: &std::sync::RwLock<Self::GD>,
    ) -> Result<ExitKind> {
        self.handler
            .lock()
            .unwrap()
            .trap_handler(vcpu, vma, &ldata.load_info)
    }
}
