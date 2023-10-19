use std::cell::RefCell;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

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
use log::{debug, error, info, trace, warn};
use mach_object::{LoadCommand, MachCommand, MachHeader, OFile};
use mmap_fixed_fixed::{MapOption, MemoryMap};

mod commpage;
mod dyld;
mod dyld_cache_format;

pub struct AppBox<Handler: AppBoxTrapHandler> {
    // Required to enable virtualization for this process.
    _vm: av::VirtualMachine,
    handler: RefCell<Handler>,

    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

impl<Handler: AppBoxTrapHandler> AppBox<Handler> {
    pub fn new(
        executable: &Path,
        argv: &Vec<String>,
        envp: &Vec<String>,
        handler: RefCell<Handler>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            _vm: av::VirtualMachine::new()?,
            handler,
            executable: executable.to_path_buf(),
            argv: argv.clone(),
            envp: envp.clone(),
        })
    }

    pub fn run(&mut self) -> Result<ExitKind> {
        // dynamically allocated physical memory must be <0x1000_0000, which is where our 1:1 mappings begins
        let config = hyperpom::config::ExecConfig::builder(0x1000_0000)
            .coverage(false)
            .build();

        let ldata = LocalData::default();
        let gdata = GlobalData::default();
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

        executor.run(None)
    }
}

pub trait AppBoxTrapHandler: Clone + Send {
    fn trap_handler(
        &mut self,
        vcpu: &mut av::Vcpu,
        vma: &mut VirtMemAllocator,
        load_info: &LoadInfo,
    ) -> Result<ExitKind>;
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
    args.vcpu.set_reg(av::Reg::PC, 0x1337)?; // TODO
    Ok(ExitKind::Continue)
}

#[derive(Clone)]
struct Mmap(Rc<MemoryMap>);
unsafe impl Send for Mmap {}

#[derive(Clone)]
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

    // Vec of all mappings made by the loader (incl. stack, commpage, etc.).
    // N.B. Needs to use a separate type which is Send.
    mappings: Vec<Mmap>,

    // Below stored as u64 instead of *mut/const u8 as raw pointers aren't Send.

    // Entry point of the executable.
    entry_point: u64,
    // Starting stack pointer.
    stack_pointer: u64,
    // Address of thread local storage.
    tls: u64,

    handler: RefCell<Handler>,
}

impl<Handler: AppBoxTrapHandler> AppBoxLoader<Handler> {
    pub fn new(
        executable: &Path,
        argv: &Vec<String>,
        envp: &Vec<String>,
        handler: RefCell<Handler>,
    ) -> anyhow::Result<Self> {
        // TODO: parse macho, check for arm64 and error accordingly.
        // Basically do the macho parsing from load_macho here.
        Ok(Self {
            executable: executable.to_path_buf(),
            arguments: argv.clone(),
            environment: envp.clone(),
            shared_cache: dyld::SharedCache::new_system_cache()?,
            mh: 0,
            mappings: vec![],
            entry_point: 0,
            stack_pointer: 0,
            tls: 0,
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
        let mapping = Rc::new(MemoryMap::new(size, options)?);
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
                LoadCommand::EntryPoint { stacksize, .. } => {
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

        // From darling loader:
        // TODO: produce stack_guard, e.g. stack_guard=0xcdd5c48c061b00fd (must contain 00 somewhere!)
        // TODO: produce malloc_entropy, e.g. malloc_entropy=0x9536cc569d9595cf,0x831942e402da316b
        // TODO: produce main_stack?
        let applep = vec![format!(
            "executable_path={}",
            self.executable.to_str().unwrap()
        )];

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
        let stack_top_offset =
            1 + 1 + self.arguments.len() + 1 + self.environment.len() + 1 + applep.len() + 1;

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
        stack_ptrs = &mut stack_ptrs[self.arguments.len()..];

        for (i, env) in self.environment.iter().enumerate() {
            stack_ptrs[i] = strings_ptr.as_ptr();
            strings_ptr[0..env.len()].copy_from_slice(env.as_bytes());
            strings_ptr = &mut strings_ptr[env.len() + 1..];
        }
        stack_ptrs = &mut stack_ptrs[self.environment.len()..];

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

        // TODO: these need to point to the same backing page
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

        // Setup the r/w commpage...
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

        executor.vma.write_byte(
            commpage::_COMM_PAGE_USER_PAGE_SHIFT_64,
            12, // PAGE_SIZE = 0x1000
        )?;
        executor
            .vma
            .write_byte(commpage::_COMM_PAGE_KERNEL_PAGE_SHIFT, 12)?;

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

        // ... then copy it to the RO page.
        let mut page = [0; 0x1000];
        executor
            .vma
            .read(commpage::_COMM_PAGE64_BASE_ADDRESS, &mut page)?;
        executor
            .vma
            .write(commpage::_COMM_PAGE64_RO_ADDRESS, &page)?;

        Ok(())
    }
}

impl<Handler: AppBoxTrapHandler> Loader for AppBoxLoader<Handler> {
    type LD = LocalData;
    type GD = GlobalData;

    fn map(&mut self, executor: &mut Executor<Self, Self::LD, Self::GD>) -> Result<()> {
        let tls = self
            .new_mapping(
                executor,
                0x10000,
                &[MapOption::MapReadable, MapOption::MapWritable],
            )
            .map_err(|e| hyperpom::error::MemoryError::Generic(e.to_string()))?;
        self.tls = tls.data() as _;
        trace!("tls_page = 0x{:x}", self.tls);

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
        // executor.add_custom_hook(
        //     self.shared_cache.base_address() as u64 + 0x3f9df8,
        //     pthread_hook,
        // );
        // TODO: figure out where the actual call to set restartable ranges is
        // and intercept that syscall instead
        // executor.add_custom_hook(
        //     self.shared_cache.base_address() as u64 + 0x5e554,
        //     objc_restartable_ranges_hook,
        // );

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
        self.handler
            .borrow_mut()
            .trap_handler(vcpu, vma, &ldata.load_info)
    }
}
