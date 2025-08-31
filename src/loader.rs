use crate::dyld;
use crate::vm::VmManager;
use anyhow::{bail, Result};
use log::{debug, trace, warn};
use mach_object::{LoadCommand, MachCommand, MachHeader, OFile};
use mmap_fixed_fixed::{MapOption, MemoryMap};
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use hyperpom::applevisor as av;

pub fn load_macho(
    vm: &mut VmManager,
    executable: &Path,
    arguments: Vec<String>,
    environment: Vec<String>,
) -> Result<Loader> {
    let mut loader = Loader::new(executable, arguments, environment)?;

    loader.load_macho_recursive(vm, executable)?;
    loader.shared_cache.map_into_vm(vm)?;
    loader.setup_stack(vm)?;
    loader.setup_commpage(vm)?;

    Ok(loader)
}

pub struct Loader {
    executable: PathBuf,
    arguments: Vec<String>,
    environment: Vec<String>,

    pub shared_cache: dyld::SharedCache,
    pub mh: u64,

    map_fixed_next: usize,

    pub entry_point: u64,
    pub stack_pointer: u64,
}

impl Loader {
    fn new(executable: &Path, arguments: Vec<String>, environment: Vec<String>) -> Result<Self> {
        Ok(Self {
            executable: executable.to_path_buf(),
            arguments,
            environment,
            shared_cache: dyld::SharedCache::new_system_cache()?,
            mh: 0,
            map_fixed_next: 0x5_0000_0000,
            entry_point: 0,
            stack_pointer: 0,
        })
    }

    fn new_mapping(
        &mut self,
        vm: &mut VmManager,
        size: usize,
        options: &[MapOption],
    ) -> Result<Rc<MemoryMap>> {
        let mut options = options.to_vec();
        let has_fixed = options.iter().any(|o| matches!(o, MapOption::MapAddr(_)));
        if !has_fixed {
            options.push(MapOption::MapAddr(self.map_fixed_next as _));
        }
        let mapping = Rc::new(MemoryMap::new(size, &options)?);
        self.map_fixed_next += mapping.len();
        vm.mappings.push(mapping.clone());
        vm.vma
            .map_1to1(mapping.data() as _, mapping.len(), av::MemPerms::RWX)?;
        Ok(mapping)
    }

    // Based on darling's mldr
    // https://github.com/darlinghq/darling/blob/fbcd182dfbadab5076b6a41c21688d9c53a29cc4/src/startup/mldr/loader.c#L50
    fn load_macho_recursive(&mut self, vm: &mut VmManager, path: &Path) -> Result<()> {
        debug!("loading mach-o {}", path.display());

        let mut executable_file = File::open(path)?;
        let mut executable_data = Vec::new();
        let size = executable_file.read_to_end(&mut executable_data)?;
        let mut cur = Cursor::new(&executable_data[..size]);

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
                vm,
                va_size as usize,
                &[MapOption::MapReadable, MapOption::MapWritable],
            )?
        } else {
            trace!("mach-o va range 0x{:x}-0x{:x}, static", minaddr, maxaddr);
            warn!("Non-PIE binary. There may be overlapping vaddrs which cause issues!");
            self.new_mapping(
                vm,
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
                        let mapping = self.new_mapping(
                            vm,
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
                    self.load_macho_recursive(vm, &PathBuf::from(path.as_str()))?;
                }
                _ => {}
            }
        }

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

    fn setup_stack(&mut self, vm: &mut VmManager) -> Result<()> {
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
            vm,
            total_len,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        trace!("strings = {:?}", strings.data());
        let mut strings_ptr: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(strings.data() as _, total_len) };

        // TODO: use rlimit stack size
        let stack = self.new_mapping(
            vm,
            0x100000,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        trace!("stack = {:?}", stack.data());

        let stack_size_in_ptrs = stack.len() / std::mem::size_of::<*const u8>();

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

    fn setup_commpage(&mut self, vm: &mut VmManager) -> Result<()> {
        debug!("setting up commpage");

        vm.vma.map(
            crate::commpage::_COMM_PAGE64_BASE_ADDRESS as _,
            0x1000,
            av::MemPerms::RW,
        )?;
        vm.vma.map(
            crate::commpage::_COMM_PAGE64_RO_ADDRESS as _,
            0x1000,
            av::MemPerms::R,
        )?;

        vm.vma.write(
            crate::commpage::_COMM_PAGE64_BASE_ADDRESS,
            b"commpage 64-bit",
        )?;
        vm.vma.write_word(
            crate::commpage::_COMM_PAGE_VERSION,
            crate::commpage::_COMM_PAGE_THIS_VERSION as _,
        )?;

        vm.vma.write_byte(crate::commpage::_COMM_PAGE_NCPUS, 1)?;
        vm.vma
            .write_byte(crate::commpage::_COMM_PAGE_ACTIVE_CPUS, 1)?;
        vm.vma
            .write_byte(crate::commpage::_COMM_PAGE_PHYSICAL_CPUS, 1)?;
        vm.vma
            .write_byte(crate::commpage::_COMM_PAGE_LOGICAL_CPUS, 1)?;

        // N.B. These are in the RO page
        vm.vma.write_byte(
            crate::commpage::_COMM_PAGE_USER_PAGE_SHIFT_64,
            14, // PAGE_SIZE = 0x4000
        )?;
        vm.vma
            .write_byte(crate::commpage::_COMM_PAGE_KERNEL_PAGE_SHIFT, 14)?;

        vm.vma.write_dword(
            crate::commpage::_COMM_PAGE_CPU_CAPABILITIES,
            crate::commpage::kUP,
        )?;
        vm.vma.write_qword(
            crate::commpage::_COMM_PAGE_CPU_CAPABILITIES64,
            crate::commpage::kUP as _,
        )?;

        vm.vma.write_qword(
            crate::commpage::_COMM_PAGE_MEMORY_SIZE,
            1 * 1024 * 1024 * 1024, // TODO: no idea if correct
        )?;

        Ok(())
    }
}
