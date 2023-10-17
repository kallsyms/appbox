use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::{bail, Result};
use log::{debug, error, info, trace, warn};
use mmap_fixed_fixed::{MapOption, MemoryMap};

pub struct SharedCache {
    pub reservation: MemoryMap,
    pub slide: usize,
    pub mappings: Vec<MemoryMap>,
}

// Clone + Send are required as transitive requirements from Loader.
// It should be safe to move this cache object between threads,
// and the struct itself should not be modified after initialization.
// However, modifications to the mapped cache memory (e.g. writing to globals in an image) would be reflected in all "copies".
impl Clone for SharedCache {
    fn clone(&self) -> Self {
        Self {
            reservation: self.reservation,
            slide: self.slide,
            mappings: self.mappings,
        }
    }
}

unsafe impl Send for SharedCache {}

impl SharedCache {
    pub fn new_system_cache() -> Result<Self> {
        Self::new(&PathBuf::from(
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
        ))
    }

    pub fn new(cache_path: &Path) -> Result<Self> {
        let cache = File::open(cache_path)?;
        let cache_header: dyld_cache_header = {
            let mut buf = [0; std::mem::size_of::<dyld_cache_header>()];
            cache.read_exact_at(&mut buf, 0)?;
            unsafe { *(&buf as *const _ as *const dyld_cache_header) }
        };
        let reservation = MemoryMap::new(
            cache_header.sharedRegionSize as usize,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        let slide = (reservation.data() as u64 - cache_header.sharedRegionStart) as usize;

        let cache = Self {
            reservation,
            slide,
            mappings: vec![],
        };
        cache.map_single_cache(cache_path, 0)?;

        let dyndata = MemoryMap::new(
            std::mem::size_of::<dyld_cache_dynamic_data_header>(),
            &[
                MapOption::MapReadable,
                MapOption::MapWritable,
                MapOption::MapAddr(unsafe {
                    cache
                        .base_address()
                        .add(cache_header.dynamicDataOffset as _)
                }),
            ],
        )?;
        cache.mappings.push(dyndata);

        let dyndata: *mut dyld_cache_dynamic_data_header = dyndata.data() as _;
        let stat = std::fs::metadata(cache_path)?;
        unsafe {
            (*dyndata).magic = std::mem::transmute(*DYLD_SHARED_CACHE_DYNAMIC_DATA_MAGIC);
            (*dyndata).fsId = stat.st_dev();
            (*dyndata).fsObjId = stat.st_ino();
        }

        Ok(cache)
    }

    pub fn base_address(&self) -> *mut u8 {
        self.reservation.data()
    }

    fn map_single_cache(&mut self, path: &Path, cache_offset: usize) -> Result<()> {
        let cache = File::open(path)?;
        let cache_header: dyld_cache_header = {
            let mut buf = [0; std::mem::size_of::<dyld_cache_header>()];
            cache.read_exact_at(&mut buf, 0)?;
            unsafe { *(&buf as *const _ as *const dyld_cache_header) }
        };
        let mappings: &[dyld_cache_mapping_and_slide_info] = {
            let mut buf = vec![
                0;
                std::mem::size_of::<dyld_cache_mapping_and_slide_info>()
                    * cache_header.mappingWithSlideCount as usize
            ];
            cache.read_exact_at(&mut buf, cache_header.mappingWithSlideOffset as _)?;
            unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr() as _,
                    cache_header.mappingWithSlideCount as usize,
                )
            }
            .clone()
        };
        for mapping_info in mappings {
            let map_addr = mapping_info.address + self.slide as u64 + cache_offset as u64;
            debug!("mapping cache {:x} -> {:x}", mapping_info.address, map_addr);

            let mapping = MemoryMap::new(
                mapping_info.size as usize,
                &[
                    MapOption::MapFd(cache.as_raw_fd()),
                    MapOption::MapReadable,
                    MapOption::MapWritable,
                    MapOption::MapAddr(map_addr as _),
                    MapOption::MapOffset(mapping_info.fileOffset as _),
                ],
            )?;
            self.mappings.push(mapping);

            if mapping_info.slideInfoFileSize > 0 {
                let slide_version: u32 = {
                    let mut buf = [0; std::mem::size_of::<u32>()];
                    cache.read_exact_at(&mut buf, mapping_info.slideInfoFileOffset)?;
                    unsafe { *(&buf as *const _ as *const u32) }
                };
                match slide_version {
                    3 => {
                        let slide_info: dyld_cache_slide_info3 = {
                            let mut buf = [0; std::mem::size_of::<dyld_cache_slide_info3>()];
                            cache.read_exact_at(&mut buf, mapping_info.slideInfoFileOffset)?;
                            unsafe { *(&buf as *const _ as *const dyld_cache_slide_info3) }
                        };
                        for (i, &delta) in unsafe {
                            slide_info
                                .page_starts
                                .as_slice(slide_info.page_starts_count as _)
                        }
                        .iter()
                        .enumerate()
                        {
                            if delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE as _ {
                                continue;
                            }
                            delta = delta / std::mem::size_of::<u64>() as u16;
                            let page_start: *mut u8 =
                                unsafe { mapping.data().add(i * slide_info.page_size as usize) };
                            let mut loc: *mut dyld_cache_slide_pointer3 = page_start as _;
                            loop {
                                loc = unsafe { loc.add(delta as _) };
                                let mut locref: &dyld_cache_slide_pointer3 = unsafe { &mut *loc };
                                delta = locref.plain.offsetToNextPointer() as _;
                                if locref.auth.authenticated() != 0 {
                                    locref.raw = locref.auth.offsetFromSharedCacheBase()
                                        + self.slide as u64
                                        + slide_info.auth_value_add;
                                } else {
                                    let value51: u64 = locref.plain.pointerValue();
                                    let top8 = value51 & 0x0007F80000000000;
                                    let bottom43 = value51 & 0x000007FFFFFFFFFF;
                                    let target_value = (top8 << 13) | bottom43;
                                    locref.raw = target_value + self.slide as u64;
                                }
                                if delta == 0 {
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        bail!(format!("unsupported slide version {}", slide_version))
                    }
                }
            } else {
                info!("no slide info for mapping {:x}?", mapping_info.address);
            }
        }

        let subcaches: &[dyld_subcache_entry] = unsafe {
            let mut buf = vec![
                0;
                std::mem::size_of::<dyld_subcache_entry>()
                    * cache_header.subCacheArrayCount as usize
            ];
            cache.read_exact_at(&mut buf, cache_header.subCacheArrayOffset as _)?;
            unsafe {
                std::slice::from_raw_parts(
                    buf.as_ptr() as _,
                    cache_header.subCacheArrayCount as usize,
                )
            }
            .clone()
        };

        for (i, subcache) in subcaches.iter().enumerate() {
            let subcache_path = path.with_extension(format!("{:02}", i + 1));
            self.map_single_cache(&subcache_path, subcache.cacheVMOffset as _)?;
        }

        Ok(())
    }
}

include!(concat!(env!("OUT_DIR"), "/dyld.rs"));
