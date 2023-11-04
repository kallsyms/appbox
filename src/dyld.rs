use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::{bail, Result};
use log::{debug, trace};
use mmap_fixed_fixed::{MapOption, MemoryMap};

use crate::dyld_cache_format::*;

// Clone + Send are required as transitive requirements from Loader.
// It should be safe to move this cache object between threads,
// and the struct itself should not be modified after initialization.
// However, modifications to the mapped cache memory (e.g. writing to globals in an image) would be reflected in all "copies".
#[derive(Clone)]
pub struct SharedCache {
    // MemoryMaps are wrapped in an Rc as MemoryMap doesn't implement Clone.
    pub reservation: Rc<MemoryMap>,
    pub slide: usize,
    pub mappings: Vec<Rc<MemoryMap>>,
}

unsafe impl Send for SharedCache {}

fn read_at<T: Copy>(file: &File, offset: u64) -> Result<T> {
    let mut buf: Vec<u8> = vec![0; std::mem::size_of::<T>()];
    file.read_exact_at(&mut buf, offset)?;
    Ok(unsafe { *(buf.as_ptr() as *const T) })
}

fn read_vec_at<T: Clone>(file: &File, offset: u64, count: usize) -> Result<Vec<T>> {
    let mut vec: Vec<T> = unsafe { vec![std::mem::zeroed(); count] };
    let buf: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(vec.as_mut_ptr() as _, count * std::mem::size_of::<T>())
    };
    file.read_exact_at(buf, offset)?;
    Ok(vec)
}

impl SharedCache {
    pub fn new_system_cache() -> Result<Self> {
        Self::new(&PathBuf::from(
            "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
        ))
    }

    pub fn new(cache_path: &Path) -> Result<Self> {
        debug!("loading shared cache {}", cache_path.display());

        let cache = File::open(cache_path)?;
        let cache_header: dyld_cache_header = read_at(&cache, 0)?;
        let reservation = MemoryMap::new(
            cache_header.sharedRegionSize as usize,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?;
        let slide = (reservation.data() as u64 - cache_header.sharedRegionStart) as usize;
        trace!(
            "main cache at {:p}, slide 0x{:x}",
            reservation.data(),
            slide
        );

        let mut cache = Self {
            reservation: Rc::new(reservation),
            slide,
            mappings: vec![],
        };
        cache.map_single_cache(cache_path)?;

        let dyndata_mapping = MemoryMap::new(
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

        let dyndata: *mut dyld_cache_dynamic_data_header = dyndata_mapping.data() as _;
        let stat = std::fs::metadata(cache_path)?;
        unsafe {
            (*dyndata).magic = std::mem::transmute(*DYLD_SHARED_CACHE_DYNAMIC_DATA_MAGIC);
            (*dyndata).fsId = stat.st_dev();
            (*dyndata).fsObjId = stat.st_ino();
        }

        cache.mappings.push(Rc::new(dyndata_mapping));

        debug!("shared cache loaded");

        Ok(cache)
    }

    pub fn base_address(&self) -> *mut u8 {
        self.reservation.data()
    }

    fn map_single_cache(&mut self, path: &Path) -> Result<()> {
        trace!("mapping single cache {}", path.display());
        let cache = File::open(path)?;
        let cache_header: dyld_cache_header = read_at(&cache, 0)?;
        let mappings: Vec<dyld_cache_mapping_and_slide_info> = read_vec_at(
            &cache,
            cache_header.mappingWithSlideOffset as _,
            cache_header.mappingWithSlideCount as _,
        )?;
        for mapping_info in mappings {
            let map_addr = mapping_info.address + self.slide as u64;
            trace!(
                "mapping in cache 0x{:x} -> 0x{:x}",
                mapping_info.address,
                map_addr
            );

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

            if mapping_info.slideInfoFileSize > 0 {
                let slide_version: u32 = read_at(&cache, mapping_info.slideInfoFileOffset)?;
                match slide_version {
                    3 => {
                        // This is to get around the fact that the slide info has a flexible array
                        // member at the end, which means the struct is not Copy and can't be
                        // simply derefed.
                        // Have to create a vec with the actual data (including the flexible
                        // array), bring that up to keep it alive, then cast the vec contents.
                        let sib = {
                            let mut buf: Vec<u8> = vec![0; mapping_info.slideInfoFileSize as usize];
                            cache.read_exact_at(&mut buf, mapping_info.slideInfoFileOffset)?;
                            buf
                        };
                        let slide_info: &dyld_cache_slide_info3 = unsafe {
                            &*(sib.as_ptr() as *const _ as *const dyld_cache_slide_info3)
                        };

                        // https://github.com/apple-oss-distributions/dyld/blob/18d3cb0f6b46707fee6d315cccccf7af8a8dbe57/cache-builder/dyld_cache_format.h#L339
                        for (i, &delta) in unsafe {
                            slide_info
                                .page_starts
                                .as_slice(slide_info.page_starts_count as _)
                        }
                        .iter()
                        .enumerate()
                        {
                            let mut delta = delta;
                            if delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE as _ {
                                continue;
                            }
                            delta = delta / std::mem::size_of::<u64>() as u16;
                            let page_start: *mut u8 =
                                unsafe { mapping.data().add(i * slide_info.page_size as usize) };
                            let mut loc: *mut dyld_cache_slide_pointer3 = page_start as _;
                            loop {
                                unsafe {
                                    loc = loc.add(delta as _);
                                    let locref: &mut dyld_cache_slide_pointer3 = &mut *loc;
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
                    }
                    _ => {
                        bail!(format!("unsupported slide version {}", slide_version))
                    }
                }
            } else {
                trace!("no slide info for mapping 0x{:x}", mapping_info.address);
            }

            self.mappings.push(Rc::new(mapping));
        }

        let subcaches: Vec<dyld_subcache_entry> = read_vec_at(
            &cache,
            cache_header.subCacheArrayOffset as _,
            cache_header.subCacheArrayCount as _,
        )?;

        for (i, _) in subcaches.iter().enumerate() {
            let subcache_path = path.with_extension(format!("{:02}", i + 1));
            self.map_single_cache(&subcache_path)?;
        }

        Ok(())
    }
}
