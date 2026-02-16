use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::{bail, Result};
use log::{debug, trace, warn};
use mmap_fixed_fixed::{MapOption, MemoryMap};

use crate::hyperpom::applevisor as av;

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
    symbol_map: Option<SymbolMap>,
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

        let cache_file = File::open(cache_path)?;
        let cache_header: dyld_cache_header = read_at(&cache_file, 0)?;
        let magic = String::from_utf8_lossy(unsafe {
            std::slice::from_raw_parts(
                cache_header.magic.as_ptr() as *const u8,
                cache_header.magic.len(),
            )
        });
        trace!("dyld cache magic: {}", magic.trim_end_matches('\0'));
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
            symbol_map: None,
        };
        cache.map_single_cache(cache_path)?;
        cache.symbol_map = match load_symbol_map(&cache_file, &cache_header, slide) {
            Ok(symbol_map) => symbol_map,
            Err(err) => {
                warn!("failed to load dyld symbols: {}", err);
                None
            }
        };

        let dyndata_mapping = MemoryMap::new(
            std::mem::size_of::<dyld_cache_dynamic_data_header>() + 4096, // sizeof struct plus path strings
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

        // TODO: cryptex path?
        let path_bytes = cache_path.as_os_str().as_encoded_bytes();
        unsafe {
            (*dyndata).cachePathOffset =
                std::mem::size_of::<dyld_cache_dynamic_data_header>() as u32;
            std::ptr::copy_nonoverlapping(
                path_bytes.as_ptr(),
                dyndata_mapping
                    .data()
                    .add((*dyndata).cachePathOffset as usize),
                path_bytes.len(),
            );
        }

        cache.mappings.push(Rc::new(dyndata_mapping));

        debug!("shared cache loaded");

        Ok(cache)
    }

    pub fn base_address(&self) -> *mut u8 {
        self.reservation.data()
    }

    pub fn contains_addr(&self, addr: u64) -> bool {
        let start = self.reservation.data() as u64;
        let end = start + self.reservation.len() as u64;
        addr >= start && addr < end
    }

    pub fn symbolicate(&self, addr: u64) -> Option<Symbolication> {
        self.symbol_map.as_ref()?.symbolicate(addr)
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
                            delta /= std::mem::size_of::<u64>() as u16;
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
                    5 => {
                        let sib = {
                            let mut buf: Vec<u8> = vec![0; mapping_info.slideInfoFileSize as usize];
                            cache.read_exact_at(&mut buf, mapping_info.slideInfoFileOffset)?;
                            buf
                        };
                        let slide_info: &dyld_cache_slide_info5 = unsafe {
                            &*(sib.as_ptr() as *const _ as *const dyld_cache_slide_info5)
                        };
                        for (i, &delta) in unsafe {
                            slide_info
                                .page_starts
                                .as_slice(slide_info.page_starts_count as _)
                        }
                        .iter()
                        .enumerate()
                        {
                            let mut delta = delta;
                            if delta == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE as _ {
                                continue;
                            }
                            // https://github.com/apple-oss-distributions/dyld/blob/d552c40cd1de105f0ec95008e0e0c0972de43456/cache-builder/dyld_cache_format.h#L504
                            delta /= std::mem::size_of::<u64>() as u16;
                            let page_start: *mut u8 =
                                unsafe { mapping.data().add(i * slide_info.page_size as usize) };
                            let mut loc: *mut dyld_cache_slide_pointer5 = page_start as _;
                            loop {
                                unsafe {
                                    loc = loc.add(delta as _);
                                    let locref: &mut dyld_cache_slide_pointer5 = &mut *loc;
                                    delta = locref.regular.next() as _;
                                    let mut new_value = locref.regular.runtimeOffset()
                                        + slide_info.value_add
                                        + self.slide as u64;
                                    if locref.auth.auth() == 0 {
                                        new_value = new_value | (locref.regular.high8() << 56);
                                    }
                                    locref.raw = new_value;
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

    pub(crate) fn map_into_vm(&self, vm: &mut crate::vm::VmManager) -> Result<()> {
        for mapping in &self.mappings {
            trace!(
                "mapping shared cache region {:p}-{:p} into VM",
                mapping.data(),
                unsafe { mapping.data().add(mapping.len()) }
            );
            vm.vma
                .map_1to1(mapping.data() as _, mapping.len(), av::MemPerms::RWX)?;
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct mach_header_64 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct load_command {
    cmd: u32,
    cmdsize: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct dyld_info_command {
    cmd: u32,
    cmdsize: u32,
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct linkedit_data_command {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

const MH_MAGIC_64: u32 = 0xfeedfacf;
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = LC_DYLD_INFO | LC_REQ_DYLD;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;

const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

#[derive(Clone)]
struct ImageTextInfo {
    load_address: u64,
    text_size: u32,
    path: String,
}

#[derive(Clone)]
struct SymbolEntry {
    addr: u64,
    name: String,
    image_index: Option<usize>,
}

#[derive(Clone)]
struct SymbolMap {
    symbols: Vec<SymbolEntry>,
    images: Vec<ImageTextInfo>,
}

pub struct Symbolication {
    pub image: String,
    pub symbol: String,
    pub symbol_addr: u64,
}

impl SymbolMap {
    fn symbolicate(&self, addr: u64) -> Option<Symbolication> {
        let idx = match self
            .symbols
            .binary_search_by_key(&addr, |entry| entry.addr)
        {
            Ok(idx) => idx,
            Err(0) => return None,
            Err(idx) => idx - 1,
        };
        let entry = self.symbols.get(idx)?;
        let image = if let Some(image_index) = entry.image_index {
            self.images
                .get(image_index)
                .map(|image| image.path.clone())
        } else {
            self.image_for_address(addr)
                .map(|image| image.path.clone())
        }
        .unwrap_or_else(|| "<unknown>".to_string());

        Some(Symbolication {
            image,
            symbol: entry.name.clone(),
            symbol_addr: entry.addr,
        })
    }

    fn image_for_address(&self, addr: u64) -> Option<&ImageTextInfo> {
        let idx = match self
            .images
            .binary_search_by_key(&addr, |image| image.load_address)
        {
            Ok(idx) => idx,
            Err(0) => return None,
            Err(idx) => idx - 1,
        };
        let image = self.images.get(idx)?;
        if addr < image.load_address + image.text_size as u64 {
            Some(image)
        } else {
            None
        }
    }
}

struct ExportSymbol {
    addr: u64,
    name: String,
}

fn read_bytes_at(file: &File, offset: u64, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    file.read_exact_at(&mut buf, offset)?;
    Ok(buf)
}

fn read_cstring_at(file: &File, offset: u64, max_len: usize) -> Result<String> {
    let mut buf = Vec::new();
    let mut cur = offset;
    while buf.len() < max_len {
        let mut chunk = [0u8; 256];
        file.read_exact_at(&mut chunk, cur)?;
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            buf.extend_from_slice(&chunk[..pos]);
            break;
        }
        buf.extend_from_slice(&chunk);
        cur += chunk.len() as u64;
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn load_symbol_map(
    cache_file: &File,
    cache_header: &dyld_cache_header,
    slide: usize,
) -> Result<Option<SymbolMap>> {
    trace!("loading dyld symbol map");
    let images = load_images(cache_file, cache_header, slide)?;
    trace!("loaded {} images", images.len());
    let mut symbols = load_exports_symbols(cache_file, cache_header, slide, &images)?;
    trace!("loaded {} export symbols", symbols.len());

    if symbols.is_empty() {
        return Ok(None);
    }
    symbols.sort_by_key(|entry| entry.addr);
    Ok(Some(SymbolMap { symbols, images }))
}

fn load_images(
    cache_file: &File,
    cache_header: &dyld_cache_header,
    slide: usize,
) -> Result<Vec<ImageTextInfo>> {
    if cache_header.imagesTextOffset == 0 || cache_header.imagesTextCount == 0 {
        return Ok(Vec::new());
    }
    let infos: Vec<dyld_cache_image_text_info> = read_vec_at(
        cache_file,
        cache_header.imagesTextOffset,
        cache_header.imagesTextCount as usize,
    )?;
    let mut images = Vec::with_capacity(infos.len());
    for info in infos {
        let path = read_cstring_at(cache_file, info.pathOffset as u64, 4096)?;
        images.push(ImageTextInfo {
            load_address: info.loadAddress + slide as u64,
            text_size: info.textSegmentSize,
            path,
        });
    }
    images.sort_by_key(|image| image.load_address);
    Ok(images)
}

fn load_exports_symbols(
    cache_file: &File,
    cache_header: &dyld_cache_header,
    slide: usize,
    images: &[ImageTextInfo],
) -> Result<Vec<SymbolEntry>> {
    if cache_header.imagesOffset == 0 || cache_header.imagesCount == 0 {
        trace!("cache has no images array");
        return Ok(Vec::new());
    }

    let image_infos: Vec<dyld_cache_image_info> = read_vec_at(
        cache_file,
        cache_header.imagesOffset as u64,
        cache_header.imagesCount as usize,
    )?;

    let mut symbols = Vec::new();
    for image in image_infos {
        let load_addr = image.address + slide as u64;
        let header = unsafe { &*(load_addr as *const mach_header_64) };
        if header.magic != MH_MAGIC_64 {
            continue;
        }

        let mut cmd_ptr = unsafe { (header as *const mach_header_64).add(1) as *const load_command };
        let mut export_info: Option<(u32, u32)> = None;
        for _ in 0..header.ncmds {
            let cmd = unsafe { &*cmd_ptr };
            if cmd.cmd == LC_DYLD_EXPORTS_TRIE {
                let export_cmd = unsafe { &*(cmd_ptr as *const linkedit_data_command) };
                export_info = Some((export_cmd.dataoff, export_cmd.datasize));
                break;
            } else if cmd.cmd == LC_DYLD_INFO || cmd.cmd == LC_DYLD_INFO_ONLY {
                let dyld_info = unsafe { &*(cmd_ptr as *const dyld_info_command) };
                if dyld_info.export_size != 0 {
                    export_info = Some((dyld_info.export_off, dyld_info.export_size));
                }
            }
            cmd_ptr = unsafe { (cmd_ptr as *const u8).add(cmd.cmdsize as usize) as *const load_command };
        }

        let Some((dataoff, datasize)) = export_info else { continue };
        if datasize == 0 {
            continue;
        }

        let data = read_bytes_at(cache_file, dataoff as u64, datasize as usize)?;
        let exports = parse_exports_trie(&data)?;
        if exports.is_empty() {
            continue;
        }

        let image_index = images
            .binary_search_by_key(&load_addr, |image| image.load_address)
            .map(Some)
            .unwrap_or_else(|idx| if idx == 0 { None } else { Some(idx - 1) })
            .and_then(|idx| {
                let image = images.get(idx)?;
                if load_addr < image.load_address + image.text_size as u64 {
                    Some(idx)
                } else {
                    None
                }
            });

        for export in exports {
            let addr = load_addr + export.addr;
            symbols.push(SymbolEntry {
                addr,
                name: export.name,
                image_index,
            });
        }
    }

    symbols.sort_by_key(|entry| entry.addr);
    Ok(symbols)
}

fn parse_exports_trie(data: &[u8]) -> Result<Vec<ExportSymbol>> {
    let mut exports = Vec::new();
    let mut visited = std::collections::HashSet::new();
    parse_exports_node(data, 0, String::new(), &mut exports, &mut visited)?;
    Ok(exports)
}

fn parse_exports_node(
    data: &[u8],
    offset: usize,
    prefix: String,
    exports: &mut Vec<ExportSymbol>,
    visited: &mut std::collections::HashSet<usize>,
) -> Result<()> {
    if offset >= data.len() || visited.contains(&offset) {
        return Ok(());
    }
    visited.insert(offset);

    let mut cursor = offset;
    let terminal_size = data[cursor] as usize;
    cursor += 1;
    let terminal_end = cursor + terminal_size;
    if terminal_end > data.len() {
        return Ok(());
    }

    if terminal_size != 0 {
        let (flags, mut term_cursor) = read_uleb(data, cursor)?;
        if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
            let (_ordinal, new_cursor) = read_uleb(data, term_cursor)?;
            term_cursor = new_cursor;
            while term_cursor < terminal_end && data[term_cursor] != 0 {
                term_cursor += 1;
            }
        } else {
            let (addr, term_cursor) = read_uleb(data, term_cursor)?;
            let mut final_addr = addr;
            if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                let (other, _) = read_uleb(data, term_cursor)?;
                final_addr = other;
            }
            exports.push(ExportSymbol {
                addr: final_addr,
                name: prefix.clone(),
            });
        }
    }

    cursor = terminal_end;
    if cursor >= data.len() {
        return Ok(());
    }
    let child_count = data[cursor] as usize;
    cursor += 1;
    for _ in 0..child_count {
        let mut edge = Vec::new();
        while cursor < data.len() && data[cursor] != 0 {
            edge.push(data[cursor]);
            cursor += 1;
        }
        cursor += 1;
        let (child_offset, new_cursor) = read_uleb(data, cursor)?;
        cursor = new_cursor;
        let mut name = prefix.clone();
        name.push_str(&String::from_utf8_lossy(&edge));
        parse_exports_node(data, child_offset as usize, name, exports, visited)?;
    }

    Ok(())
}

fn read_uleb(data: &[u8], mut offset: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut bit = 0;
    loop {
        if offset >= data.len() {
            return Ok((result, offset));
        }
        let byte = data[offset];
        offset += 1;
        let slice = (byte & 0x7f) as u64;
        result |= slice << bit;
        if (byte & 0x80) == 0 {
            break;
        }
        bit += 7;
        if bit > 63 {
            break;
        }
    }
    Ok((result, offset))
}

// removed unused local-symbol helpers
