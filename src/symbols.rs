use anyhow::Result;
use log::trace;
use mach_object::{LoadCommand, MachCommand, Section, Symbol, SymbolIter};
use std::io::Cursor;
use std::path::Path;
use std::rc::Rc;

#[derive(Clone)]
pub struct Symbolication {
    pub image: String,
    pub symbol: String,
    pub symbol_addr: u64,
}

#[derive(Clone)]
pub struct MachOSymbolMap {
    image: String,
    range: (u64, u64),
    symbols: Vec<SymbolEntry>,
}

#[derive(Clone)]
struct SymbolEntry {
    addr: u64,
    name: String,
}

impl MachOSymbolMap {
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.range.0 && addr < self.range.1
    }

    pub fn symbolicate(&self, addr: u64) -> Option<Symbolication> {
        let idx = match self
            .symbols
            .binary_search_by_key(&addr, |entry| entry.addr)
        {
            Ok(idx) => idx,
            Err(0) => return None,
            Err(idx) => idx - 1,
        };
        let entry = self.symbols.get(idx)?;
        Some(Symbolication {
            image: self.image.clone(),
            symbol: entry.name.clone(),
            symbol_addr: entry.addr,
        })
    }
}

pub fn load_macho_symbols(
    path: &Path,
    data: &[u8],
    arch_offset: u64,
    mach_commands: &[MachCommand],
    slide: u64,
) -> Result<Option<MachOSymbolMap>> {
    let mut min_addr: Option<u64> = None;
    let mut max_addr: Option<u64> = None;
    for cmd in mach_commands {
        if let MachCommand(LoadCommand::Segment64 { segname, vmaddr, vmsize, .. }, _) = cmd {
            if segname == "__PAGEZERO" {
                continue;
            }
            let start = *vmaddr as u64 + slide;
            let end = start + *vmsize as u64;
            min_addr = Some(min_addr.map_or(start, |min| min.min(start)));
            max_addr = Some(max_addr.map_or(end, |max| max.max(end)));
        }
    }

    let symtab = mach_commands.iter().find_map(|cmd| match cmd {
        MachCommand(LoadCommand::SymTab { symoff, nsyms, stroff, strsize }, _) => {
            Some((*symoff, *nsyms, *stroff, *strsize))
        }
        _ => None,
    });
    let Some((symoff, nsyms, stroff, strsize)) = symtab else {
        return Ok(None);
    };

    let slice_start = arch_offset as usize;
    if slice_start >= data.len() {
        return Ok(None);
    }
    let slice = &data[slice_start..];
    let symoff_end = symoff as usize + (nsyms as usize * 16);
    let stroff_end = stroff as usize + strsize as usize;
    if symoff_end > slice.len() || stroff_end > slice.len() {
        return Ok(None);
    }

    let mut sections: Vec<Rc<Section>> = Vec::new();
    for cmd in mach_commands {
        if let MachCommand(
            LoadCommand::Segment64 { sections: seg_sections, .. },
            _,
        ) = cmd
        {
            for sect in seg_sections {
                sections.push(sect.clone());
            }
        }
    }

    let mut cursor = Cursor::new(slice);
    cursor.set_position(symoff as u64);
    let mut iter = SymbolIter::new(&mut cursor, sections, nsyms, stroff, strsize, false, true);

    let mut symbols = Vec::new();
    while let Some(sym) = iter.next() {
        match sym {
            Symbol::Defined { name: Some(name), entry, .. } => {
                if entry != 0 {
                    symbols.push(SymbolEntry {
                        addr: entry as u64 + slide,
                        name: name.to_owned(),
                    });
                }
            }
            Symbol::Debug { name: Some(name), addr, .. } => {
                if addr != 0 {
                    symbols.push(SymbolEntry {
                        addr: addr as u64 + slide,
                        name: name.to_owned(),
                    });
                }
            }
            _ => {}
        }
    }

    if symbols.is_empty() {
        return Ok(None);
    }

    symbols.sort_by_key(|entry| entry.addr);
    let image = path.display().to_string();
    trace!("loaded {} symbols from {}", symbols.len(), image);
    let range = match (min_addr, max_addr) {
        (Some(start), Some(end)) if start < end => (start, end),
        _ => (0, 0),
    };
    Ok(Some(MachOSymbolMap { image, range, symbols }))
}
