//! Folds `.text` into each entrypoint section, so a helper function works.
//!
//! A guest's entrypoints live in named sections — `synchronicity.stream`,
//! `synchronicity.init` — and everything else the program defines lands in
//! `.text`, because that is where a C compiler puts a function nobody gave a
//! section to. Static helpers, and every convenience in `synch.h` that is not
//! a macro, are exactly that.
//!
//! async-ebpf loads *one section* and analyzes it on its own, so a call from
//! an entrypoint into `.text` is a call out of the program as far as that
//! analysis is concerned: "local call target out of range". Which would mean a
//! guest could not call a function it wrote, and `sy_pump` — the one piece of
//! the SDK that is a function rather than a macro — would be unusable.
//!
//! So each entrypoint section that calls into `.text` gets its own copy of
//! `.text` appended, and those calls are rewritten to reach it. Copying rather
//! than sharing because sections are loaded independently; the duplication is
//! bounded by the number of entrypoints, which is two.
//!
//! Nothing here is inference about what a compiler meant. Every rewrite is
//! driven by a relocation the object already carries.

/// `.symtab`.
const SHT_SYMTAB: u32 = 2;
/// `.text`, and every other section with bytes in the file.
const SHT_PROGBITS: u32 = 1;
/// `.bss`: a header with no bytes behind it.
const SHT_NOBITS: u32 = 8;
/// A relocation section, in the `Elf64_Rel` form the BPF ABI uses.
const SHT_REL: u32 = 9;
/// `SHF_ALLOC | SHF_EXECINSTR`: the flags that make a section code.
const SHF_CODE: u64 = 0x6;
/// The `call` opcode.
const OP_CALL: u8 = 0x85;
/// The relocation a call carries: a 32-bit immediate in an instruction.
const R_BPF_64_32: u32 = 10;
/// One eBPF instruction.
const INSN: usize = 8;
/// One section header.
const SHDR: usize = 64;

#[derive(Clone)]
struct Section {
    name: String,
    name_offset: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
    data: Vec<u8>,
}

impl Section {
    fn is_code(&self) -> bool {
        self.kind == SHT_PROGBITS && self.flags == SHF_CODE && !self.data.is_empty()
    }
}

#[derive(Clone, Copy)]
struct Symbol {
    name_offset: u32,
    section: u16,
    value: u64,
}

#[derive(Clone, Copy)]
struct Rel {
    offset: u64,
    info: u64,
}

impl Rel {
    fn symbol(self) -> usize {
        (self.info >> 32) as usize
    }
    fn kind(self) -> u32 {
        self.info as u32
    }
}

/// Rewrites `object` in place if anything needs folding.
///
/// Returns `None` when the object is already whole — no `.text`, or no
/// entrypoint calling into it — which is the common case for a program that
/// only calls helpers.
pub(crate) fn fold_text(object: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if object.len() < 64 || &object[0..4] != b"\x7fELF" || object[4] != 2 || object[5] != 1 {
        return Ok(None);
    }
    // EM_BPF, little-endian ELF64. Anything else is not ours to rewrite.
    if u16(object, 18)? != 247 {
        return Ok(None);
    }

    let shoff = u64at(object, 40)? as usize;
    let shentsize = u16(object, 58)? as usize;
    let shnum = u16(object, 60)? as usize;
    let shstrndx = u16(object, 62)? as usize;
    if shentsize != SHDR || shnum == 0 || shstrndx >= shnum {
        return Ok(None);
    }

    let mut sections = read_sections(object, shoff, shnum)?;
    let names = sections[shstrndx].data.clone();
    for section in &mut sections {
        section.name = cstr(&names, section.name_offset as usize).unwrap_or_default();
    }

    let Some(text) = sections
        .iter()
        .position(|s| s.name == ".text" && s.is_code())
    else {
        return Ok(None);
    };
    if !sections[text].data.len().is_multiple_of(INSN) {
        return Ok(None);
    }
    let Some(symtab) = sections.iter().position(|s| s.kind == SHT_SYMTAB) else {
        return Ok(None);
    };
    let strtab = sections[symtab].link as usize;
    if strtab >= sections.len() {
        return Ok(None);
    }
    let symbols = read_symbols(&sections[symtab])?;
    let strings = sections[strtab].data.clone();
    let text_data = sections[text].data.clone();
    let text_rels = rels_for(&sections, text)?;

    let targets: Vec<usize> = (0..sections.len())
        .filter(|&i| i != text && sections[i].is_code())
        .collect();

    let mut changed = false;
    for target in targets {
        let Some(rel_index) = sections
            .iter()
            .position(|s| s.kind == SHT_REL && s.info as usize == target)
        else {
            continue;
        };
        let rels = read_rels(&sections[rel_index])?;
        let calls_text = rels
            .iter()
            .any(|rel| is_text_call(*rel, &symbols, &strings, text));

        if !calls_text {
            // Nothing to fold, but tinycc can leave a call relocation on an
            // instruction that is no longer a call. Left in place, the loader
            // refuses the whole object over an entry that means nothing.
            let pruned = prune(&sections[target].data, rels)?;
            let encoded = encode_rels(&pruned);
            if encoded != sections[rel_index].data {
                sections[rel_index].size = encoded.len() as u64;
                sections[rel_index].data = encoded;
                changed = true;
            }
            continue;
        }

        let original = sections[target].data.len();
        if !original.is_multiple_of(INSN) {
            continue;
        }
        let mut data = sections[target].data.clone();
        data.extend_from_slice(&text_data);

        let mut kept = Vec::new();
        for rel in rels {
            if is_text_call(rel, &symbols, &strings, text) {
                rewrite_call(&mut data, rel, &symbols, original, text)?;
            } else {
                kept.push(rel);
            }
        }
        // `.text`'s own relocations come along with its bytes, shifted to
        // where those bytes now are — including the calls it makes to itself.
        for rel in &text_rels {
            let mut moved = *rel;
            moved.offset = moved
                .offset
                .checked_add(original as u64)
                .ok_or_else(|| "relocation offset overflow".to_string())?;
            if is_text_call(moved, &symbols, &strings, text) {
                rewrite_call(&mut data, moved, &symbols, original, text)?;
            } else {
                kept.push(moved);
            }
        }
        let kept = prune(&data, kept)?;

        sections[target].size = data.len() as u64;
        sections[target].data = data;
        let encoded = encode_rels(&kept);
        sections[rel_index].size = encoded.len() as u64;
        sections[rel_index].data = encoded;
        changed = true;
    }

    if !changed {
        return Ok(None);
    }
    Ok(Some(rebuild(object, &mut sections)))
}

/// Whether a relocation is a call into `.text`.
fn is_text_call(rel: Rel, symbols: &[Symbol], strings: &[u8], text: usize) -> bool {
    if rel.kind() != R_BPF_64_32 {
        return false;
    }
    let Some(symbol) = symbols.get(rel.symbol()) else {
        return false;
    };
    symbol.section as usize == text
        || cstr(strings, symbol.name_offset as usize).as_deref() == Some(".text")
}

/// Turns a call-into-`.text` into a relative call inside the folded section.
fn rewrite_call(
    data: &mut [u8],
    rel: Rel,
    symbols: &[Symbol],
    original: usize,
    text: usize,
) -> Result<(), String> {
    let at = rel.offset as usize;
    if !at.is_multiple_of(INSN) || at + INSN > data.len() {
        return Err("a call relocation points outside its section".to_string());
    }
    if data[at] != OP_CALL {
        // The relocation survived an instruction that is no longer a call.
        // `prune` drops it; nothing here should touch the instruction.
        return Ok(());
    }
    let symbol = symbols
        .get(rel.symbol())
        .ok_or_else(|| "a call relocation names no symbol".to_string())?;

    // A symbol with no value carries its target in the instruction's own
    // immediate, as a count of instructions from the one after the call.
    let old = i32::from_le_bytes(data[at + 4..at + 8].try_into().expect("4 bytes")) as i64;
    let within_text = if symbol.section as usize == text && symbol.value != 0 {
        (symbol.value / INSN as u64) as i64
    } else {
        old + 1
    };

    let target = (original / INSN) as i64 + within_text;
    let here = (at / INSN) as i64;
    let delta = target - here - 1;
    let delta = i32::try_from(delta).map_err(|_| "a call target is out of range".to_string())?;

    // src = 1 marks a call to another instruction in this section rather than
    // to a helper index.
    data[at + 1] = (data[at + 1] & 0x0f) | 0x10;
    data[at + 4..at + 8].copy_from_slice(&delta.to_le_bytes());
    Ok(())
}

/// Drops call relocations that no longer describe a call, and duplicates.
fn prune(data: &[u8], rels: Vec<Rel>) -> Result<Vec<Rel>, String> {
    let mut out = Vec::with_capacity(rels.len());
    let mut seen = std::collections::HashSet::new();
    for rel in rels {
        if rel.kind() == R_BPF_64_32 {
            let at = rel.offset as usize;
            if !at.is_multiple_of(INSN) || at + INSN > data.len() {
                return Err("a call relocation points outside its section".to_string());
            }
            if data[at] != OP_CALL || !seen.insert(rel.offset) {
                continue;
            }
        }
        out.push(rel);
    }
    Ok(out)
}

fn read_sections(object: &[u8], shoff: usize, shnum: usize) -> Result<Vec<Section>, String> {
    let mut out = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let at = shoff
            .checked_add(index * SHDR)
            .ok_or_else(|| "section table overflows".to_string())?;
        if at + SHDR > object.len() {
            return Err("a section header is out of bounds".to_string());
        }
        let mut section = Section {
            name: String::new(),
            name_offset: u32at(object, at)?,
            kind: u32at(object, at + 4)?,
            flags: u64at(object, at + 8)?,
            addr: u64at(object, at + 16)?,
            offset: u64at(object, at + 24)?,
            size: u64at(object, at + 32)?,
            link: u32at(object, at + 40)?,
            info: u32at(object, at + 44)?,
            align: u64at(object, at + 48)?,
            entsize: u64at(object, at + 56)?,
            data: Vec::new(),
        };
        section.data = section_data(object, &section)?.to_vec();
        out.push(section);
    }
    Ok(out)
}

fn section_data<'a>(object: &'a [u8], section: &Section) -> Result<&'a [u8], String> {
    if section.kind == SHT_NOBITS || section.size == 0 {
        return Ok(&[]);
    }
    let start = section.offset as usize;
    let end = start
        .checked_add(section.size as usize)
        .ok_or_else(|| "section data overflows".to_string())?;
    object
        .get(start..end)
        .ok_or_else(|| "section data is out of bounds".to_string())
}

fn read_symbols(symtab: &Section) -> Result<Vec<Symbol>, String> {
    let entsize = if symtab.entsize == 0 {
        24
    } else {
        symtab.entsize as usize
    };
    if entsize < 24 {
        return Err("the symbol table has an impossible entry size".to_string());
    }
    symtab
        .data
        .chunks_exact(entsize)
        .map(|chunk| {
            Ok(Symbol {
                name_offset: u32at(chunk, 0)?,
                section: u16(chunk, 6)?,
                value: u64at(chunk, 8)?,
            })
        })
        .collect()
}

fn rels_for(sections: &[Section], target: usize) -> Result<Vec<Rel>, String> {
    match sections
        .iter()
        .find(|s| s.kind == SHT_REL && s.info as usize == target)
    {
        Some(section) => read_rels(section),
        None => Ok(Vec::new()),
    }
}

fn read_rels(section: &Section) -> Result<Vec<Rel>, String> {
    let entsize = if section.entsize == 0 {
        16
    } else {
        section.entsize as usize
    };
    if entsize < 16 {
        return Err("a relocation section has an impossible entry size".to_string());
    }
    section
        .data
        .chunks_exact(entsize)
        .map(|chunk| {
            Ok(Rel {
                offset: u64at(chunk, 0)?,
                info: u64at(chunk, 8)?,
            })
        })
        .collect()
}

fn encode_rels(rels: &[Rel]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rels.len() * 16);
    for rel in rels {
        out.extend_from_slice(&rel.offset.to_le_bytes());
        out.extend_from_slice(&rel.info.to_le_bytes());
    }
    out
}

/// Lays the sections out again, since some of them changed size.
fn rebuild(object: &[u8], sections: &mut [Section]) -> Vec<u8> {
    let mut out = object[..64].to_vec();
    for (index, section) in sections.iter_mut().enumerate() {
        if index == 0 {
            section.offset = 0;
            section.size = 0;
            continue;
        }
        if section.kind == SHT_NOBITS {
            // No bytes in the file, but an offset is still written, and a
            // plausible one costs nothing.
            section.offset = out.len() as u64;
            section.size = section.data.len() as u64;
            continue;
        }
        align(&mut out, section.align.max(1) as usize);
        section.offset = out.len() as u64;
        section.size = section.data.len() as u64;
        out.extend_from_slice(&section.data);
    }

    align(&mut out, 8);
    let shoff = out.len() as u64;
    for section in sections {
        out.extend_from_slice(&section.name_offset.to_le_bytes());
        out.extend_from_slice(&section.kind.to_le_bytes());
        out.extend_from_slice(&section.flags.to_le_bytes());
        out.extend_from_slice(&section.addr.to_le_bytes());
        out.extend_from_slice(&section.offset.to_le_bytes());
        out.extend_from_slice(&section.size.to_le_bytes());
        out.extend_from_slice(&section.link.to_le_bytes());
        out.extend_from_slice(&section.info.to_le_bytes());
        out.extend_from_slice(&section.align.to_le_bytes());
        out.extend_from_slice(&section.entsize.to_le_bytes());
    }
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    out
}

fn align(out: &mut Vec<u8>, to: usize) {
    if to > 1 {
        let over = out.len() % to;
        if over != 0 {
            out.resize(out.len() + to - over, 0);
        }
    }
}

fn cstr(data: &[u8], at: usize) -> Option<String> {
    let rest = data.get(at..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..end])
        .ok()
        .map(ToOwned::to_owned)
}

fn u16(data: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(read(data, at)?))
}

fn u32at(data: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(read(data, at)?))
}

fn u64at(data: &[u8], at: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(read(data, at)?))
}

fn read<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N], String> {
    data.get(at..at + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| format!("a {N}-byte read at {at} is out of bounds"))
}
