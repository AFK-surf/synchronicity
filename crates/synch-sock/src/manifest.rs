//! The `synchronicity.manifest` section: how a program's declaration is read
//! out of its ELF object (`docs/SOCKETS.md` §3.1).
//!
//! A declaration is **data, never code**. The object carries one non-executable
//! `synchronicity.manifest` section holding versioned JSON, and this module is
//! the only reader: a bounded ELF section walk, then
//! [`synch_core::parse_socket_manifest`] over the bytes it finds. Nothing here
//! executes anything, which is why this module is portable — inspection and
//! admission read the same manifest on platforms that cannot run the program
//! at all.
//!
//! The walk refuses, by name, everything the format forbids: a manifest
//! section marked executable, more than one of them, an oversized one, and any
//! `synchronicity.init` section at all — the executable declaration hook of an
//! earlier format, which must not be silently ignored when its author expected
//! it to run.

use synch_core::{Declaration, ManifestError};

use crate::abi::{SECTION_INIT, SECTION_MANIFEST, SECTION_STREAM};

/// `SHF_EXECINSTR`: the flag that makes a section code.
const SHF_EXECINSTR: u64 = 0x4;
/// `SHT_NOBITS`: a header with no bytes behind it (`.bss`).
const SHT_NOBITS: u32 = 8;
/// One ELF64 section header.
const SHDR_LEN: usize = 64;

/// Why an object's manifest cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProgramManifestError {
    /// The bytes are not a little-endian ELF64 object.
    #[error("not a little-endian ELF64 object: {0}")]
    NotElf(String),
    /// The object still carries the executable `synchronicity.init` section.
    #[error(
        "the object carries an executable `synchronicity.init` declaration section; \
         declarations are a `synchronicity.manifest` JSON section now — rebuild against \
         the current SDK (`synch socket sdk`)"
    )]
    ExecutableDeclaration,
    /// More than one `synchronicity.manifest` section: two claims, neither wins.
    #[error("the object carries more than one `synchronicity.manifest` section")]
    Duplicate,
    /// The manifest section is marked executable, which the format forbids.
    #[error("the `synchronicity.manifest` section is marked executable; it must be data")]
    Executable,
    /// The section is present but its JSON does not parse.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

/// What one ELF section walk found.
struct Sections {
    /// The manifest section's bytes, if the object carries one.
    manifest: Option<Vec<u8>>,
    /// Whether a `synchronicity.stream` entrypoint section exists.
    stream: bool,
}

/// Reads the manifest declaration out of `elf`.
///
/// An object with no `synchronicity.manifest` section declares nothing and
/// gets the empty [`Declaration`], which grants exactly nothing. An object
/// with one gets its parsed, validated declaration — or a named refusal.
pub fn manifest_declaration(elf: &[u8]) -> Result<Declaration, ProgramManifestError> {
    match walk(elf)?.manifest {
        Some(bytes) => Ok(synch_core::parse_socket_manifest(&bytes)?),
        None => Ok(Declaration::default()),
    }
}

/// Whether the object names a `synchronicity.stream` entrypoint.
///
/// The portable half of program validation: an object with no stream section
/// can be refused at inspection and admission without an eBPF runtime.
pub fn has_stream_section(elf: &[u8]) -> bool {
    walk(elf).is_ok_and(|sections| sections.stream)
}

/// The bounded section walk everything above shares.
fn walk(elf: &[u8]) -> Result<Sections, ProgramManifestError> {
    let bad = |reason: &str| ProgramManifestError::NotElf(reason.to_string());
    if elf.len() < 64 || &elf[0..4] != b"\x7fELF" {
        return Err(bad("no ELF magic"));
    }
    if elf[4] != 2 || elf[5] != 1 {
        return Err(bad("not little-endian ELF64"));
    }
    let shoff = u64at(elf, 40).ok_or_else(|| bad("truncated header"))? as usize;
    let shentsize = u16at(elf, 58).ok_or_else(|| bad("truncated header"))? as usize;
    let shnum = u16at(elf, 60).ok_or_else(|| bad("truncated header"))? as usize;
    let shstrndx = u16at(elf, 62).ok_or_else(|| bad("truncated header"))? as usize;
    if shentsize != SHDR_LEN || shnum == 0 || shstrndx >= shnum {
        return Err(bad("no readable section table"));
    }

    let header = |index: usize| -> Result<(u32, u32, u64, u64, u64), ProgramManifestError> {
        // `shoff` is `e_shoff`, an attacker-controlled u64: the whole
        // `at .. at + SHDR_LEN` range must be checked without any add that can
        // wrap, or a huge `e_shoff` slips a wildly out-of-range `at` past the
        // bound and the reads below fault. Both the multiply-add and the
        // window end go through `checked_add`.
        let at = shoff
            .checked_add(index * SHDR_LEN)
            .filter(|at| at.checked_add(SHDR_LEN).is_some_and(|end| end <= elf.len()))
            .ok_or_else(|| bad("a section header is out of bounds"))?;
        // The filter proved `at + SHDR_LEN <= elf.len()`, so every read below
        // is in bounds; the fallible reads keep that a property of the code
        // rather than of a comment, so a future change to the filter cannot
        // reintroduce a panic.
        let oob = || bad("a section header is out of bounds");
        Ok((
            u32at(elf, at).ok_or_else(oob)?,      // name offset
            u32at(elf, at + 4).ok_or_else(oob)?,  // type
            u64at(elf, at + 8).ok_or_else(oob)?,  // flags
            u64at(elf, at + 24).ok_or_else(oob)?, // offset
            u64at(elf, at + 32).ok_or_else(oob)?, // size
        ))
    };

    // The section-name string table, bounded like every other read.
    let (_, names_kind, _, names_off, names_len) = header(shstrndx)?;
    let names = if names_kind == SHT_NOBITS {
        &[][..]
    } else {
        let start = names_off as usize;
        let end = start
            .checked_add(names_len as usize)
            .ok_or_else(|| bad("the name table overflows"))?;
        elf.get(start..end)
            .ok_or_else(|| bad("the name table is out of bounds"))?
    };

    let mut out = Sections {
        manifest: None,
        stream: false,
    };
    for index in 0..shnum {
        let (name_offset, kind, flags, offset, size) = header(index)?;
        let Some(name) = cstr(names, name_offset as usize) else {
            continue;
        };
        match name {
            SECTION_INIT => return Err(ProgramManifestError::ExecutableDeclaration),
            SECTION_STREAM => out.stream = true,
            SECTION_MANIFEST => {
                if out.manifest.is_some() {
                    return Err(ProgramManifestError::Duplicate);
                }
                if flags & SHF_EXECINSTR != 0 {
                    return Err(ProgramManifestError::Executable);
                }
                // Bounded before it is copied: an oversized section must not
                // cost an allocation on its way to being refused.
                if size as usize > synch_core::MAX_SOCKET_MANIFEST_BYTES {
                    return Err(ProgramManifestError::Manifest(ManifestError::TooLarge {
                        size: size as usize,
                    }));
                }
                let data = if kind == SHT_NOBITS || size == 0 {
                    Vec::new()
                } else {
                    let start = offset as usize;
                    let end = start
                        .checked_add(size as usize)
                        .ok_or_else(|| bad("the manifest section overflows"))?;
                    elf.get(start..end)
                        .ok_or_else(|| bad("the manifest section is out of bounds"))?
                        .to_vec()
                };
                out.manifest = Some(data);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn cstr(data: &[u8], at: usize) -> Option<&str> {
    let rest = data.get(at..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

fn u16at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn u32at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn u64at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal ELF64 object with the given `(name, flags, bytes)`
    /// sections, laid out the way the loader and this walk both read it.
    fn elf_with(sections: &[(&str, u64, &[u8])]) -> Vec<u8> {
        // Section 0 is the null section; the last is `.shstrtab`.
        let mut names = vec![0u8];
        let mut name_offsets = Vec::new();
        for (name, _, _) in sections {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        let shstrtab_name = names.len() as u32;
        names.extend_from_slice(b".shstrtab\0");

        let mut out = vec![0u8; 64];
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELF64
        out[5] = 1; // little-endian
        out[18..20].copy_from_slice(&247u16.to_le_bytes()); // EM_BPF

        let mut offsets = Vec::new();
        for (_, _, data) in sections {
            offsets.push(out.len() as u64);
            out.extend_from_slice(data);
        }
        let names_offset = out.len() as u64;
        out.extend_from_slice(&names);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }

        let shoff = out.len() as u64;
        let shnum = sections.len() as u16 + 2;
        let mut header = |name: u32, kind: u32, flags: u64, offset: u64, size: u64| {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes()); // addr
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // link
            out.extend_from_slice(&0u32.to_le_bytes()); // info
            out.extend_from_slice(&1u64.to_le_bytes()); // align
            out.extend_from_slice(&0u64.to_le_bytes()); // entsize
        };
        header(0, 0, 0, 0, 0);
        for (index, (_, flags, data)) in sections.iter().enumerate() {
            header(
                name_offsets[index],
                1,
                *flags,
                offsets[index],
                data.len() as u64,
            );
        }
        header(shstrtab_name, 3, 0, names_offset, names.len() as u64);

        out[40..48].copy_from_slice(&shoff.to_le_bytes());
        out[58..60].copy_from_slice(&(SHDR_LEN as u16).to_le_bytes());
        out[60..62].copy_from_slice(&shnum.to_le_bytes());
        out[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());
        out
    }

    #[test]
    fn a_manifest_section_is_read_and_its_absence_declares_nothing() {
        let manifest = br#"{"manifest": 1, "name": "gate", "egress": ["git.internal:9418"]}"#;
        let elf = elf_with(&[
            (
                "synchronicity.stream",
                0x6,
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("synchronicity.manifest", 0x2, manifest),
        ]);
        let declared = manifest_declaration(&elf).unwrap();
        assert_eq!(declared.name, "gate");
        assert_eq!(declared.egress, vec!["git.internal:9418".to_string()]);
        assert!(has_stream_section(&elf));

        let bare = elf_with(&[(
            "synchronicity.stream",
            0x6,
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        )]);
        assert_eq!(
            manifest_declaration(&bare).unwrap(),
            Declaration::default(),
            "no manifest section is the empty declaration, which grants nothing"
        );
    }

    #[test]
    fn the_forbidden_shapes_are_refused_by_name() {
        let manifest = br#"{"manifest": 1}"#;
        // An executable declaration section, whatever else the object carries.
        let with_init = elf_with(&[
            (
                "synchronicity.init",
                0x6,
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
            ("synchronicity.manifest", 0x2, manifest),
        ]);
        assert!(matches!(
            manifest_declaration(&with_init),
            Err(ProgramManifestError::ExecutableDeclaration)
        ));

        // A manifest marked executable is code wearing a data section's name.
        let executable = elf_with(&[("synchronicity.manifest", 0x6, manifest)]);
        assert!(matches!(
            manifest_declaration(&executable),
            Err(ProgramManifestError::Executable)
        ));

        // Two manifests are two claims, and neither wins.
        let duplicated = elf_with(&[
            ("synchronicity.manifest", 0x2, manifest),
            ("synchronicity.manifest", 0x2, manifest),
        ]);
        assert!(matches!(
            manifest_declaration(&duplicated),
            Err(ProgramManifestError::Duplicate)
        ));

        // Not an ELF at all.
        assert!(matches!(
            manifest_declaration(b"\x7fELF but truncated"),
            Err(ProgramManifestError::NotElf(_))
        ));

        // A section past the bound is refused before it is copied.
        let huge = vec![b' '; synch_core::MAX_SOCKET_MANIFEST_BYTES + 1];
        let oversized = elf_with(&[("synchronicity.manifest", 0x2, &huge)]);
        assert!(matches!(
            manifest_declaration(&oversized),
            Err(ProgramManifestError::Manifest(
                synch_core::ManifestError::TooLarge { .. }
            ))
        ));

        // A present-but-garbled manifest is an error, never "declares nothing".
        let garbled = elf_with(&[("synchronicity.manifest", 0x2, b"{ not json")]);
        assert!(matches!(
            manifest_declaration(&garbled),
            Err(ProgramManifestError::Manifest(_))
        ));
    }

    #[test]
    fn a_wraparound_section_offset_is_a_refusal_not_a_panic() {
        // `e_shoff` is attacker-controlled: a value near `u64::MAX` makes
        // `at + SHDR_LEN` wrap to a small in-range number if the window end is
        // added unchecked, slipping an out-of-range `at` past the bound. The
        // bytes reach this walk straight off disk (`synch socket inspect`) and
        // off the wire (admission of adopted or S3-written content), so a
        // panic here is a reachable DoS and a broken refusal contract.
        let mut object = vec![0u8; 64];
        object[0..4].copy_from_slice(b"\x7fELF");
        object[4] = 2; // ELF64
        object[5] = 1; // little-endian
        object[40..48].copy_from_slice(&0xFFFF_FFFF_FFFF_FFF0u64.to_le_bytes()); // e_shoff
        object[58..60].copy_from_slice(&(SHDR_LEN as u16).to_le_bytes()); // e_shentsize
        object[60..62].copy_from_slice(&1u16.to_le_bytes()); // e_shnum
        object[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert!(matches!(
            manifest_declaration(&object),
            Err(ProgramManifestError::NotElf(_))
        ));
        assert!(!has_stream_section(&object));
    }
}
