// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OS-agnostic parser for the Go runtime line table (`gopclntab`).
//!
//! The `gopclntab` blob is a Go *runtime* structure and is identical across
//! operating systems and object formats (ELF/PE/Mach-O). This module therefore
//! deals only in raw bytes: the caller is responsible for locating the blob
//! (e.g. the ELF `.gopclntab` section, or the PE `runtime.pclntab` symbol
//! range) and for supplying the `text_start` virtual address. The returned
//! function entry/end values are virtual addresses in the same space as the
//! object file's symbol values, so callers can translate them exactly like an
//! ELF symbol's `st_value`.
//!
//! Only the modern table layouts are supported: Go 1.18/1.19 (`ver118`,
//! magic `0xfffffff0`) and Go 1.20+ (`ver120`, magic `0xfffffff1`). These share
//! an identical on-disk layout and differ only by magic; one parser serves
//! every Go release from 1.18 through current. Any other / older / unknown
//! magic causes [`GoPclnTab::parse`] to return `None` so the caller can fall
//! back to ELF/PE symbol tables — it never panics.
//!
//! The field math mirrors Go's own `debug/gosym` package.

use tracing::debug;

/// Magic for the Go 1.18/1.19 pclntab layout.
const MAGIC_GO118: u32 = 0xfffffff0;
/// Magic for the Go 1.20+ pclntab layout.
const MAGIC_GO120: u32 = 0xfffffff1;

/// A parsed Go line table, retaining the raw blob for lazy name lookups.
pub(crate) struct GoPclnTab {
    data: Vec<u8>,
    little_endian: bool,
    text_start: u64,
    /// Number of functions in the table (the functab has `nfunc + 1` entries).
    nfunc: usize,
    /// Offset within `data` of the function-name string table.
    funcname_off: usize,
    /// Offset within `data` of the functab (PC, funcoff pairs) and func structs.
    functab_off: usize,
}

impl GoPclnTab {
    /// Attempts to parse `data` as a supported (Go 1.18+) pclntab.
    ///
    /// `text_start` is the virtual address of the runtime text (the `.text`
    /// section address). Returns `None` for any unsupported magic or malformed
    /// header rather than panicking, so callers can fall back gracefully.
    pub(crate) fn parse(
        data: Vec<u8>,
        text_start: u64) -> Option<GoPclnTab> {
        // Need at least the fixed 8-byte header prefix.
        if data.len() < 8 {
            return None;
        }

        // Detect magic + endianness.
        let le_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let be_magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        let little_endian = match (le_magic, be_magic) {
            (MAGIC_GO118, _) | (MAGIC_GO120, _) => true,
            (_, MAGIC_GO118) | (_, MAGIC_GO120) => false,
            _ => {
                debug!("gopclntab: unsupported magic le={:#x} be={:#x}", le_magic, be_magic);
                return None;
            }
        };

        // Bytes 4 and 5 must be zero in a valid header.
        if data[4] != 0 || data[5] != 0 {
            return None;
        }

        let _min_lc = data[6];
        let ptr_size = data[7] as usize;
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }

        // Header words are ptr_size-wide integers starting at offset 8.
        // word 0 = nfunc, word 2 = textStart, word 3 = funcnameOffset,
        // word 7 = pclnOffset (functab + func structs).
        let read_word = |w: usize| -> Option<u64> {
            let pos = 8 + w * ptr_size;
            read_uint(&data, pos, ptr_size, little_endian)
        };

        let nfunc = read_word(0)? as usize;
        let funcname_off = read_word(3)? as usize;
        let functab_off = read_word(7)? as usize;

        // Sanity-check offsets are within the blob.
        if funcname_off >= data.len() || functab_off >= data.len() {
            return None;
        }

        // The functab holds (nfunc + 1) pairs of 4-byte fields (Go 1.18+).
        let functab_bytes = (nfunc + 1)
            .checked_mul(2)?
            .checked_mul(FUNCTAB_FIELD_SIZE)?;
        if functab_off.checked_add(functab_bytes)? > data.len() {
            return None;
        }

        Some(GoPclnTab {
            data,
            little_endian,
            text_start,
            nfunc,
            funcname_off,
            functab_off,
        })
    }

    /// Number of functions described by the table.
    pub(crate) fn len(&self) -> usize {
        self.nfunc
    }

    /// Returns true if the table describes no functions.
    pub(crate) fn is_empty(&self) -> bool {
        self.nfunc == 0
    }

    /// Returns the `i`th function as `(start_va, end_va, name)`.
    ///
    /// `start_va`/`end_va` are virtual addresses (text_start relative). `end_va`
    /// is the entry of the next function (the functab's trailing sentinel for
    /// the final function), matching how Go derives function extents. Returns
    /// `None` if `i` is out of range or the entry is malformed.
    pub(crate) fn func(&self, i: usize) -> Option<(u64, u64, &str)> {
        if i >= self.nfunc {
            return None;
        }

        let entry_off = self.functab_field(2 * i)?;
        let next_off = self.functab_field(2 * (i + 1))?;
        let func_off = self.functab_field(2 * i + 1)? as usize;

        let start = self.text_start.checked_add(entry_off)?;
        let end = self.text_start.checked_add(next_off)?;

        // The _func struct lives at functab_off + func_off. For Go 1.18+ the
        // first field is a uint32 entry offset, so nameoff (field 1) is the
        // uint32 at _func + 4.
        let func_struct = self.functab_off.checked_add(func_off)?;
        let name_off = read_u32(&self.data, func_struct.checked_add(4)?, self.little_endian)? as usize;

        let name = self.name_at(self.funcname_off.checked_add(name_off)?)?;

        Some((start, end, name))
    }

    /// Reads functab field `idx` (a 4-byte value), adding `text_start` is left
    /// to the caller. Returns the raw offset value.
    fn functab_field(&self, idx: usize) -> Option<u64> {
        let pos = self.functab_off.checked_add(idx.checked_mul(FUNCTAB_FIELD_SIZE)?)?;
        read_u32(&self.data, pos, self.little_endian).map(|v| v as u64)
    }

    /// Returns the NUL-terminated UTF-8 string starting at `off` within `data`.
    fn name_at(&self, off: usize) -> Option<&str> {
        let bytes = self.data.get(off..)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).ok()
    }
}

/// Functab field width for Go 1.18+ layouts (uint32 offsets).
const FUNCTAB_FIELD_SIZE: usize = 4;

/// Reads a `size`-byte unsigned integer (4 or 8) at `pos`.
fn read_uint(
    data: &[u8],
    pos: usize,
    size: usize,
    little_endian: bool) -> Option<u64> {
    match size {
        4 => read_u32(data, pos, little_endian).map(|v| v as u64),
        8 => read_u64(data, pos, little_endian),
        _ => None,
    }
}

fn read_u32(
    data: &[u8],
    pos: usize,
    little_endian: bool) -> Option<u32> {
    let b = data.get(pos..pos + 4)?;
    let arr = [b[0], b[1], b[2], b[3]];
    Some(if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    })
}

fn read_u64(
    data: &[u8],
    pos: usize,
    little_endian: bool) -> Option<u64> {
    let b = data.get(pos..pos + 8)?;
    let arr = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
    Some(if little_endian {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but valid Go 1.18+ pclntab for the given functions.
    /// Each function is `(entry_offset, name)`; the table is laid out as:
    ///   [header][funcname table][functab + func structs]
    fn build_pclntab(
        magic: u32,
        ptr_size: usize,
        little_endian: bool,
        text_start: u64,
        funcs: &[(u32, &str)],
        sentinel_end: u32) -> Vec<u8> {
        let put_uint = |buf: &mut Vec<u8>, v: u64| {
            if ptr_size == 8 {
                if little_endian { buf.extend_from_slice(&v.to_le_bytes()); }
                else { buf.extend_from_slice(&v.to_be_bytes()); }
            } else {
                let v = v as u32;
                if little_endian { buf.extend_from_slice(&v.to_le_bytes()); }
                else { buf.extend_from_slice(&v.to_be_bytes()); }
            }
        };
        let put_u32 = |buf: &mut Vec<u8>, v: u32| {
            if little_endian { buf.extend_from_slice(&v.to_le_bytes()); }
            else { buf.extend_from_slice(&v.to_be_bytes()); }
        };

        let nfunc = funcs.len();

        // Build the funcname string table; record each name's offset.
        let mut funcname_tab: Vec<u8> = Vec::new();
        let mut name_offsets: Vec<u32> = Vec::new();
        for (_, name) in funcs {
            name_offsets.push(funcname_tab.len() as u32);
            funcname_tab.extend_from_slice(name.as_bytes());
            funcname_tab.push(0);
        }

        // Layout offsets within the final blob.
        let header_len = 8 + 8 * ptr_size; // 8 header words is plenty.
        let funcname_off = header_len;
        let functab_off = funcname_off + funcname_tab.len();

        // functab: (nfunc + 1) pairs of (entryoff, funcoff). The func structs
        // are placed after the functab; funcoff is relative to functab_off.
        let functab_entries = (nfunc + 1) * 2;
        let functab_len = functab_entries * FUNCTAB_FIELD_SIZE;
        // Each func struct: uint32 entryoff (field 0) + uint32 nameoff (field 1).
        let func_struct_size = 8;

        let mut functab: Vec<u8> = Vec::new();
        // First emit the func structs region after the functab, computing
        // their offsets relative to functab_off.
        let mut func_offs: Vec<u32> = Vec::new();
        for idx in 0..nfunc {
            func_offs.push((functab_len + idx * func_struct_size) as u32);
        }

        // Emit functab pairs.
        for idx in 0..nfunc {
            put_u32(&mut functab, funcs[idx].0); // entryoff
            put_u32(&mut functab, func_offs[idx]); // funcoff
        }
        // Trailing sentinel pair: max pc, dummy funcoff.
        put_u32(&mut functab, sentinel_end);
        put_u32(&mut functab, 0);

        // Emit func structs.
        for idx in 0..nfunc {
            put_u32(&mut functab, funcs[idx].0); // field 0: entry offset
            put_u32(&mut functab, name_offsets[idx]); // field 1: name offset
        }

        // Assemble header.
        let mut buf: Vec<u8> = Vec::new();
        if little_endian { buf.extend_from_slice(&magic.to_le_bytes()); }
        else { buf.extend_from_slice(&magic.to_be_bytes()); }
        buf.push(0); // pad1
        buf.push(0); // pad2
        buf.push(1); // minLC
        buf.push(ptr_size as u8);
        // header words 0..8
        put_uint(&mut buf, nfunc as u64);      // word 0: nfunc
        put_uint(&mut buf, 0);                 // word 1: nfiles
        put_uint(&mut buf, text_start);        // word 2: textStart
        put_uint(&mut buf, funcname_off as u64); // word 3: funcnameOffset
        put_uint(&mut buf, 0);                 // word 4: cuOffset
        put_uint(&mut buf, 0);                 // word 5: filetabOffset
        put_uint(&mut buf, 0);                 // word 6: pctabOffset
        put_uint(&mut buf, functab_off as u64);  // word 7: pclnOffset

        debug_assert_eq!(buf.len(), header_len);

        buf.extend_from_slice(&funcname_tab);
        buf.extend_from_slice(&functab);
        buf
    }

    #[test]
    fn parses_go120_le_64() {
        let text = 0x400000u64;
        let funcs = [(0x1000u32, "main.main"), (0x1100u32, "runtime.mcall")];
        let blob = build_pclntab(MAGIC_GO120, 8, true, text, &funcs, 0x1200);

        let tab = GoPclnTab::parse(blob, text).expect("should parse");
        assert_eq!(tab.len(), 2);

        let (s0, e0, n0) = tab.func(0).unwrap();
        assert_eq!(s0, text + 0x1000);
        assert_eq!(e0, text + 0x1100);
        assert_eq!(n0, "main.main");

        let (s1, e1, n1) = tab.func(1).unwrap();
        assert_eq!(s1, text + 0x1100);
        assert_eq!(e1, text + 0x1200);
        assert_eq!(n1, "runtime.mcall");

        assert!(tab.func(2).is_none());
    }

    #[test]
    fn parses_go118_magic() {
        let text = 0x10000u64;
        let funcs = [(0u32, "foo.Bar")];
        let blob = build_pclntab(MAGIC_GO118, 8, true, text, &funcs, 0x40);
        let tab = GoPclnTab::parse(blob, text).expect("should parse");
        let (s, e, n) = tab.func(0).unwrap();
        assert_eq!(s, text);
        assert_eq!(e, text + 0x40);
        assert_eq!(n, "foo.Bar");
    }

    #[test]
    fn parses_big_endian() {
        let text = 0x80000u64;
        let funcs = [(0x10u32, "pkg.fn")];
        let blob = build_pclntab(MAGIC_GO120, 8, false, text, &funcs, 0x20);
        let tab = GoPclnTab::parse(blob, text).expect("should parse BE");
        let (_, _, n) = tab.func(0).unwrap();
        assert_eq!(n, "pkg.fn");
    }

    #[test]
    fn preserves_unicode_middle_dot() {
        // Older-style anonymous names embed U+00B7 (·); must be preserved.
        let text = 0x1000u64;
        let name = "type:.eq.runtime\u{00b7}foo";
        let funcs = [(0u32, name)];
        let blob = build_pclntab(MAGIC_GO120, 8, true, text, &funcs, 0x10);
        let tab = GoPclnTab::parse(blob, text).unwrap();
        let (_, _, n) = tab.func(0).unwrap();
        assert_eq!(n, name);
    }

    #[test]
    fn rejects_unsupported_magic() {
        // go1.16 magic (0xfffffffa) is intentionally unsupported.
        let blob = build_pclntab(0xfffffffa, 8, true, 0x1000, &[(0u32, "x")], 0x10);
        assert!(GoPclnTab::parse(blob, 0x1000).is_none());
    }

    #[test]
    fn rejects_short_and_malformed() {
        assert!(GoPclnTab::parse(vec![0u8; 4], 0).is_none());
        // Valid magic but non-zero pad bytes.
        let mut blob = MAGIC_GO120.to_le_bytes().to_vec();
        blob.extend_from_slice(&[1, 0, 1, 8]);
        blob.extend_from_slice(&[0u8; 64]);
        assert!(GoPclnTab::parse(blob, 0).is_none());
    }

    #[test]
    fn rejects_bad_ptr_size() {
        let mut blob = MAGIC_GO120.to_le_bytes().to_vec();
        blob.extend_from_slice(&[0, 0, 1, 7]); // ptr_size = 7 invalid
        blob.extend_from_slice(&[0u8; 64]);
        assert!(GoPclnTab::parse(blob, 0).is_none());
    }

    // ----- Committed-fixture integration tests (no network) -----

    /// Path to a checked-in Go test fixture under test/assets/go/.
    #[cfg(target_os = "linux")]
    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::env::current_dir().unwrap().join("../test/assets/go").join(name)
    }

    /// The `.gopclntab` section path: a Go binary built with `-ldflags "-s -w"`
    /// (symbol table stripped, line table retained) — the kubelet-like case.
    #[test]
    #[cfg(target_os = "linux")]
    fn fixture_section_path() {
        use std::fs::File;
        use std::io::BufReader;

        let path = fixture_path("pclntab_stripped_symbols");
        let file = File::open(&path).expect("open fixture");
        let mut reader = BufReader::new(file);

        let (data, text) = crate::ruwind::elf::read_go_pclntab(&mut reader)
            .expect("fixture has a .gopclntab section");
        let tab = GoPclnTab::parse(data, text).expect("parse fixture pclntab");

        assert!(tab.len() > 100, "expected many funcs, got {}", tab.len());

        let mut found_main = false;
        let mut found_mcall = false;
        for i in 0..tab.len() {
            let (s, e, n) = tab.func(i).unwrap();
            assert!(s <= e);
            match n {
                "main.main" => found_main = true,
                "runtime.mcall" => found_mcall = true,
                _ => {}
            }
        }
        assert!(found_main, "main.main should resolve");
        assert!(found_mcall, "runtime.mcall should resolve");
    }

    /// The recovery path: the same binary with its `.gopclntab` section header
    /// renamed so the section lookup fails (the data remains in the segment) —
    /// the containerd-like stripped-section case.
    #[test]
    #[cfg(target_os = "linux")]
    fn fixture_recovery_path() {
        use std::fs::File;
        use std::io::BufReader;

        let path = fixture_path("pclntab_section_stripped");
        let file = File::open(&path).expect("open fixture");
        let mut reader = BufReader::new(file);

        // The section lookup must fail (the header was renamed)...
        assert!(
            crate::ruwind::elf::read_go_pclntab(&mut reader).is_none(),
            "section lookup should fail for the recovery fixture");

        // ...but the build-info marker remains and recovery succeeds.
        assert!(crate::ruwind::elf::has_go_build_info(&mut reader));

        let (data, text) = crate::ruwind::elf::recover_go_pclntab(&mut reader)
            .expect("recovery should find the stripped line table");
        let tab = GoPclnTab::parse(data, text).expect("parse recovered pclntab");

        assert!(tab.len() > 100, "expected many funcs, got {}", tab.len());
        let mut found_main = false;
        for i in 0..tab.len() {
            let (_, _, n) = tab.func(i).unwrap();
            if n == "main.main" {
                found_main = true;
                break;
            }
        }
        assert!(found_main, "main.main should resolve via recovery");
    }

    /// Integration check against a real Go binary. Ignored by default; run with:    ///   GO_PCLNTAB_BIN=/path/to/bin GO_PCLNTAB_MIN=69763 \
    ///     cargo test --lib real_binary -- --ignored --nocapture
    #[test]
    #[ignore]
    fn real_binary() {
        use std::fs::File;
        use std::io::BufReader;

        let path = std::env::var("GO_PCLNTAB_BIN")
            .expect("set GO_PCLNTAB_BIN");
        let min = std::env::var("GO_PCLNTAB_MIN")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);

        let file = File::open(&path).expect("open binary");
        let mut reader = BufReader::new(file);

        let (data, text) = crate::ruwind::elf::read_go_pclntab(&mut reader)
            .expect("should find .gopclntab");
        let tab = GoPclnTab::parse(data, text).expect("should parse pclntab");

        println!("{}: funcs={} text_start={:#x}", path, tab.len(), text);
        assert!(tab.len() >= min, "expected >= {} funcs, got {}", min, tab.len());

        // Spot-check a few well-known names resolve and look sane.
        let mut samples = 0;
        for i in 0..tab.len() {
            let (s, e, n) = tab.func(i).unwrap();
            assert!(s <= e, "func {} start {:#x} > end {:#x}", i, s, e);
            if n.contains("runtime.mcall") || n.contains("runtime.systemstack") || n == "main.main" {
                println!("  {:#x}-{:#x} {}", s, e, n);
                samples += 1;
            }
        }
        assert!(samples > 0, "expected to find some well-known runtime symbols");
    }

    /// Validates stripped-section recovery against a real binary whose
    /// `.gopclntab` section header has been removed (e.g. containerd). Ignored;
    /// run with:
    ///   GO_PCLNTAB_BIN=/path/to/stripped GO_PCLNTAB_MIN=51884 \
    ///     cargo test --lib recover_real_binary -- --ignored --nocapture
    #[test]
    #[ignore]
    fn recover_real_binary() {
        use std::fs::File;
        use std::io::BufReader;

        let path = std::env::var("GO_PCLNTAB_BIN").expect("set GO_PCLNTAB_BIN");
        let min = std::env::var("GO_PCLNTAB_MIN")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);

        let file = File::open(&path).expect("open binary");
        let mut reader = BufReader::new(file);

        assert!(
            crate::ruwind::elf::has_go_build_info(&mut reader),
            "binary should carry a Go build-info marker");

        let (data, text) = crate::ruwind::elf::recover_go_pclntab(&mut reader)
            .expect("should recover a stripped .gopclntab");
        let tab = GoPclnTab::parse(data, text).expect("recovered table should parse");

        println!("{}: recovered funcs={} text_start={:#x}", path, tab.len(), text);
        assert!(tab.len() >= min, "expected >= {} funcs, got {}", min, tab.len());

        // Names must be sane.
        let (_, _, n0) = tab.func(0).unwrap();
        assert!(!n0.is_empty());
    }

    /// Corpus-sweep dumper. Reads the binary at `GO_PCLNTAB_BIN`, resolves its
    /// pclntab exactly as `GoPclnTabSymbolReader` does (section first, then
    /// stripped-section recovery), and writes one `"<hexEntryVA>\t<name>"` line
    /// per function to `GO_PCLNTAB_OUT` (or stdout). The emitted entry addresses
    /// are absolute virtual addresses (text_start relative), directly comparable
    /// to `debug/gosym`'s `Func.Entry`, so an external diff can measure parity
    /// against the Go standard library oracle across a large binary corpus.
    /// Ignored by default; run with:
    ///   GO_PCLNTAB_BIN=/path/to/bin GO_PCLNTAB_OUT=/path/to/out.tsv \
    ///     cargo test --lib dump_pclntab -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dump_pclntab() {
        use std::fs::File;
        use std::io::{BufReader, BufWriter, Write};

        let path = std::env::var("GO_PCLNTAB_BIN").expect("set GO_PCLNTAB_BIN");
        let file = File::open(&path).expect("open binary");
        let mut reader = BufReader::new(file);

        // Same resolution order as GoPclnTabSymbolReader::new.
        let (data, text) = crate::ruwind::elf::read_go_pclntab(&mut reader)
            .or_else(|| crate::ruwind::elf::recover_go_pclntab(&mut reader))
            .expect("should find or recover a .gopclntab");
        let tab = GoPclnTab::parse(data, text).expect("should parse pclntab");

        let mut out: Box<dyn Write> = match std::env::var("GO_PCLNTAB_OUT") {
            Ok(p) => Box::new(BufWriter::new(File::create(p).expect("create out"))),
            Err(_) => Box::new(BufWriter::new(std::io::stdout())),
        };

        let mut n = 0usize;
        for i in 0..tab.len() {
            if let Some((start, _end, name)) = tab.func(i) {
                writeln!(out, "{:#x}\t{}", start, name).expect("write");
                n += 1;
            }
        }
        out.flush().expect("flush");
        eprintln!("dump_pclntab: {} funcs, text_start={:#x}", n, text);
    }
}
