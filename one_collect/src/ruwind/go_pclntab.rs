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
//! magic causes [`GoPclnTab::open`] to return `None` so the caller can fall
//! back to ELF/PE symbol tables — it never panics.
//!
//! The field math mirrors Go's own `debug/gosym` package.

use std::fs::File;
use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};

use tracing::debug;

/// Magic for the Go 1.18/1.19 pclntab layout.
const MAGIC_GO118: u32 = 0xfffffff0;
/// Magic for the Go 1.20+ pclntab layout.
const MAGIC_GO120: u32 = 0xfffffff1;

pub(crate) const GO_PCLNTAB_HEADER_MAX: usize = 8 + 8 * 8;
pub(crate) const GO_PCLNTAB_BUFFER_SIZE: usize = 64 * 1024;
pub(crate) const GO_PCLNTAB_METADATA_SIZE: usize = 128 * 1024;
pub(crate) const GO_SYMBOL_NAME_MAX: usize = 4 * 1024;

pub(crate) trait GoPclnTabRead: Read + Seek {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error>;

    fn read_name_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        self.read_exact_at(offset, output)
    }
}

impl<T: Read + Seek> GoPclnTabRead for &mut T {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        self.seek(SeekFrom::Start(offset))?;
        self.read_exact(output)
    }
}

impl GoPclnTabRead for Cursor<Vec<u8>> {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        let start = usize::try_from(offset)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "offset exceeds usize"))?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "read range overflow"))?;
        let input = self
            .get_ref()
            .get(start..end)
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "read past input"))?;
        output.copy_from_slice(input);
        Ok(())
    }
}

pub(crate) struct GoPclnTabFileReader {
    file: File,
    metadata: ReadWindow,
    names: ReadWindow,
}

impl GoPclnTabFileReader {
    pub(crate) fn new(file: File, table_offset: u64) -> Self {
        Self {
            file,
            metadata: ReadWindow::new(GO_PCLNTAB_METADATA_SIZE, table_offset, false),
            names: ReadWindow::new(GO_PCLNTAB_BUFFER_SIZE, table_offset, true),
        }
    }
}

impl Read for GoPclnTabFileReader {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.file.read(output)
    }
}

impl Seek for GoPclnTabFileReader {
    fn seek(&mut self, position: SeekFrom) -> Result<u64, Error> {
        self.file.seek(position)
    }
}

impl GoPclnTabRead for GoPclnTabFileReader {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        self.metadata.read(&self.file, offset, output)
    }

    fn read_name_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        self.names.read(&self.file, offset, output)
    }
}

struct ReadWindow {
    data: Box<[u8]>,
    base: u64,
    align: bool,
    start: u64,
    len: usize,
}

impl ReadWindow {
    fn new(capacity: usize, base: u64, align: bool) -> Self {
        Self {
            data: vec![0; capacity].into_boxed_slice(),
            base,
            align,
            start: 0,
            len: 0,
        }
    }

    fn read(&mut self, file: &File, mut offset: u64, mut output: &mut [u8]) -> Result<(), Error> {
        while !output.is_empty() {
            let window_end = self.start + self.len as u64;
            if offset < self.start || offset >= window_end {
                let capacity = self.data.len() as u64;
                self.start = if self.align {
                    let relative = offset
                        .checked_sub(self.base)
                        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "read before table"))?;
                    self.base + relative / capacity * capacity
                } else {
                    offset
                };
                self.len = 0;
                while self.len < self.data.len() {
                    let read = read_file_at(
                        file,
                        &mut self.data[self.len..],
                        self.start + self.len as u64,
                    )?;
                    if read == 0 {
                        break;
                    }
                    self.len += read;
                }
            }

            let start = usize::try_from(offset - self.start)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "offset exceeds usize"))?;
            let available = self
                .len
                .checked_sub(start)
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "positioned read"))?;
            let copy_len = available.min(output.len());
            if copy_len == 0 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "positioned read"));
            }
            output[..copy_len].copy_from_slice(&self.data[start..start + copy_len]);
            offset = offset
                .checked_add(copy_len as u64)
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "read range overflow"))?;
            output = &mut output[copy_len..];
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_file_at(file: &File, output: &mut [u8], offset: u64) -> Result<usize, Error> {
    std::os::unix::fs::FileExt::read_at(file, output, offset)
}

#[cfg(windows)]
fn read_file_at(file: &File, output: &mut [u8], offset: u64) -> Result<usize, Error> {
    std::os::windows::fs::FileExt::seek_read(file, output, offset)
}

#[derive(Clone, Copy)]
pub(crate) struct GoPclnTabLocation {
    file_offset: u64,
    max_len: u64,
    text_start: u64,
}

impl GoPclnTabLocation {
    pub(crate) fn new(file_offset: u64, max_len: u64, text_start: u64) -> Self {
        Self {
            file_offset,
            max_len,
            text_start,
        }
    }

    pub(crate) fn file_offset(&self) -> u64 {
        self.file_offset
    }

    pub(crate) fn max_len(&self) -> u64 {
        self.max_len
    }

    pub(crate) fn text_start(&self) -> u64 {
        self.text_start
    }
}

#[derive(Clone, Copy)]
struct GoPclnTabMetadata {
    little_endian: bool,
    text_start: u64,
    nfunc: usize,
    funcname_off: u64,
    functab_off: u64,
}

impl GoPclnTabMetadata {
    fn parse_header(data: &[u8], max_len: u64, text_start: u64) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let le_magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let be_magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let little_endian = match (le_magic, be_magic) {
            (MAGIC_GO118, _) | (MAGIC_GO120, _) => true,
            (_, MAGIC_GO118) | (_, MAGIC_GO120) => false,
            _ => return None,
        };

        if data[4] != 0 || data[5] != 0 {
            return None;
        }

        let ptr_size = data[7] as usize;
        if ptr_size != 4 && ptr_size != 8 {
            return None;
        }

        let read_word = |word: usize| -> Option<u64> {
            let pos = 8usize.checked_add(word.checked_mul(ptr_size)?)?;
            read_uint(data, pos, ptr_size, little_endian)
        };

        let nfunc = usize::try_from(read_word(0)?).ok()?;
        let funcname_off = read_word(3)?;
        let functab_off = read_word(7)?;

        if funcname_off >= max_len || functab_off >= max_len {
            return None;
        }

        let functab_bytes = u64::try_from(nfunc)
            .ok()?
            .checked_add(1)?
            .checked_mul(2)?
            .checked_mul(FUNCTAB_FIELD_SIZE as u64)?;
        if functab_off.checked_add(functab_bytes)? > max_len {
            return None;
        }

        Some(Self {
            little_endian,
            text_start,
            nfunc,
            funcname_off,
            functab_off,
        })
    }
}

/// Incremental Go line-table cursor over any seekable reader.
///
/// The reader supplies buffering. The cursor itself keeps only parsed header
/// metadata, sequential iteration state, and one bounded symbol-name buffer.
pub(crate) struct GoPclnTab<R: GoPclnTabRead> {
    reader: R,
    location: GoPclnTabLocation,
    metadata: GoPclnTabMetadata,
    index: usize,
    next_entry: Option<u64>,
    current_start: u64,
    current_end: u64,
    current_name: [u8; GO_SYMBOL_NAME_MAX],
    current_name_len: usize,
}

impl<R: GoPclnTabRead> GoPclnTab<R> {
    pub(crate) fn open(mut reader: R, location: GoPclnTabLocation) -> Option<Self> {
        let metadata = read_metadata(&mut reader, &location)?;
        Some(Self {
            reader,
            location,
            metadata,
            index: 0,
            next_entry: None,
            current_start: 0,
            current_end: 0,
            current_name: [0; GO_SYMBOL_NAME_MAX],
            current_name_len: 0,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.metadata.nfunc
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
        self.next_entry = None;
        self.current_name_len = 0;
    }

    pub(crate) fn next(&mut self) -> bool {
        while self.index < self.metadata.nfunc {
            let index = self.index;
            self.index += 1;
            if self.read_func(index, true) {
                return true;
            }
        }
        self.current_name_len = 0;
        false
    }

    pub(crate) fn start(&self) -> u64 {
        self.current_start
    }

    pub(crate) fn end(&self) -> u64 {
        self.current_end
    }

    pub(crate) fn name(&self) -> &str {
        std::str::from_utf8(&self.current_name[..self.current_name_len]).unwrap_or("")
    }

    fn read_func(&mut self, index: usize, sequential: bool) -> bool {
        if index >= self.metadata.nfunc {
            return false;
        }

        let entry_off = match if sequential {
            self.next_entry.take()
        } else {
            None
        } {
            Some(entry) => entry,
            None => match index
                .checked_mul(2)
                .and_then(|field| functab_field_offset(self.metadata.functab_off, field))
                .and_then(|offset| self.read_u32(offset))
            {
                Some(entry) => entry as u64,
                None => return false,
            },
        };
        let pair_offset = match index
            .checked_mul(2)
            .and_then(|field| field.checked_add(1))
            .and_then(|field| functab_field_offset(self.metadata.functab_off, field))
        {
            Some(offset) => offset,
            None => return false,
        };
        let (func_off, next_off) = match self.read_u32_pair(pair_offset) {
            Some(pair) => pair,
            None => return false,
        };
        let func_off = func_off as u64;
        let next_off = next_off as u64;
        if sequential {
            self.next_entry = Some(next_off);
        }

        let func_struct = match self.metadata.functab_off.checked_add(func_off) {
            Some(offset) => offset,
            None => return false,
        };
        let name_field = match func_struct.checked_add(4) {
            Some(offset) => offset,
            None => return false,
        };
        let name_off = match self.read_u32(name_field) {
            Some(offset) => offset as u64,
            None => return false,
        };

        let start = match self.metadata.text_start.checked_add(entry_off) {
            Some(start) => start,
            None => return false,
        };
        let end = match self.metadata.text_start.checked_add(next_off) {
            Some(end) => end,
            None => return false,
        };
        let name_offset = match self.metadata.funcname_off.checked_add(name_off) {
            Some(offset) => offset,
            None => return false,
        };
        if !self.read_name(name_offset) {
            return false;
        }
        self.current_start = start;
        self.current_end = end;
        true
    }

    fn read_u32(&mut self, relative_offset: u64) -> Option<u32> {
        let mut bytes = [0u8; 4];
        self.read_exact_at(relative_offset, &mut bytes)?;
        Some(if self.metadata.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn read_u32_pair(&mut self, relative_offset: u64) -> Option<(u32, u32)> {
        let mut bytes = [0u8; 8];
        self.read_exact_at(relative_offset, &mut bytes)?;
        Some(if self.metadata.little_endian {
            (
                u32::from_le_bytes(bytes[..4].try_into().ok()?),
                u32::from_le_bytes(bytes[4..].try_into().ok()?),
            )
        } else {
            (
                u32::from_be_bytes(bytes[..4].try_into().ok()?),
                u32::from_be_bytes(bytes[4..].try_into().ok()?),
            )
        })
    }

    fn read_name(&mut self, relative_offset: u64) -> bool {
        if relative_offset >= self.location.max_len {
            return false;
        }
        let max_len = usize::try_from(
            (self.location.max_len - relative_offset).min(GO_SYMBOL_NAME_MAX as u64),
        )
        .unwrap_or(0);
        if max_len == 0 {
            return false;
        }

        let mut name_len = 0;
        let mut buffer = [0u8; 256];
        while name_len < max_len {
            let read_len = buffer.len().min(max_len - name_len);
            let offset = match self
                .location
                .file_offset
                .checked_add(relative_offset)
                .and_then(|offset| offset.checked_add(name_len as u64))
            {
                Some(offset) => offset,
                None => return false,
            };
            if self
                .reader
                .read_name_exact_at(offset, &mut buffer[..read_len])
                .is_err()
            {
                return false;
            }
            if let Some(end) = buffer[..read_len].iter().position(|byte| *byte == 0) {
                self.current_name[name_len..name_len + end].copy_from_slice(&buffer[..end]);
                self.current_name_len = name_len + end;
                return std::str::from_utf8(&self.current_name[..self.current_name_len]).is_ok();
            }
            self.current_name[name_len..name_len + read_len].copy_from_slice(&buffer[..read_len]);
            name_len += read_len;
        }
        debug!(
            "gopclntab: symbol name exceeds {} bytes",
            GO_SYMBOL_NAME_MAX
        );
        false
    }

    fn read_exact_at(&mut self, relative_offset: u64, output: &mut [u8]) -> Option<()> {
        let len = u64::try_from(output.len()).ok()?;
        if relative_offset.checked_add(len)? > self.location.max_len {
            return None;
        }
        let absolute = self.location.file_offset.checked_add(relative_offset)?;
        self.reader.read_exact_at(absolute, output).ok()
    }

    #[cfg(test)]
    fn func(&mut self, index: usize) -> Option<(u64, u64, &str)> {
        self.read_func(index, false)
            .then(|| (self.current_start, self.current_end, self.name()))
    }
}

#[cfg(test)]
impl GoPclnTab<Cursor<Vec<u8>>> {
    fn parse(data: Vec<u8>, text_start: u64) -> Option<Self> {
        let len = data.len() as u64;
        Self::open(
            Cursor::new(data),
            GoPclnTabLocation::new(0, len, text_start),
        )
    }
}

fn read_metadata(
    reader: &mut (impl Read + Seek),
    location: &GoPclnTabLocation,
) -> Option<GoPclnTabMetadata> {
    let header_len = usize::try_from(location.max_len.min(GO_PCLNTAB_HEADER_MAX as u64)).ok()?;
    let mut header = [0u8; GO_PCLNTAB_HEADER_MAX];
    reader.seek(SeekFrom::Start(location.file_offset)).ok()?;
    reader.read_exact(&mut header[..header_len]).ok()?;
    GoPclnTabMetadata::parse_header(&header[..header_len], location.max_len, location.text_start)
}

pub(crate) fn validate_go_pclntab_location(
    reader: &mut (impl Read + Seek),
    location: &GoPclnTabLocation,
) -> bool {
    let mut tab = match GoPclnTab::open(reader, *location) {
        Some(tab) => tab,
        None => return false,
    };
    if tab.len() <= 16 {
        return false;
    }

    tab.read_func(0, false)
        && tab.current_end >= tab.current_start
        && tab.read_func(tab.len() - 1, false)
        && tab.current_end >= tab.current_start
}

fn functab_field_offset(functab_off: u64, field_index: usize) -> Option<u64> {
    functab_off.checked_add(
        u64::try_from(field_index)
            .ok()?
            .checked_mul(FUNCTAB_FIELD_SIZE as u64)?,
    )
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
    use std::io::Write;

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

        let mut tab = GoPclnTab::parse(blob, text).expect("should parse");
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
        let mut tab = GoPclnTab::parse(blob, text).expect("should parse");
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
        let mut tab = GoPclnTab::parse(blob, text).expect("should parse BE");
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
        let mut tab = GoPclnTab::parse(blob, text).unwrap();
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

    fn open_file_table(
        blob: &[u8],
        text_start: u64,
        suffix: &str,
    ) -> (GoPclnTab<GoPclnTabFileReader>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "one_collect_go_pclntab_{}_{}",
            std::process::id(),
            suffix
        ));
        let mut file = File::create(&path).expect("create temporary pclntab");
        file.write_all(blob).expect("write temporary pclntab");
        drop(file);

        let file = File::open(&path).expect("open temporary pclntab");
        let location = GoPclnTabLocation::new(0, blob.len() as u64, text_start);
        let tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("open file-backed pclntab");
        (tab, path)
    }

    #[test]
    fn file_reader_large_table_is_bounded() {
        const FUNCTION_COUNT: usize = 20_000;
        let text = 0x400000u64;
        let funcs: Vec<(u32, &str)> = (0..FUNCTION_COUNT)
            .map(|index| ((index as u32) * 16, "pkg.function"))
            .collect();
        let blob = build_pclntab(
            MAGIC_GO120,
            8,
            true,
            text,
            &funcs,
            (FUNCTION_COUNT as u32) * 16,
        );
        assert!(blob.len() > GO_PCLNTAB_BUFFER_SIZE * 3);

        let (mut tab, path) = open_file_table(&blob, text, "large");
        assert!(
            GO_PCLNTAB_BUFFER_SIZE + GO_PCLNTAB_METADATA_SIZE + GO_SYMBOL_NAME_MAX < 256 * 1024
        );
        for index in 0..FUNCTION_COUNT {
            let (start, end, name) = tab.func(index).expect("read function");
            assert_eq!(start, text + (index as u64) * 16);
            assert_eq!(end, start + 16);
            assert_eq!(name, "pkg.function");
        }

        std::fs::remove_file(path).expect("remove temporary pclntab");
    }

    #[test]
    fn file_reader_bounds_symbol_names() {
        let text = 0x400000u64;
        let accepted = "a".repeat(GO_SYMBOL_NAME_MAX - 1);
        let rejected = "b".repeat(GO_SYMBOL_NAME_MAX);

        for (suffix, name, should_read) in [
            ("max-name", accepted.as_str(), true),
            ("over-name", rejected.as_str(), false),
        ] {
            let funcs = [(0u32, name)];
            let blob = build_pclntab(MAGIC_GO120, 8, true, text, &funcs, 16);
            let (mut tab, path) = open_file_table(&blob, text, suffix);
            let result = tab.func(0);
            assert_eq!(result.is_some(), should_read);
            if should_read {
                assert_eq!(result.unwrap().2, name);
            }
            std::fs::remove_file(path).expect("remove temporary pclntab");
        }
    }

    #[test]
    fn file_reader_supports_endian_and_pointer_layouts() {
        let text = 0x400000u64;
        for (ptr_size, little_endian, suffix) in [
            (4usize, true, "le32"),
            (8usize, true, "le64"),
            (4usize, false, "be32"),
            (8usize, false, "be64"),
        ] {
            let funcs = [(0x10u32, "pkg.first"), (0x20u32, "pkg.second")];
            let blob = build_pclntab(MAGIC_GO120, ptr_size, little_endian, text, &funcs, 0x30);
            let (mut tab, path) = open_file_table(&blob, text, suffix);

            let first = tab.func(0).expect("read first function");
            assert_eq!(first, (text + 0x10, text + 0x20, "pkg.first"));

            let second = tab.func(1).expect("read second function");
            assert_eq!(second, (text + 0x20, text + 0x30, "pkg.second"));

            std::fs::remove_file(path).expect("remove temporary pclntab");
        }
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

        let path = fixture_path("pclntab_stripped_symbols");
        let mut file = File::open(&path).expect("open fixture");
        let location = crate::ruwind::elf::read_go_pclntab(&mut file)
            .expect("fixture has a .gopclntab section");
        let mut tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("parse fixture pclntab");

        assert!(tab.len() > 100, "expected many funcs, got {}", tab.len());

        let mut found_main = false;
        let mut found_mcall = false;
        for i in 0..tab.len() {
            let (s, e, name) = tab.func(i).unwrap();
            assert!(s <= e);
            match name {
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

        let path = fixture_path("pclntab_section_stripped");
        let mut file = File::open(&path).expect("open fixture");

        // The section lookup must fail (the header was renamed)...
        assert!(
            crate::ruwind::elf::read_go_pclntab(&mut file).is_none(),
            "section lookup should fail for the recovery fixture"
        );

        // ...but the build-info marker remains and recovery succeeds.
        assert!(crate::ruwind::elf::has_go_build_info(&mut file));

        let location = crate::ruwind::elf::recover_go_pclntab(&mut file)
            .expect("recovery should find the stripped line table");
        let split_chunk = (4096usize..8192)
            .find(|chunk| {
                let remainder = location.file_offset() % *chunk as u64;
                remainder >= (*chunk - 7) as u64
            })
            .expect("find a chunk size that splits the magic header");
        let split_location =
            crate::ruwind::elf::recover_go_pclntab_with_chunk(&mut file, split_chunk)
                .expect("recovery should find magic split across chunks");
        assert_eq!(split_location.file_offset(), location.file_offset());

        let mut tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("parse recovered pclntab");

        assert!(tab.len() > 100, "expected many funcs, got {}", tab.len());
        let mut found_main = false;
        for i in 0..tab.len() {
            let (_, _, name) = tab.func(i).unwrap();
            if name == "main.main" {
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

        let path = std::env::var("GO_PCLNTAB_BIN")
            .expect("set GO_PCLNTAB_BIN");
        let min = std::env::var("GO_PCLNTAB_MIN")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);

        let mut file = File::open(&path).expect("open binary");
        let location =
            crate::ruwind::elf::read_go_pclntab(&mut file).expect("should find .gopclntab");
        let text = location.text_start();
        let mut tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("should parse pclntab");

        println!("{}: funcs={} text_start={:#x}", path, tab.len(), text);
        assert!(
            tab.len() >= min,
            "expected >= {} funcs, got {}",
            min,
            tab.len()
        );

        // Spot-check a few well-known names resolve and look sane.
        let mut samples = 0;
        for i in 0..tab.len() {
            let (s, e, n) = tab.func(i).unwrap();
            assert!(s <= e, "func {} start {:#x} > end {:#x}", i, s, e);
            if n.contains("runtime.mcall") || n.contains("runtime.systemstack") || n == "main.main"
            {
                println!("  {:#x}-{:#x} {}", s, e, n);
                samples += 1;
            }
        }
        assert!(
            samples > 0,
            "expected to find some well-known runtime symbols"
        );
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

        let path = std::env::var("GO_PCLNTAB_BIN").expect("set GO_PCLNTAB_BIN");
        let min = std::env::var("GO_PCLNTAB_MIN")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1);

        let mut file = File::open(&path).expect("open binary");

        assert!(
            crate::ruwind::elf::has_go_build_info(&mut file),
            "binary should carry a Go build-info marker"
        );

        let location = crate::ruwind::elf::recover_go_pclntab(&mut file)
            .expect("should recover a stripped .gopclntab");
        let text = location.text_start();
        let mut tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("recovered table should parse");

        println!(
            "{}: recovered funcs={} text_start={:#x}",
            path,
            tab.len(),
            text
        );
        assert!(
            tab.len() >= min,
            "expected >= {} funcs, got {}",
            min,
            tab.len()
        );

        // Names must be sane.
        let (_, _, name) = tab.func(0).unwrap();
        assert!(!name.is_empty());
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
        use std::io::{BufWriter, Write};

        let path = std::env::var("GO_PCLNTAB_BIN").expect("set GO_PCLNTAB_BIN");
        let mut file = File::open(&path).expect("open binary");

        // Same resolution order as GoPclnTabSymbolReader::new.
        let location = crate::ruwind::elf::read_go_pclntab(&mut file)
            .or_else(|| crate::ruwind::elf::recover_go_pclntab(&mut file))
            .expect("should find or recover a .gopclntab");
        let text = location.text_start();
        let mut tab = GoPclnTab::open(
            GoPclnTabFileReader::new(file, location.file_offset()),
            location,
        )
        .expect("should parse pclntab");

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
