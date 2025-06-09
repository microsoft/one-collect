// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Read, Seek, SeekFrom};
use std::fmt;

use crate::elf::*;

const VALUE_TYPE_OFFSET: u8 = 0;
const VALUE_TYPE_REG: u8 = 1;
const VALUE_TYPE_UNDEFINED: u8 = 2;
const VALUE_TYPE_EXPRESSION: u8 = 3;
const VALUE_TYPE_RESTORE: u8 = 4;

pub struct UnwindCFA {
    pub reg: u8,
    pub off: i16,
    pub off_mask: u64,
}

impl UnwindCFA {
    pub fn new() -> Self {
        Self {
            reg: 0,
            off: 0,
            off_mask: 0,
        }
    }
}

impl Default for UnwindCFA {
    fn default() -> Self {
        Self::new()
    }
}

struct RegState {
    reg: u8,
    val_type: u8,
    val: i16,
}

struct CFAState {
    cfa_reg: u8,
    cfa_off: i16,
}

struct FrameState {
    rva: u64,
    cfa_reg: u8,
    cfa_off: i16,
    reg_states: Vec<RegState>,
}

impl FrameState {
    fn new(
        rva: u64,
        cfa_reg: u8,
        cfa_off: i16) -> Self {
        Self {
            rva,
            cfa_reg,
            cfa_off,
            reg_states: Vec::new(),
        }
    }

    fn set_cfa_reg(
        &mut self,
        reg: i64) -> Result<(), Error> {
        if reg > u8::MAX.into() {
           return Err(
            error("Reg out of range"));
        }

        self.cfa_reg = reg as u8;

        Ok(())
    }

    fn set_cfa_offset(
        &mut self,
        off: i64) -> Result<(), Error> {
        if off > i16::MAX.into() ||
           off < i16::MIN.into() {
           return Err(
            error("Offset out of range"));
        }

        self.cfa_off = off as i16;

        Ok(())
    }

    fn add_reg_value(
        &mut self,
        reg: i64,
        val: i64,
        val_type: u8) -> Result<(), Error> {
        if reg > u8::MAX.into() ||
           val > i16::MAX.into() ||
           val < i16::MIN.into() {
           return Err(
            error("Reg/Value out of range"));
        }

        self.reg_states.push(
            RegState {
                reg: reg as u8,
                val_type,
                val: val as i16,
            });

        Ok(())
    }
}

impl fmt::Debug for FrameState {
    fn fmt(
        &self,
        f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RVA: 0x{:X}", self.rva)?;
        write!(f, "CFA: Reg{}@{}", self.cfa_reg, self.cfa_off)?;
        for state in &self.reg_states {
            match state.val_type {
                VALUE_TYPE_OFFSET => {
                    write!(f, "REG{}: CFA@{}", state.reg, state.val)?;
                },
                VALUE_TYPE_REG => {
                    write!(f, "REG{}: REG{}", state.reg, state.val)?;
                },
                VALUE_TYPE_UNDEFINED => {
                    write!(f, "REG{}: undefined", state.reg)?;
                },
                VALUE_TYPE_EXPRESSION => {
                    write!(f, "REG{}: expression", state.reg)?;
                },
                VALUE_TYPE_RESTORE => {
                    write!(f, "REG{}: restore to CIE", state.reg)?;
                },
                /* Default */
                _ => {},
            }
        }

        Ok(())
    }
}

struct FrameOptions {
    enc: u8,
    code_align: i16,
    data_align: i16,
    has_aug_data: bool,
    cfa_stack: Vec<CFAState>,
}

impl FrameOptions {
    fn new() -> Self {
        Self {
            enc: DW_EH_PE_UDATA8 |
                 DW_EH_PE_ABSPTR,
            code_align: 0,
            data_align: 0,
            has_aug_data: false,
            cfa_stack: Vec::new(),
        }
    }
}

pub struct FrameOffset {
    pub rva: u64,
    pub fde: u64,
    state: u8,
    ret_reg: u8,
    frame_states: Vec<FrameState>,
}

impl FrameOffset {
    fn new(
        rva: u64,
        fde: u64) -> Self {
        Self {
            rva,
            fde,
            state: STATE_UNPARSED,
            ret_reg: 0,
            frame_states: Vec::new(),
        }
    }

    pub fn unwind_to_cfa(
        &self,
        reg_offsets: &mut Vec<i16>,
        rva: u64) -> UnwindCFA {
        let mut cfa_data = UnwindCFA::new();

        let max_reg: u8 = reg_offsets.len() as u8;

        for state in &self.frame_states {
            if state.rva > rva {
                break;
            }

            cfa_data.reg = state.cfa_reg;
            cfa_data.off = state.cfa_off;

            for reg_state in &state.reg_states {
                if reg_state.reg >= max_reg || 
                   reg_state.val_type != VALUE_TYPE_OFFSET {
                    continue;
                }

                reg_offsets[reg_state.reg as usize] = reg_state.val;
                cfa_data.off_mask |= 1 << reg_state.reg as u64;
            }
        }

        cfa_data
    }

    pub fn is_unparsed(&self) -> bool {
        self.state == STATE_UNPARSED
    }

    pub fn is_valid(&self) -> bool {
        self.state == STATE_VALID
    }

    pub fn mark_invalid(&mut self) {
        self.state = STATE_INVALID;
    }

    fn mark_valid(&mut self) {
        self.state = STATE_VALID;
    }

    fn parse_cie(
        &mut self,
        entry: &[u8],
        options: &mut FrameOptions) -> Result<usize, Error> {
        if entry.len() < 8 {
            return Err(
                error("CIE too small"));
        }

        let cie_id = u32::from_ne_bytes(
            entry[4..8].try_into().unwrap());

        /* Not valid */
        if cie_id != 0 {
            return Err(
                error("Invalid CIE"));
        }

        let mut cursor: usize = 8;

        let version = read_byte(entry, &mut cursor)?;

        if version != 1 {
            return Err(
                error("Invalid Version"));
        }

        let aug_len = read_string(entry, &mut cursor)?;
        let aug = &entry[9..(9 + aug_len)];

        let code_align = read_uleb(entry, &mut cursor)?;
        let data_align = read_sleb(entry, &mut cursor)?;
        let ret_reg = read_uleb(entry, &mut cursor)?;

        if code_align > i16::MAX.into() ||
           data_align > i16::MAX.into() ||
           data_align < i16::MIN.into() ||
           ret_reg > u8::MAX.into() {
            return Err(
                error("alignment/.into() ret reg out of range"));
        }

        options.code_align = code_align as i16;
        options.data_align = data_align as i16;
        self.ret_reg = ret_reg as u8;

        if aug[0] == b'z' {
            let _aug_len = read_uleb(entry, &mut cursor)?;
            options.has_aug_data = true;

            for a in aug {
                match *a as char{
                    'L' => {
                        /* lang */
                        let _ = read_byte(entry, &mut cursor)?;
                    },
                    'P' => {
                        /* personality */
                        let p_enc = read_byte(entry, &mut cursor)?;
                        let _ = read_value(p_enc, 0, entry, &mut cursor)?;
                    },
                    'R' => {
                        options.enc = read_byte(entry, &mut cursor)?;
                    },
                    'S' => {
                        /* Signal frame */
                    },
                    /* Default */
                    _ => {},
                }
            }
        }

        Ok(cursor)
    }

    fn read_frame_entry(
        reader: &mut (impl Read + Seek),
        buf: &mut Vec<u8>) -> Result<usize, Error> {
        /* Try to read up to 256 bytes */
        buf.resize(256, 0);

        let read_len = reader.read(buf)?;

        if read_len < 4 {
            return Err(
                error("Cannot read length"));
        }

        let len = u32::from_ne_bytes(
            buf[0..4].try_into().unwrap()) as usize;

        /* Not valid, or really large, skip */
        if len == 0 {
            return Err(
                error("Zero length"));
        }

        if len > 2048 {
            return Err(
                error("Too large length"));
        }

        /* Length does not include the length itself */
        let len = len + 4;

        /* Read in remaining, if any */
        if read_len < len {
            buf.resize(len, 0);
            reader.read_exact(&mut buf[read_len..])?;
        }

        /* Return length of data */
        Ok(len)
    }

    fn load_rules(
        &mut self,
        reader: &mut (impl Read + Seek),
        fde_buf: &mut Vec<u8>,
        cie_buf: &mut Vec<u8>) -> Result<(), Error> {
        /* Mark invalid in case of error(s) */
        self.mark_invalid();

        /* Move to FDE */
        reader.seek(SeekFrom::Start(self.fde))?;
        let fde_len = Self::read_frame_entry(
            reader,
            fde_buf)?;

        if fde_len < 8 {
            return Err(
                error("FDE too small"));
        }

        let fde_slice = &fde_buf[..fde_len];

        let cie_offset = u32::from_ne_bytes(
            fde_slice[4..8].try_into().unwrap());

        /* Not valid */
        if cie_offset == 0 {
            return Err(
                error("Invalid CIE offset"));
        }

        /* CIE is back from current pos */
        let cie_pos = (self.fde + 4) - cie_offset as u64;

        /* Move to CIE and load */
        reader.seek(SeekFrom::Start(cie_pos))?;
        let cie_len = Self::read_frame_entry(
            reader,
            cie_buf)?;
        let cie_slice = &cie_buf[..cie_len];

        let mut options = FrameOptions::new();
        let cie_cursor = self.parse_cie(
            cie_slice,
            &mut options)?;

        let mut cursor: usize = 8;
        let pc_start = read_value(options.enc, self.fde as i64, fde_slice, &mut cursor)?;
        let _pc_size = read_value(options.enc, -12, fde_slice, &mut cursor)?;

        if options.has_aug_data {
            /* Skip augmentation data */
            let size = read_uleb(fde_slice, &mut cursor)?;
            cursor += size as usize;
        }

        let mut frame = FrameState::new(
            pc_start as u64,
            0,
            0);

        /* Read CIE rules */
        let mut cie_cursor = cie_cursor;
        let mut pc = pc_start;
        while cie_cursor < cie_len {
            /* CIE shouldn't advance */
            let _ = self.read_rule(
                &mut pc,
                &mut frame,
                cie_slice,
                &mut cie_cursor,
                &mut options)?;
        }

        /* Read FDE rules */
        let mut pc = pc_start;
        while cursor < fde_len {
            if self.read_rule(
                &mut pc,
                &mut frame,
                fde_slice,
                &mut cursor,
                &mut options)? {
                let cfa_reg = frame.cfa_reg;
                let cfa_off = frame.cfa_off;
                self.frame_states.push(frame);
                frame = FrameState::new(
                    pc as u64,
                    cfa_reg,
                    cfa_off);
            }
        }

        /* Push in last frame */
        self.frame_states.push(frame);

        /* Valid at this point */
        self.mark_valid();
        Ok(())
    }

    fn read_rule(
        &mut self,
        pc: &mut i64,
        frame: &mut FrameState,
        slice: &[u8],
        cursor: &mut usize,
        options: &mut FrameOptions) -> Result<bool, Error> {
        let ins = read_byte(slice, cursor)?;
        let p = ins & 0xC0;
        let e = ins & 0x3F;

        match p {
            /* Extended */
            DW_CFA_EXTENDED => {
                match e {
                    /* NOP */
                    DW_CFA_NOP => {
                        /* Nothing */
                    },

                    /* Set Location */
                    DW_CFA_SET_LOC => {
                        let address = read_value(
                            options.enc,
                            *pc,
                            slice,
                            cursor)?;

                        if address > *pc {
                            *pc = address;
                        }

                        return Ok(true);
                    },

                    /* Advance Location (1 byte) */
                    DW_CFA_ADVANCE_LOC1 => {
                        let delta = read_byte(slice, cursor)?;
                        let new_pc = *pc + (delta as i64 * options.code_align as i64);

                        if new_pc > *pc {
                            *pc = new_pc;
                        }

                        return Ok(true);
                    },

                    /* Advance Location (2 byte) */
                    DW_CFA_ADVANCE_LOC2 => {
                        let delta = read_u16(slice, cursor)?;
                        let new_pc = *pc + (delta as i64 * options.code_align as i64);

                        if new_pc > *pc {
                            *pc = new_pc;
                        }

                        return Ok(true);
                    },

                    /* Advance Location (4 byte) */
                    DW_CFA_ADVANCE_LOC4 => {
                        let delta = read_u32(slice, cursor)?;
                        let new_pc = *pc + (delta as i64 * options.code_align as i64);

                        if new_pc > *pc {
                            *pc = new_pc;
                        }

                        return Ok(true);
                    },

                    /* Register saved at offset */
                    DW_CFA_OFFSET_EXTENDED => {
                        let reg = read_uleb(slice, cursor)?;
                        let offset = read_uleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.add_reg_value(
                            reg,
                            offset,
                            VALUE_TYPE_OFFSET)?;
                    },

                    /* Register same as intial instructions */
                    DW_CFA_RESTORE_EXTENDED => {
                        let reg = read_uleb(slice, cursor)?;
                        frame.add_reg_value(
                            reg,
                            0,
                            VALUE_TYPE_RESTORE)?;
                    },

                    /* Register undefined */
                    DW_CFA_UNDEFINED => {
                        let reg = read_uleb(slice, cursor)?;

                        frame.add_reg_value(
                            reg,
                            0,
                            VALUE_TYPE_UNDEFINED)?;
                    },

                    /* Register same as before */
                    DW_CFA_SAME_VALUE => {
                        let _reg = read_uleb(slice, cursor)?;
                        /* Don't add, previous value will be used */
                    },

                    /* Register clone */
                    DW_CFA_REGISTER => {
                        let src_reg = read_uleb(slice, cursor)?;
                        let dst_reg = read_uleb(slice, cursor)?;

                        frame.add_reg_value(
                            src_reg,
                            dst_reg,
                            VALUE_TYPE_REG)?;
                    },

                    /* Push state */
                    DW_CFA_REMEMBER_STATE => {
                        options.cfa_stack.push(
                            CFAState {
                                cfa_reg: frame.cfa_reg,
                                cfa_off: frame.cfa_off,
                            });
                    },

                    /* Pop state */
                    DW_CFA_RESTORE_STATE => {
                        match options.cfa_stack.pop() {
                            Some(cfa_state) => {
                                frame.cfa_reg = cfa_state.cfa_reg;
                                frame.cfa_off = cfa_state.cfa_off;
                            },
                            None => {
                                return Err(
                                    error("Unbalanced state restore"));
                            }
                        }
                    },

                    /* CFA register and offset */
                    DW_CFA_DEF_CFA => {
                        let reg = read_uleb(slice, cursor)?;
                        let off = read_uleb(slice, cursor)?;

                        frame.set_cfa_reg(reg)?;
                        frame.set_cfa_offset(off)?;
                    },

                    /* CFA register only */
                    DW_CFA_DEF_CFA_REGISTER => {
                        let reg = read_uleb(slice, cursor)?;

                        frame.set_cfa_reg(reg)?;
                    },

                    /* CFA offset only */
                    DW_CFA_DEF_CFA_OFFSET => {
                        let off = read_uleb(slice, cursor)?;

                        frame.set_cfa_offset(off)?;
                    },

                    /* CFA expression */
                    DW_CFA_DEF_CFA_EXPRESSION => {
                        let size = read_uleb(slice, cursor)?;
                        *cursor += size as usize;
                        return Err(
                            error("CFA expression not supported"));
                    }

                    /* CFA expression */
                    DW_CFA_EXPRESSION => {
                        let reg = read_uleb(slice, cursor)?;
                        let size = read_uleb(slice, cursor)?;
                        *cursor += size as usize;

                        frame.add_reg_value(
                            reg,
                            0,
                            VALUE_TYPE_EXPRESSION)?;
                    },

                    /* Reg at signed offset */
                    DW_CFA_OFFSET_EXTENDED_SF => {
                        let reg = read_uleb(slice, cursor)?;
                        let offset = read_sleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.add_reg_value(
                            reg,
                            offset,
                            VALUE_TYPE_OFFSET)?;
                    },

                    /* CFA reg at signed offset */
                    DW_CFA_DEF_CFA_SF => {
                        let reg = read_uleb(slice, cursor)?;
                        let offset = read_sleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.set_cfa_reg(reg)?;
                        frame.set_cfa_offset(offset)?;
                    },

                    /* CFA at signed offset */
                    DW_CFA_DEF_CFA_OFFSET_SF => {
                        let offset = read_sleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.set_cfa_offset(offset)?;
                    },

                    /* Register value offset */
                    DW_CFA_VAL_OFFSET => {
                        let reg = read_uleb(slice, cursor)?;
                        let offset = read_uleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.add_reg_value(
                            reg,
                            offset,
                            VALUE_TYPE_OFFSET)?;
                    },

                    /* Register value signed offset */
                    DW_CFA_VAL_OFFSET_SF => {
                        let reg = read_uleb(slice, cursor)?;
                        let offset = read_sleb(slice, cursor)?;
                        let offset = offset * options.data_align as i64;

                        frame.add_reg_value(
                            reg,
                            offset,
                            VALUE_TYPE_OFFSET)?;
                    },

                    /* Register value expression */
                    DW_CFA_VAL_EXPRESSION => {
                        let reg = read_uleb(slice, cursor)?;
                        let size = read_uleb(slice, cursor)?;
                        *cursor += size as usize;

                        frame.add_reg_value(
                            reg,
                            0,
                            VALUE_TYPE_EXPRESSION)?;
                    },

                    /* Arg size */
                    DW_CFA_GNU_ARGS_SIZE => {
                        let _size = read_uleb(slice, cursor)?;
                    },

                    /* Unknown */
                    _ => {
                        return Err(
                            error("Unknown DWARF extended opcode"));
                    },
                }
            },

            /* Basic advance */
            DW_CFA_ADVANCE_LOC => {
                let delta = e;
                let new_pc = *pc + (delta as i64 * options.code_align as i64);

                if new_pc > *pc {
                    *pc = new_pc;
                }

                return Ok(true);
            },

            /* Basic offset */
            DW_CFA_OFFSET => {
                let reg = e;
                let offset = read_uleb(slice, cursor)?;
                let offset = offset * options.data_align as i64;

                frame.add_reg_value(
                    reg as i64,
                    offset,
                    VALUE_TYPE_OFFSET)?;
            },

            /* Basic restore */
            DW_CFA_RESTORE => {
                let reg = e;
                frame.add_reg_value(
                    reg as i64,
                    0,
                    VALUE_TYPE_RESTORE)?;
            },

            /* Unknown */
            _ => {
                return Err(
                    error("Unknown DWARF primary opcode"));
            },
        }

        Ok(false)
    }

    pub fn find(
        rva: u64,
        offsets: &Vec<FrameOffset>) -> Option<usize> {
        if !offsets.is_empty() {
            let mut index = offsets.partition_point(
                |offset| offset.rva <= rva );

            index = index.saturating_sub(1);

            let offset = &offsets[index];

            if offset.rva <= rva {
                return Some(index);
            }
        }

        None
    }

    fn parse_loc_table(
        reader: &mut (impl Read + Seek),
        metadata: &SectionMetadata,
        eh_offset: u64,
        offsets: &mut Vec<FrameOffset>,
        buf: &mut Vec<u8>) -> Result<(), Error> {
        let mut cursor: usize = 0;
        /* Move to section */
        reader.seek(SeekFrom::Start(metadata.offset))?;
        buf.clear();
        buf.resize(metadata.size as usize, 0);
        reader.read_exact(buf)?;

        /* Validate header */
        if buf[0] != 1 {
            /* Unknown version, skip */
            return Ok(());
        }

        let section_enc = buf[1];
        let count_enc = buf[2];
        let table_enc = buf[3];

        cursor += 4;

        if section_enc == DW_EH_PE_OMIT ||
           count_enc == DW_EH_PE_OMIT ||
           table_enc == DW_EH_PE_OMIT
        {
            /* Not available, skip */
            return Ok(());
        }

        let data: i64 = metadata.offset as i64;
        let sec_ptr = read_value(section_enc, data, buf, &mut cursor)? as u64;
        let count = read_value(count_enc, data, buf, &mut cursor)?;

        for _ in 0..count {
            let rva = read_value(table_enc, data, buf, &mut cursor)? as u64;
            let fde = read_value(table_enc, data, buf, &mut cursor)? as u64;

            let fde = eh_offset + (fde - sec_ptr);

            offsets.push(
                FrameOffset::new(
                    rva,
                    fde));
        }

        Ok(())
    }
}

impl fmt::Debug for FrameOffset {
    fn fmt(
        &self,
        f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Frame RVA: 0x{:X}", self.rva)?;
        write!(f, "FDE=0x{:X},RetReg={}", self.fde, self.ret_reg)?;
        write!(f, "FrameStates:")?;
        for state in &self.frame_states {
            state.fmt(f)?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct FrameHeaderTable {
    metadata_buf: Vec<SectionMetadata>,
    fde_buf: Vec<u8>,
    cie_buf: Vec<u8>,
}

impl FrameHeaderTable {
    pub fn new() -> Self { Self::default() }

    pub fn parse_offset(
        &mut self,
        reader: &mut (impl Read + Seek),
        offset: &mut FrameOffset) -> Result<(), Error> {
        offset.load_rules(
            reader,
            &mut self.fde_buf,
            &mut self.cie_buf)
    }

    pub fn parse(
        &mut self,
        reader: &mut (impl Read + Seek),
        frame_offsets: &mut Vec<FrameOffset>) -> Result<(), Error> {
        self.metadata_buf.clear();
        get_section_metadata(
            reader,
            None,
            SHT_PROGBITS,
            &mut self.metadata_buf)?;

        let mut eh_offset: u64 = 0;

        for sec in &self.metadata_buf {
            if let Ok(true) = sec.name_equals(
                reader,
                ".eh_frame",
                &mut self.cie_buf) {
                eh_offset = sec.offset;

                break;
            }
        }

        for sec in &self.metadata_buf {
            if let Ok(true) = sec.name_equals(
                reader,
                ".eh_frame_hdr",
                &mut self.cie_buf) {
                /* Load in location table */
                FrameOffset::parse_loc_table(
                    reader,
                    sec,
                    eh_offset,
                    frame_offsets,
                    &mut self.cie_buf)?;
                break;
            }
        }

        Ok(())
    }
}

/* Internal state */
const STATE_UNPARSED: u8 = 0;
const STATE_INVALID: u8 = 1;
const STATE_VALID: u8 = 2;

/* Pointer encodings */
const DW_EH_PE_OMIT: u8 = 0xFF;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0A;
const DW_EH_PE_SDATA4: u8 = 0x0B;
const DW_EH_PE_SDATA8: u8 = 0x0C;
const DW_EH_PE_FORMAT_MASK: u8 = 0x0F;

/* Applications */
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_DATAREL: u8 = 0x30;
const DW_EH_PE_APPL_MASK: u8 = 0xF0;

/* Instructions */
const DW_CFA_EXTENDED: u8 = 0x00;
const DW_CFA_ADVANCE_LOC: u8 = 0x40;
const DW_CFA_OFFSET: u8 = 0x80;
const DW_CFA_RESTORE: u8 = 0xC0;

const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_SET_LOC: u8 = 0x01;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
const DW_CFA_UNDEFINED: u8 = 0x07;
const DW_CFA_SAME_VALUE: u8 = 0x08;
const DW_CFA_REGISTER: u8 = 0x09;
const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
const DW_CFA_RESTORE_STATE: u8 = 0x0b;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
const DW_CFA_EXPRESSION: u8 = 0x10;
const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
const DW_CFA_DEF_CFA_SF: u8 = 0x12;
const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
const DW_CFA_VAL_OFFSET: u8 = 0x14;
const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
const DW_CFA_GNU_ARGS_SIZE: u8 = 0x2e;

fn read_byte(
    slice: &[u8],
    cursor: &mut usize) -> Result<u8, Error> {
    let byte = slice[*cursor];
    *cursor += 1;
    Ok(byte)
}

fn read_u16(
    slice: &[u8],
    cursor: &mut usize) -> Result<u16, Error> {
    let start = *cursor;
    *cursor += 2;
    Ok(u16::from_ne_bytes(
        slice[start..*cursor]
        .try_into()
        .unwrap()))
}

fn read_u32(
    slice: &[u8],
    cursor: &mut usize) -> Result<u32, Error> {
    let start = *cursor;
    *cursor += 4;
    Ok(u32::from_ne_bytes(
        slice[start..*cursor]
        .try_into()
        .unwrap()))
}

fn read_string(
    slice: &[u8],
    cursor: &mut usize) -> Result<usize, Error> {
    let start = *cursor;
    let mut pos = start;

    while slice[pos] != 0 {
        pos += 1;
    }

    *cursor = pos + 1;

    Ok(pos - start)
}

fn read_uleb(
    slice: &[u8],
    cursor: &mut usize) -> Result<i64, Error> {
    let mut pos = *cursor;
    let mut value: i64 = 0;
    let mut bit: i32 = 0;

    loop {
        let byte = slice[pos];
        pos += 1;

        value |= ((byte & 127) as i64) << bit;

        if (byte & 128) == 0 {
            break;
        }

        bit += 7;
    }

    *cursor = pos;

    Ok(value)
}

fn read_sleb(
    slice: &[u8],
    cursor: &mut usize) -> Result<i64, Error> {
    let mut pos = *cursor;
    let mut value: i64 = 0;
    let mut bit: i32 = 0;

    loop {
        let byte = slice[pos];
        pos += 1;

        value |= ((byte & 127) as i64) << bit;
        bit += 7;

        if (byte & 128) == 0 {
            if bit < 64 && (byte & 64) != 0 {
                /* Sign extend */
                value |= -(1_i64 << bit);
            }

            break;
        }
    }

    *cursor = pos;

    Ok(value)
}

fn read_value(
    enc: u8,
    data: i64,
    slice: &[u8],
    cursor: &mut usize) -> Result<i64, Error> {
    let mut value: i64;
    let start = *cursor;

    match enc & DW_EH_PE_FORMAT_MASK {
        DW_EH_PE_ULEB128 => {
            value = read_uleb(
                slice,
                cursor)?;
        },
        DW_EH_PE_UDATA2 => {
            value = read_u16(
                slice,
                cursor)? as i64;
        },
        DW_EH_PE_UDATA4 => {
            value = read_u32(
                slice,
                cursor)? as i64;
        },
        DW_EH_PE_UDATA8 => {
            *cursor += 8;
            value = u64::from_ne_bytes(
                slice[start..*cursor]
                .try_into()
                .unwrap()) as i64;
        },
        DW_EH_PE_SLEB128 => {
            value = read_sleb(
                slice,
                cursor)?;
        },
        DW_EH_PE_SDATA2 => {
            *cursor += 2;
            value = i16::from_ne_bytes(
                slice[start..*cursor]
                .try_into()
                .unwrap()) as i64;
        },
        DW_EH_PE_SDATA4 => {
            *cursor += 4;
            value = i32::from_ne_bytes(
                slice[start..*cursor]
                .try_into()
                .unwrap()) as i64;
        },
        DW_EH_PE_SDATA8 => {
            *cursor += 8;
            value = i64::from_ne_bytes(
                slice[start..*cursor]
                .try_into()
                .unwrap());
        },
        _ => {
            /* Unknown, unsupported */
            value = 0;
        },
    }

    match enc & DW_EH_PE_APPL_MASK {
        DW_EH_PE_PCREL => { value += data; value += start as i64; },
        DW_EH_PE_DATAREL => { value += data; },
        _ => { /* Nothing */ },
    }

    Ok(value)
}

fn error(
    error: &str) -> Error {
    Error::new(
        ErrorKind::Other,
        error)
}
