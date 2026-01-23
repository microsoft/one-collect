// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::dwarf::*;
use tracing::{debug, trace, error, warn};

#[derive(Default)]
struct FrameOffsets {
    frame_offsets: Vec<FrameOffset>,
    filled: bool,
}

impl FrameOffsets {
    fn get_frame_offset(
        &mut self,
        key: &ModuleKey,
        accessor: &dyn ModuleAccessor,
        table: &mut FrameHeaderTable,
        rva: u64) -> Option<&FrameOffset> {
        if !self.filled {
            /* Initial find, load offsets */
            if let Some(mut file) = accessor.open(key) {
                debug!("Loading frame offsets: dev={}, ino={}", key.dev(), key.ino());
                let _result = table.parse(
                    &mut file,
                    &mut self.frame_offsets);
                debug!("Frame offsets loaded: count={}", self.frame_offsets.len());
            } else {
                warn!("Failed to open file for frame offsets: dev={}, ino={}", key.dev(), key.ino());
            }

            /* Don't attempt any more loads */
            self.filled = true;
        }

        /* Find frame offset by RVA */
        if let Some(index) = FrameOffset::find(
            rva,
            &self.frame_offsets) {
            let offset = &mut self.frame_offsets[index];

            /* Ensure parsed */
            if offset.is_unparsed() {
                debug!("Parsing frame offset: rva={:#x}", rva);
                if let Some(mut file) = accessor.open(key) {
                    /* Parse, determines if valid */
                    let _result = table.parse_offset(
                        &mut file,
                        offset);
                } else {
                    /* Cannot access file */
                    warn!("Cannot access file for frame offset parsing: dev={}, ino={}", key.dev(), key.ino());
                    offset.mark_invalid();
                }
            }

            /* Ensure valid */
            if offset.is_valid() {
                trace!("Frame offset found and valid: rva={:#x}", rva);
                return Some(offset);
            } else {
                trace!("Frame offset found but invalid: rva={:#x}", rva);
            }
        } else {
            trace!("No frame offset found for rva={:#x}", rva);
        }

        None
    }
}

#[derive(Default)]
pub struct Unwinder {
    frame_cache: HashMap<ModuleKey, FrameOffsets>,
    frame_table: FrameHeaderTable,
    registers: Vec<u64>,
    offsets: Vec<i16>,
    rip: u64,
    rsp: u64,
}

impl Unwinder {
    pub fn new() -> Self { Self::default() }

    fn stack_value(
        rsp: u64,
        cfa: u64,
        off: i64,
        stack_data: &[u8]) -> Option<u64> {
        if cfa < rsp {
            return None;
        }

        let offset = (cfa - rsp) as i64 + off;
        let max_offset = stack_data.len() as i64 - 8;

        if offset < 0 || offset >= max_offset {
            return None;
        }

        let start = offset as usize;
        let end = start + 8;

        Some(u64::from_ne_bytes(
            stack_data[start..end]
            .try_into()
            .unwrap()))
    }

    fn unwind_prolog(
        &mut self,
        process: &dyn Unwindable,
        stack_data: &[u8],
        result: &mut UnwindResult) -> Option<u64> {

        let cfa = self.registers[REG_RSP];
        let len = stack_data.len();

        /* Ensure valid enough to start scan */
        if cfa < self.rsp || len < 16 {
            trace!("Prolog unwind failed: insufficient data, cfa={:#x}, rsp={:#x}, len={}", cfa, self.rsp, len);
            return None;
        }

        trace!("Starting prolog scan: cfa={:#x}, stack_len={}", cfa, len);

        /* Limit range to stack size at stack location */
        let max_cfa = cfa + len as u64;

        /* Determine offset and limit read offset */
        let mut offset = (cfa - self.rsp) as usize;
        let max_offset = len - 8;

        if offset > max_offset {
            warn!("Prolog unwind failed: offset out of range");
            return None;
        }

        /* Limit how many times we scan */
        let mut count = 0;
        let max_count = 64;

        let mut first = u64::from_ne_bytes(
            stack_data[offset..offset+8]
            .try_into()
            .unwrap());

        offset += 8;

        /* Scan */
        while offset <= max_offset && count < max_count {
            let second = u64::from_ne_bytes(
                stack_data[offset..offset+8]
                .try_into()
                .unwrap());

            /* Check if CFA/RSP is within range */
            if first > cfa && first <= max_cfa {
                /* Check if IP is within a module */
                if process.find(second).is_some() {
                    /* Assume valid */
                    trace!("Prolog scan successful: new_rsp={:#x}, next_ip={:#x}, scan_count={}", first, second, count);
                    self.registers[REG_RSP] = first;
                    self.registers[REG_RBP] = first;

                    return Some(second);
                }
            }

            /* Swap read value to first */
            first = second;

            /* Proceed further */
            offset += 8;
            count += 1;
        }

        warn!("Prolog scan exhausted: scan_count={}", count);
        result.error = Some("Anon prolog not found");

        None
    }

    fn unwind_module(
        &mut self,
        key: &ModuleKey,
        accessor: &dyn ModuleAccessor,
        rva: u64,
        stack_data: &[u8],
        result: &mut UnwindResult) -> Option<u64> {
        trace!("Unwinding module: rva={:#x}, dev={}, ino={}", rva, key.dev(), key.ino());
        
        /* Lookup offset by RVA */
        if let Some(offset) = self.frame_cache
            .entry(*key)
            .or_insert_with(FrameOffsets::default)
            .get_frame_offset(
                key,
                accessor,
                &mut self.frame_table,
                rva) {
            let cfa_data = offset.unwind_to_cfa(
                &mut self.offsets,
                rva);

            if cfa_data.reg as usize > REG_RA {
                error!("Register out of range: reg={}", cfa_data.reg);
                result.error = Some("Register out of range");
                return None;
            }
                
            let cfa = (self.registers[cfa_data.reg as usize] as i64 + cfa_data.off as i64) as u64;
            debug!("CFA computed: cfa={:#x}, cfa_reg={}, cfa_off={}", cfa, cfa_data.reg, cfa_data.off);

            /* No return address, unexpected */
            if cfa_data.off_mask & REG_RA_BIT == 0 {
                warn!("No return address register in frame");
                result.error = Some("No return address register");
                return None;
            }

            /* Unexpected backwards access */
            if self.registers[REG_RSP] >= cfa {
                warn!("CFA would go backwards: rsp={:#x}, cfa={:#x}", self.registers[REG_RSP], cfa);
                result.error = Some("CFA would go backwards");
                return None;
            }

            /* Update RBP */
            if cfa_data.off_mask & REG_RBP_BIT != 0 {
                match Unwinder::stack_value(
                    self.rsp,
                    cfa,
                    self.offsets[REG_RBP] as i64,
                    stack_data) {
                    Some(value) => {
                        trace!("RBP updated: rbp={:#x}", value);
                        self.registers[REG_RBP] = value;
                    },
                    None => {
                        debug!("Bad stack RBP read");
                        result.error = Some("Bad stack RBP read");
                        return None;
                    },
                }
            }

            /* Update RSP */
            self.registers[REG_RSP] = cfa;

            /* Read IP */
            match Unwinder::stack_value(
                self.rsp,
                cfa,
                self.offsets[REG_RA] as i64,
                stack_data) {
                Some(value) => {
                    debug!("Module unwind successful: next_ip={:#x}", value);
                    return Some(value);
                },
                None => {
                    debug!("Bad stack IP read");
                    result.error = Some("Bad stack IP read");
                    return None;
                }
            }
        }

        debug!("No frame offset found for module");
        result.error = Some("No module found");
        None
    }
}

/* DWARF register values */
const REG_RBP: usize = 6;
const REG_RSP: usize = 7;
const REG_RA: usize = 16;

/* Matching bits to DWARF */
const REG_RBP_BIT: u64 = 1 << REG_RBP;
const REG_RA_BIT: u64 = 1 << REG_RA;

impl MachineUnwinder for Unwinder {
    fn reset(
        &mut self,
        rip: u64,
        rbp: u64,
        rsp: u64) {
        debug!("Unwinder reset: rip={:#x}, rbp={:#x}, rsp={:#x}", rip, rbp, rsp);
        
        /* Force 0 values for registers */
        self.registers.clear();
        self.registers.resize(REG_RA + 1, 0);

        /* Force enough slots for offsets */
        self.offsets.clear();
        self.offsets.resize(REG_RA + 1, 0);

        /* Set initial values */
        self.registers[REG_RBP] = rbp;
        self.registers[REG_RSP] = rsp;
        self.rip = rip;
        self.rsp = rsp;
    }

    fn unwind(
        &mut self,
        process: &dyn Unwindable,
        accessor: &dyn ModuleAccessor,
        stack_data: &[u8],
        stack_frames: &mut Vec<u64>,
        result: &mut UnwindResult) {
        trace!("Starting stack unwind loop");
        
        while let Some(module) = process.find(self.rip) {
            let ip = if module.unwind_type() == UnwindType::Prolog {
                /* Anonymous and PE */
                trace!("Using prolog unwinder for ip={:#x}", self.rip);
                self.unwind_prolog(
                    process,
                    stack_data,
                    result)
            } else {
                /* Default to DWARF */
                let rva = module.rva(self.rip);
                trace!("Using DWARF unwinder for ip={:#x}, rva={:#x}", self.rip, rva);

                self.unwind_module(
                    &module.key(),
                    accessor,
                    rva,
                    stack_data,
                    result)
            };

            /* Add ip to stack or stop */
            match ip {
                Some(next_ip) => {
                    self.rip = next_ip;

                    stack_frames.push(self.rip);
                    result.frames_pushed += 1;
                    trace!("Frame pushed: ip={:#x}, total_frames={}", self.rip, result.frames_pushed);

                    /* Hard cap of frames */
                    if result.frames_pushed > 128 {
                        debug!("Maximum frame count reached: {}", result.frames_pushed);
                        break;
                    }

                    /* IP of 0 means we are done. */
                    if self.rip == 0 {
                        debug!("Reached null IP, unwinding complete");
                        break;
                    }
                },
                None => {
                    debug!("Unwind failed, stopping");
                    return;
                },
            }
        }

        debug!("No module found for current IP, unwinding stopped");

        if result.frames_pushed > 1 {
            stack_frames.pop();
            result.frames_pushed -= 1;
        }
    }
}
