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
                /*
                 * The .eh_frame_hdr index only stores the FDE start RVAs;
                 * partition_point above can return an FDE whose PC range
                 * ends before the queried RVA (which then sits in a code
                 * gap with no FDE coverage — common for hand-written
                 * assembly thunks and JIT helpers in libcoreclr.so).
                 * Apply the FDE only when the RVA is actually inside its
                 * declared PC range so we don't compute a garbage CFA.
                 */
                if offset.pc_size != 0 && rva >= offset.rva + offset.pc_size {
                    trace!(
                        "FDE found but rva {:#x} is outside FDE range {:#x}..{:#x}",
                        rva, offset.rva, offset.rva + offset.pc_size);
                    return None;
                }
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
        let rbp = self.registers[REG_RBP];
        let len = stack_data.len();

        /* Ensure valid enough to start scan */
        if cfa < self.rsp || len < 16 {
            trace!("Prolog unwind failed: insufficient data, cfa={:#x}, rsp={:#x}, len={}", cfa, self.rsp, len);
            return None;
        }

        trace!("Starting prolog scan: cfa={:#x}, stack_len={}", cfa, len);

        /* Limit range to stack size at stack location */
        let max_cfa = cfa + len as u64;

        /*
         * Try walking the RBP frame pointer chain first.
         *
         * Many compilers and runtimes maintain an RBP chain on x64 where
         * [rbp] = caller's saved RBP and [rbp+8] = return address. If a
         * function does not push RBP, it simply preserves the register
         * and is skipped in the chain (equivalent to inlining).
         *
         * We follow the chain looking for a link where [rbp+8] is a valid
         * code address. If [rbp+8] is not valid, we follow [rbp] to the
         * next chain link. If the chain is absent or corrupted (e.g. RBP
         * is used as a general-purpose register), the guard checks below
         * (alignment, forward progress, bounds) will break out and we
         * fall back to the existing linear scan.
         */
        let max_chain_depth = 16;
        let mut chain_rbp = rbp;

        for _depth in 0..max_chain_depth {
            let saved_rbp = match Unwinder::stack_value(self.rsp, chain_rbp, 0, stack_data) {
                Some(v) => v,
                None => break,
            };

            let ret_addr = match Unwinder::stack_value(self.rsp, chain_rbp, 8, stack_data) {
                Some(v) => v,
                None => break,
            };

            if process.find(ret_addr).is_some() {
                trace!("RBP chain walk successful: chain_rbp={:#x}, saved_rbp={:#x}, ret_addr={:#x}, depth={}", chain_rbp, saved_rbp, ret_addr, _depth);
                self.registers[REG_RSP] = chain_rbp + 16;
                self.registers[REG_RBP] = saved_rbp;
                return Some(ret_addr);
            }

            /* [rbp+8] wasn't a valid return address — follow the chain */
            if saved_rbp <= chain_rbp || saved_rbp > max_cfa || saved_rbp & 0x7 != 0 {
                break;
            }

            chain_rbp = saved_rbp;
        }

        /*
         * RBP chain walk didn't find a frame. Fall back to scanning
         * consecutive stack slots for (stack_address, code_address) pairs.
         */

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
        result.error = Some(UnwindError::AnonPrologNotFound);

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
                result.error = Some(UnwindError::RegisterOutOfRange);
                return None;
            }
                
            let cfa = (self.registers[cfa_data.reg as usize] as i64 + cfa_data.off as i64) as u64;
            debug!("CFA computed: cfa={:#x}, cfa_reg={}, cfa_off={}", cfa, cfa_data.reg, cfa_data.off);

            /* No return address, unexpected */
            if cfa_data.off_mask & REG_RA_BIT == 0 {
                warn!("No return address register in frame");
                result.error = Some(UnwindError::NoReturnAddressRegister);
                return None;
            }

            /* Unexpected backwards access */
            if self.registers[REG_RSP] >= cfa {
                warn!("CFA would go backwards: rsp={:#x}, cfa={:#x}", self.registers[REG_RSP], cfa);
                result.error = Some(UnwindError::CfaWouldGoBackwards);
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
                        result.error = Some(UnwindError::BadStackRbpRead);
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
                    result.error = Some(UnwindError::BadStackIpRead);
                    return None;
                }
            }
        }

        debug!("No frame offset found for module");
        result.error = Some(UnwindError::NoModuleFound);
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
            let saved_rsp = self.registers[REG_RSP];
            let saved_rbp = self.registers[REG_RBP];

            let mut ip = if module.unwind_type() == UnwindType::Prolog {
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

            /*
             * DWARF FDE lookup can return None for code regions inside an
             * ELF that don't have .eh_frame entries — for example PLT
             * stubs and small hand-written assembly thunks in libcoreclr.so.
             * In that case fall back to a frame-pointer / stack-scan walk
             * which can usually skip over the stub and continue unwinding.
             */
            if ip.is_none()
                && module.unwind_type() != UnwindType::Prolog
                && result.error == Some(UnwindError::NoModuleFound)
            {
                trace!(
                    "DWARF lookup missing for ip={:#x}, falling back to prolog walk",
                    self.rip);
                result.error = None;
                ip = self.unwind_prolog(
                    process,
                    stack_data,
                    result);
            }

            /* Add ip to stack or stop */
            match ip {
                Some(next_ip) => {
                    /*
                     * DWARF can compute a bogus return address at the
                     * boundary between two ABIs — for example, libcoreclr.so
                     * code calling into JIT'd managed code through a
                     * helper thunk that doesn't expose a normal return
                     * address slot. Detect the case where the unwound IP
                     * doesn't belong to any known module and try a
                     * scan-based recovery (frame-pointer chain walk +
                     * linear stack scan) before giving up.
                     */
                    let mut next_ip = next_ip;
                    if next_ip != 0 && process.find(next_ip).is_none() {
                        trace!(
                            "Unwound IP {:#x} not in any module, attempting scan recovery",
                            next_ip);
                        /*
                         * Restore RSP/RBP to their values before the bogus
                         * DWARF unwind so the prolog scan starts from a
                         * known-good stack location, not from whatever
                         * (possibly out-of-range) CFA the FDE produced.
                         */
                        self.registers[REG_RSP] = saved_rsp;
                        self.registers[REG_RBP] = saved_rbp;
                        if let Some(recovered) = self.unwind_prolog(
                            process,
                            stack_data,
                            result) {
                            trace!(
                                "Scan recovery succeeded: bogus_ip={:#x}, recovered_ip={:#x}",
                                next_ip, recovered);
                            result.error = None;
                            next_ip = recovered;
                        }
                    }

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
