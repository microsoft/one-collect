use super::*;
use crate::dwarf::*;

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
                let _result = table.parse(
                    &mut file,
                    &mut self.frame_offsets);
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
                if let Some(mut file) = accessor.open(key) {
                    /* Parse, determines if valid */
                    let _result = table.parse_offset(
                        &mut file,
                        offset);
                } else {
                    /* Cannot access file */
                    offset.mark_invalid();
                }
            }

            /* Ensure valid */
            if offset.is_valid() {
                return Some(offset);
            }
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
        process: &Process,
        stack_data: &[u8],
        result: &mut UnwindResult) -> Option<u64> {

        let cfa = self.registers[REG_RSP];
        let len = stack_data.len();

        /* Ensure valid enough to start scan */
        if cfa < self.rsp || len < 16 {
            return None;
        }

        /* Limit range to stack size at stack location */
        let max_cfa = cfa + len as u64;

        /* Determine offset and limit read offset */
        let mut offset = (cfa - self.rsp) as usize;
        let max_offset = len - 8;

        if offset > max_offset {
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
                result.error = Some("Register out of range");
                return None;
            }
                
            let cfa = (self.registers[cfa_data.reg as usize] as i64 + cfa_data.off as i64) as u64;

            /* No return address, unexpected */
            if cfa_data.off_mask & REG_RA_BIT == 0 {
                result.error = Some("No return address register");
                return None;
            }

            /* Unexpected backwards access */
            if self.registers[REG_RSP] >= cfa {
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
                        self.registers[REG_RBP] = value;
                    },
                    None => {
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
                    return Some(value);
                },
                None => {
                    result.error = Some("Bad stack IP read");
                    return None;
                }
            }
        }

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
        process: &Process,
        accessor: &dyn ModuleAccessor,
        stack_data: &[u8],
        stack_frames: &mut Vec<u64>,
        result: &mut UnwindResult) {
        while let Some(module) = process.find(self.rip) {
            let ip = if module.anon {
                /* Anonymous code, no DWARF */
                self.unwind_prolog(
                    process,
                    stack_data,
                    result)
            } else {
                /* File backed code, use DWARF */
                let rva = (self.rip - module.start) + module.offset;

                self.unwind_module(
                    &module.key,
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

                    /* Hard cap of frames */
                    if result.frames_pushed > 128 {
                        break;
                    }

                    /* IP of 0 means we are done. */
                    if self.rip == 0 {
                        break;
                    }
                },
                None => {
                    return;
                },
            }
        }

        if result.frames_pushed > 1 {
            stack_frames.pop();
            result.frames_pushed -= 1;
        }
    }
}
