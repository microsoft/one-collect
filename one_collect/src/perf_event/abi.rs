use std::array::TryFromSliceError;

// Current possible sample layout:
// u64    id;          /* if PERF_SAMPLE_IDENTIFIER */
// u64    ip;          /* if PERF_SAMPLE_IP */
// u32    pid, tid;    /* if PERF_SAMPLE_TID */
// u64    time;        /* if PERF_SAMPLE_TIME */
// u64    addr;        /* if PERF_SAMPLE_ADDR */
// u64    id;          /* if PERF_SAMPLE_ID */
// u64    stream_id;   /* if PERF_SAMPLE_STREAM_ID */
// u32    cpu, res;    /* if PERF_SAMPLE_CPU */
// u64    period;      /* if PERF_SAMPLE_PERIOD */
// struct read_format v;
//                   /* if PERF_SAMPLE_READ */
// u64    nr;          /* if PERF_SAMPLE_CALLCHAIN */
// u64    ips[nr];     /* if PERF_SAMPLE_CALLCHAIN */
// u32    size;        /* if PERF_SAMPLE_RAW */
// char   data[size];  /* if PERF_SAMPLE_RAW */
// u64    bnr;         /* if PERF_SAMPLE_BRANCH_STACK */
// struct perf_branch_entry lbr[bnr];
//                   /* if PERF_SAMPLE_BRANCH_STACK */
// u64    abi;         /* if PERF_SAMPLE_REGS_USER */
// u64    regs[weight(mask)];
//                   /* if PERF_SAMPLE_REGS_USER */
// u64    size;        /* if PERF_SAMPLE_STACK_USER */
// char   data[size];  /* if PERF_SAMPLE_STACK_USER */
// u64    dyn_size;    /* if PERF_SAMPLE_STACK_USER &&
//                     size != 0 */
// u64    weight;      /* if PERF_SAMPLE_WEIGHT */
// u64    data_src;    /* if PERF_SAMPLE_DATA_SRC */
// u64    transaction; /* if PERF_SAMPLE_TRANSACTION */
// u64    abi;         /* if PERF_SAMPLE_REGS_INTR */
// u64    regs[weight(mask)]; /* if PERF_SAMPLE_REGS_INTR */
// u64    phys_addr;   /* if PERF_SAMPLE_PHYS_ADDR */
// u64    cgroup;      /* if PERF_SAMPLE_CGROUP */
//
pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_READ: u64 = 1 << 4;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;
pub const PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
pub const PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
pub const PERF_SAMPLE_DATA_SRC: u64 = 1 << 15;
pub const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
pub const PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
pub const PERF_SAMPLE_AUX: u64 = 1 << 20;
pub const PERF_SAMPLE_CGROUP: u64 = 1 << 21;

pub const PERF_SAMPLE_REGS_ABI_NONE: u64 = 0;
pub const PERF_SAMPLE_REGS_ABI_32: u64 = 1;
pub const PERF_SAMPLE_REGS_ABI_64: u64 = 2;

// Supported record types (header.entry_type)
pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_COMM: u32 = 3;
pub const PERF_RECORD_EXIT: u32 = 4;
pub const PERF_RECORD_FORK: u32 = 7;
pub const PERF_RECORD_SAMPLE: u32 = 9;
pub const PERF_RECORD_MMAP2: u32 = 10;
pub const PERF_RECORD_LOST_SAMPLES: u32 = 13;
pub const PERF_RECORD_SWITCH_CPU_WIDE: u32 = 15;

// Known read formats
pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
pub const PERF_FORMAT_ID: u64 = 1 << 2;
pub const PERF_FORMAT_GROUP: u64 = 1 << 3;
pub const PERF_FORMAT_LOST: u64 = 1 << 4;

pub const FLAG_DISABLED: u64 = 1 << 0;
pub const FLAG_INHERIT: u64 = 1 << 1;
pub const FLAG_PINNED: u64 = 1 << 2;
pub const FLAG_EXCLUSIVE: u64 = 1 << 3;
pub const FLAG_EXCLUDE_USER: u64 = 1 << 4;
pub const FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
pub const FLAG_EXCLUDE_HV: u64 = 1 << 6;
pub const FLAG_EXCLUDE_IDLE: u64 = 1 << 7;
pub const FLAG_MMAP: u64 = 1 << 8;
pub const FLAG_COMM: u64 = 1 << 9;
pub const FLAG_FREQ: u64 = 1 << 10;
pub const FLAG_INHERIT_STAT: u64 = 1 << 11;
pub const FLAG_ENABLE_ON_EXEC: u64 = 1 << 12;
pub const FLAG_TASK: u64 = 1 << 13;
pub const FLAG_WATERMARK: u64 = 1 << 14;
pub const FLAG_PRECISE_IP: u64 = 1 << 15;
pub const FLAG_PRECISE_NO_SKID: u64 = 1 << 16;
pub const FLAG_MMAP_DATA: u64 = 1 << 17;
pub const FLAG_SAMPLE_ID_ALL: u64 = 1 << 18;
pub const FLAG_EXCLUDE_HOST: u64 = 1 << 19;
pub const FLAG_EXCLUDE_GUEST: u64 = 1 << 20;
pub const FLAG_EXCLUDE_CALLCHAIN_KERNEL: u64 = 1 << 21;
pub const FLAG_EXCLUDE_CALLCHAIN_USER: u64 = 1 << 22;
pub const FLAG_MMAP2: u64 = 1 << 23;
pub const FLAG_COMM_EXEC: u64 = 1 << 24;
pub const FLAG_USE_CLOCKID: u64 = 1 << 25;
pub const FLAG_CONTEXT_SWITCH: u64 = 1 << 26;
pub const FLAG_WRITE_BACKWARD: u64 = 1 << 27;
pub const FLAG_NAMESPACES: u64 = 1 << 28;
pub const FLAG_KSYMBOL: u64 = 1 << 29;
pub const FLAG_BPF_EVENT: u64 = 1 << 30;
pub const FLAG_AUX_OUTPUT: u64 = 1 << 31;
pub const FLAG_CGROUP: u64 = 1 << 32;
pub const FLAG_TEXT_POKE: u64 = 1 << 33;

pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC_RAW: i32 = 4;

pub const PERF_TYPE_HARDWARE: u32 = 0;
pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_TYPE_TRACEPOINT: u32 = 2;

pub const PERF_EVENT_IOC_ENABLE: i32 = 9216;
pub const PERF_EVENT_IOC_DISABLE: i32 = 9217;
pub const PERF_EVENT_IOC_SET_OUTPUT: i32 = 9221;

pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
pub const PERF_COUNT_SW_DUMMY: u64 = 9;

pub const PERF_ATTR_SIZE_VER4: u32 = 104;

/* X86_64 Common Registers */
#[cfg(target_arch = "x86_64")]
pub const PERF_REG_BP: u64 = 1 << 6u64;
#[cfg(target_arch = "x86_64")]
pub const PERF_REG_SP: u64 = 1 << 7u64;
#[cfg(target_arch = "x86_64")]
pub const PERF_REG_IP: u64 = 1 << 8u64;

/* ARM64 Common Registers */
#[cfg(target_arch = "aarch64")]
pub const PERF_REG_BP: u64 = 1 << 30u64;
#[cfg(target_arch = "aarch64")]
pub const PERF_REG_SP: u64 = 1 << 31u64;
#[cfg(target_arch = "aarch64")]
pub const PERF_REG_IP: u64 = 1 << 32u64;

#[repr(C)]
#[derive(Copy)]
#[derive(Clone)]
#[derive(Default)]
pub struct perf_event_attr {
   pub event_type: u32,
   pub size: u32,
   pub config: u64,
   pub sample_period_freq: u64,
   pub sample_type: u64,
   pub read_format: u64,
   pub flags: u64,
   pub wakeup_events_watermark: u32,
   pub bp_type: u32,
   pub bp_addr: u64,
   pub bp_len: u64,
   pub branch_sample_type: u64,
   pub sample_regs_user: u64,
   pub sample_stack_user: u32,
   pub clockid: i32,
   pub sample_regs_intr: u64,
}

#[derive(Default)]
pub struct SampleIdOffsets {
    pub pid: Option<usize>,
    pub tid: Option<usize>,
    pub time: Option<usize>,
    pub id: Option<usize>,
    pub stream_id: Option<usize>,
    pub cpu: Option<usize>,
    pub identifier: Option<usize>,
    pub size: usize,
}

impl perf_event_attr {
    pub fn has_flag(
        &self,
        flag: u64) -> bool {
        (self.flags & flag) == flag
    }
    pub fn has_format(
        &self,
        format: u64) -> bool {
        (self.sample_type & format) == format
    }

    pub fn has_read_format(
        &self,
        format: u64) -> bool {
        (self.read_format & format) == format
    }

    pub fn non_sampled_id_offsets(&self) -> Option<SampleIdOffsets> {
        /* Cannot fetch these from non-sampled records */
        if !self.has_flag(FLAG_SAMPLE_ID_ALL) {
            return None;
        }

        /* Determine which parts are where, if at all */
        let mut offset = SampleIdOffsets::default();

        if self.has_format(PERF_SAMPLE_TID) {
            offset.pid = Some(offset.size);
            offset.size += 4;

            offset.tid = Some(offset.size);
            offset.size += 4;
        }

        if self.has_format(PERF_SAMPLE_TIME) {
            offset.time = Some(offset.size);
            offset.size += 8;
        }

        if self.has_format(PERF_SAMPLE_ID) {
            offset.id = Some(offset.size);
            offset.size += 8;
        }

        if self.has_format(PERF_SAMPLE_STREAM_ID) {
            offset.stream_id = Some(offset.size);
            offset.size += 8;
        }

        if self.has_format(PERF_SAMPLE_CPU) {
            offset.cpu = Some(offset.size);
            offset.size += 8;
        }

        if self.has_format(PERF_SAMPLE_IDENTIFIER) {
            offset.identifier = Some(offset.size);
            offset.size += 8;
        }

        Some(offset)
    }
}

pub struct Header<'a> {
    pub entry_type: u32,
    pub misc: u16,
    pub size: u16,
    pub data: &'a [u8],
}

impl<'a> Header<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Header<'a>, TryFromSliceError> {
        Ok(Self {
            entry_type: Self::entry_type(slice)?,
            misc: Self::misc(slice)?,
            size: Self::size(slice)?,
            data: Self::data(slice),
        })
    }

    fn entry_type(slice: &[u8]) -> Result<u32, TryFromSliceError> {
        let slice = slice[0..4].try_into()?;

        Ok(u32::from_ne_bytes(slice))
    }

    fn misc(slice: &[u8]) -> Result<u16, TryFromSliceError> {
        let slice = slice[4..6].try_into()?;

        Ok(u16::from_ne_bytes(slice))
    }

    fn size(slice: &[u8]) -> Result<u16, TryFromSliceError> {
        let slice = slice[6..8].try_into()?;

        Ok(u16::from_ne_bytes(slice))
    }

    pub fn data_offset() -> usize {
        8
    }

    fn data(slice: &[u8]) -> &[u8] {
        &slice[Self::data_offset()..]
    }

    pub fn write(
        entry_type: u32,
        misc: u16,
        data: &[u8],
        output: &mut Vec<u8>) {
        /* Account for header itself */
        let size = (data.len() + 8) as u16;
        output.extend_from_slice(&entry_type.to_ne_bytes());
        output.extend_from_slice(&misc.to_ne_bytes());
        output.extend_from_slice(&size.to_ne_bytes());
        output.extend_from_slice(data);
    }
}

pub struct Sample {
}

impl Sample {
    pub fn write_time(
        time: u64,
        output: &mut Vec<u8>) {
        output.extend_from_slice(&time.to_ne_bytes());
    }

    pub fn write_raw(
        data: &[u8],
        output: &mut Vec<u8>) {
        let len = data.len() as u32;

        output.extend_from_slice(&len.to_ne_bytes());
        output.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rw() {
        let mut data = Vec::new();
        let magic: u32 = 1234;
        let magic_slice = magic.to_ne_bytes();

        Header::write(1024, 0, &magic_slice, &mut data);

        let slice = data.as_slice();

        let header = Header::from_slice(slice).unwrap();

        assert_eq!(1024, header.entry_type);
        assert_eq!(0, header.misc);
        assert_eq!(12, header.size);

        let data_slice = header.data;
        let magic_slice = data_slice[0..4].try_into().unwrap();
        assert_eq!(1234, u32::from_ne_bytes(magic_slice));
    }
}
