use std::array::TryFromSliceError;

// Current possible sample layout:
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
pub const PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
pub const PERF_SAMPLE_CGROUP: u64 = 1 << 21;

// Supported record types (header.entry_type)
pub const PERF_RECORD_SAMPLE: u32 = 9;

// Known read formats
pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
pub const PERF_FORMAT_ID: u64 = 1 << 2;
pub const PERF_FORMAT_GROUP: u64 = 1 << 3;
pub const PERF_FORMAT_LOST: u64 = 1 << 4;

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
