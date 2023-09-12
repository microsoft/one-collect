use std::marker::PhantomData;
use std::arch::asm;
use std::rc::Rc;

use super::abi;
use super::*;

pub mod source;

/* Arch: X64 */
#[cfg(target_arch = "x86_64")]
unsafe fn rmb() {
    asm!("lfence");
}

#[cfg(target_arch = "x86_64")]
unsafe fn mb() {
    asm!("mfence");
}

/* Arch: ARM64 */
#[cfg(target_arch = "aarch64")]
unsafe fn rmb() {
    asm!("dsb ld");
}

#[cfg(target_arch = "aarch64")]
unsafe fn mb() {
    asm!("dsb sy");
}

pub struct RingBufOptions {
    attributes: perf_event_attr,
}

impl Default for RingBufOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBufOptions {
    fn common_attributes() -> perf_event_attr {
        perf_event_attr {
            size: PERF_ATTR_SIZE_VER4,
            flags: FLAG_USE_CLOCKID |
                FLAG_SAMPLE_ID_ALL |
                FLAG_DISABLED |
                FLAG_EXCLUDE_HV |
                FLAG_EXCLUDE_IDLE,
            clockid: CLOCK_MONOTONIC_RAW,
            read_format: abi::PERF_FORMAT_ID,
            sample_type: abi::PERF_SAMPLE_IDENTIFIER |
                abi::PERF_SAMPLE_TIME |
                abi::PERF_SAMPLE_TID,
            /* Leave rest default */
            .. Default::default()
        }
    }

    fn attributes(&self) -> perf_event_attr {
        self.attributes
    }

    pub fn new() -> Self {
        Self {
            attributes: Self::common_attributes(),
        }
    }

    pub fn with_callchain_data(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.sample_type |= abi::PERF_SAMPLE_CALLCHAIN;

        Self {
            attributes,
        }
    }

    pub fn without_user_callchain_data(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_EXCLUDE_CALLCHAIN_USER;

        Self {
            attributes,
        }
    }

    pub fn without_kernel_callchain_data(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_EXCLUDE_CALLCHAIN_KERNEL;

        Self {
            attributes,
        }
    }

    pub fn with_user_regs_data(
        &self,
        regs: u64) -> Self {
        let mut attributes = self.attributes;

        attributes.sample_type |= abi::PERF_SAMPLE_REGS_USER;
        attributes.sample_regs_user = regs;

        Self {
            attributes,
        }
    }

    pub fn with_user_stack_data(
        &self,
        stack_bytes: u32) -> Self {
        let mut attributes = self.attributes;

        attributes.sample_type |= abi::PERF_SAMPLE_STACK_USER;
        attributes.sample_stack_user = stack_bytes;

        Self {
            attributes,
        }
    }
}

pub fn cpu_count() -> u32 {
    unsafe {
        const SC_NPROCESSORS_ONLN: i32 = 84;

        sysconf(SC_NPROCESSORS_ONLN) as u32
    }
}

fn perf_event_open(
    attr: &perf_event_attr,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: usize) -> IOResult<usize> {
    unsafe {
        match syscalls::syscall5(
            syscalls::Sysno::perf_event_open,
            attr as *const perf_event_attr as usize,
            pid as usize,
            cpu as usize,
            group_fd as usize,
            flags) {
            Ok(result) => Ok(result),
            Err(error) => Err(error.into())
        }
    }
}

pub struct Profiling;
pub struct ContextSwitches;
pub struct Tracepoint;
pub struct Kernel;

pub struct RingBufBuilder<T = Profiling> {
    attributes: perf_event_attr,
    _type: PhantomData<T>,
}

impl RingBufBuilder {
    pub fn for_kernel() -> RingBufBuilder<Kernel> {
        let mut options = RingBufOptions::new();

        options.attributes.event_type = PERF_TYPE_SOFTWARE;
        options.attributes.config = PERF_COUNT_SW_DUMMY;

        RingBufBuilder::<Kernel> {
            attributes: options.attributes,
            _type: PhantomData::<Kernel>,
        }
    }

    pub fn for_cswitches(options: &RingBufOptions) -> RingBufBuilder<ContextSwitches> {
        let mut attributes = options.attributes();

        attributes.event_type = PERF_TYPE_SOFTWARE;
        attributes.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
        attributes.sample_period_freq = 1;

        RingBufBuilder::<ContextSwitches> {
            attributes,
            _type: PhantomData::<ContextSwitches>,
        }
    }

    pub fn for_profiling(
        options: &RingBufOptions,
        sampling_frequency: u64) -> RingBufBuilder<Profiling> {
        let mut attributes = options.attributes();

        attributes.event_type = PERF_TYPE_SOFTWARE;
        attributes.config = PERF_COUNT_SW_CPU_CLOCK;
        attributes.sample_period_freq = sampling_frequency;
        attributes.flags |= FLAG_FREQ;

        RingBufBuilder::<Profiling> {
            attributes,
            _type: PhantomData::<Profiling>,
        }
    }

    pub fn for_tracepoint(options: &RingBufOptions) -> RingBufBuilder<Tracepoint> {
        let mut attributes = options.attributes();

        attributes.event_type = PERF_TYPE_TRACEPOINT;
        attributes.sample_period_freq = 1;

        attributes.sample_type |= abi::PERF_SAMPLE_RAW;

        RingBufBuilder::<Tracepoint> {
            attributes,
            _type: PhantomData::<Tracepoint>,
        }
    }
}

impl RingBufBuilder<Profiling> {
    pub(crate) fn build(&self) -> CommonRingBuf {
        CommonRingBuf::new(self.attributes)
    }
}

impl RingBufBuilder<ContextSwitches> {
    pub(crate) fn build(&self) -> CommonRingBuf {
        CommonRingBuf::new(self.attributes)
    }
}

impl RingBufBuilder<Tracepoint> {
    pub(crate) fn build(
        &self,
        tracepoint_id: u64) -> CommonRingBuf {
        let mut attributes = self.attributes;

        /*
         * We need to support live adding more events so we
         * copy then update the tracepoint id live here.
         */
        attributes.config = tracepoint_id;

        CommonRingBuf::new(attributes)
    }
}

impl RingBufBuilder<Kernel> {
    pub fn with_mmap_records(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_MMAP | FLAG_MMAP2;

        Self {
            attributes,
            _type: self._type,
        }
    }

    pub fn with_comm_records(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_COMM | FLAG_COMM_EXEC;

        Self {
            attributes,
            _type: self._type,
        }
    }

    pub fn with_task_records(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_TASK;

        Self {
            attributes,
            _type: self._type,
        }
    }

    pub fn with_cswitch_records(&self) -> Self {
        let mut attributes = self.attributes;

        attributes.flags |= FLAG_CONTEXT_SWITCH;

        Self {
            attributes,
            _type: self._type,
        }
    }

    pub(crate) fn build(&self) -> CommonRingBuf {
        CommonRingBuf::new(self.attributes)
    }
}

#[repr(C)]
#[derive(Default)]
struct read_format {
    value: u64,
    id: u64,
}

/* Libc calls */
extern "C" {
    fn sysconf(name: i32) -> isize;

    fn mmap64(
        addr: *mut u8,
        len: isize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: u64) -> *mut u8;

    fn read(
        fd: i32,
        buf: *mut u8,
        count: usize) -> isize;

    fn ioctl(
        fd: i32,
        req: i32,
        ...) -> i32;

    fn munmap(
        pages: *mut u8,
        len: isize) -> i32;

    fn close(fd: i32) -> i32;
}

pub(crate) struct CommonRingBuf {
    attributes: Rc<perf_event_attr>,
}

impl CommonRingBuf {
    pub fn new(
        attributes: perf_event_attr) -> Self {
        Self {
            attributes: Rc::new(attributes),
        }
    }

    pub fn for_cpu(
        &self,
        cpu: u32) -> CpuRingBuf {
        CpuRingBuf::new(
            cpu,
            self.attributes.clone())
    }
}

#[derive(Default)]
pub(crate) struct CpuRingCursor {
    start: u64,
    end: u64,
}

impl CpuRingCursor {
    pub fn set(
        &mut self,
        start: u64,
        end: u64) {
        self.start = start;
        self.end = end;
    }

    pub fn advance(
        &mut self,
        len: u16) {
        self.start += len as u64;
    }

    pub fn more(&self) -> bool {
        self.start < self.end
    }

    pub fn start(&self) -> u64 {
        self.start
    }
}

pub(crate) struct CpuRingReader {
    pages: *mut u8,
    pages_len: isize,
    data_offset: u64,
    data_size: u64,
    data_mask: u64,
}

impl<'a> CpuRingReader {
    pub fn new(
        pages: *mut u8,
        pages_len: isize) -> Self {
        let slice = unsafe {
            std::slice::from_raw_parts(
                pages,
                pages_len as usize)
        };

        let data_offset = u64::from_ne_bytes(
            slice[1040..1048].try_into().unwrap());

        let data_size = u64::from_ne_bytes(
            slice[1048..1056].try_into().unwrap());

        Self {
            pages,
            pages_len,
            data_offset,
            data_size,
            data_mask: data_size - 1,
        }
    }

    fn slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.pages,
                self.pages_len as usize)
        }
    }

    pub fn begin_reading(
        &self,
        cursor: &mut CpuRingCursor) {
        let head = self.head();

        unsafe {
            rmb();
        }

        let tail = self.tail();

        cursor.set(tail, head);
    }

    pub fn data_slice(
        &'a self) -> &'a [u8] {
        let slice = self.slice();
        let data_start = self.data_offset as usize;
        let data_end = data_start + self.data_size as usize;
        &slice[data_start..data_end]
    }

    pub fn peek_header(
        &'a self,
        cursor: &CpuRingCursor,
        data_slice: &'a [u8],
        start: &mut usize) -> IOResult<abi::Header> {
        *start = (cursor.start() & self.data_mask) as usize;
        let end = *start + abi::Header::data_offset();
        let header_slice = &data_slice[*start .. end];

        match abi::Header::from_slice(header_slice) {
            Ok(header) => Ok(header),
            Err(_) => { Err(io_error(
                "Header slice was not large enough."))
            }
        }
    }

    pub fn peek_u64(
        &self,
        cursor: &CpuRingCursor,
        offset: u64) -> u64 {
        let start = ((cursor.start() + offset) & self.data_mask) as usize;
        let end = start + 8;

        let data_slice = self.data_slice();
        u64::from_ne_bytes(data_slice[start..end].try_into().unwrap())
    }

    pub fn read(
        &'a self,
        cursor: &mut CpuRingCursor,
        temp: &'a mut Vec<u8>) -> IOResult<&'a [u8]> {
        let data_slice = self.data_slice();
        let mut header_start = 0;

        let header = self.peek_header(
            cursor,
            data_slice,
            &mut header_start)?;

        let data_size = header.size as usize;
        let data_end = header_start + data_size;

        cursor.advance(header.size);

        if header_start + data_size <= self.data_size as usize {
            /* Fits within slice, no copy */
            Ok(&data_slice[header_start .. data_end])
        } else {
            /* Data wrapped, requires copy */
            temp.clear();
            temp.extend_from_slice(&data_slice[header_start..]);
            let remaining = data_size - temp.len();
            temp.extend_from_slice(&data_slice[0..remaining]);

            Ok(&temp[0..])
        }
    }

    pub fn end_reading(
        &mut self,
        cursor: &CpuRingCursor) {
        unsafe {
            mb();
            let tail: *mut u64 = self.pages.offset(1032) as *mut u64;
            *tail = cursor.start();
        }
    }

    fn head(&self) -> u64 {
        let slice = self.slice();
        u64::from_ne_bytes(
            slice[1024..1032].try_into().unwrap())
    }

    fn tail(&self) -> u64 {
        let slice = self.slice();
        u64::from_ne_bytes(
            slice[1032..1040].try_into().unwrap())
    }
}

impl Drop for CpuRingReader {
    fn drop(&mut self) {
        unsafe {
            munmap(self.pages, self.pages_len);
        }
    }
}

pub(crate) struct CpuRingBuf {
    cpu: u32,
    attributes: Rc<perf_event_attr>,
    sample_time_offset: u16,
    fd: Option<i32>,
    id: Option<u64>,
}

impl CpuRingBuf {
    pub fn new(
        cpu: u32,
        attributes: Rc<perf_event_attr>) -> Self {
        let mut sample_time_offset = abi::Header::data_offset() as u16;

        if attributes.has_format(abi::PERF_SAMPLE_IDENTIFIER) {
            sample_time_offset += 8;
        }

        if attributes.has_format(abi::PERF_SAMPLE_IP) {
            sample_time_offset += 8;
        }

        if attributes.has_format(abi::PERF_SAMPLE_TID) {
            sample_time_offset += 8;
        }

        Self {
            cpu,
            attributes,
            sample_time_offset,
            fd: None,
            id: None,
        }
    }

    pub fn ancillary(&self) -> AncillaryData {
        AncillaryData {
            cpu: self.cpu,
            attributes: self.attributes.clone(),
        }
    }

    fn read_id(&self) -> IOResult<u64> {
        match &self.fd {
            Some(fd) => {
                let mut id = read_format::default();

                unsafe {
                    let result = read(
                        *fd,
                        &mut id as *mut read_format as *mut u8,
                        16);

                    if result == -1 {
                        return Err(IOError::last_os_error());
                    }
                }

                Ok(id.id)
            },

            None => Err(io_error(
                "Ring buffer is not open."))
        }
    }

    pub fn sample_time_offset(&self) -> u16 {
        self.sample_time_offset
    }

    pub fn id(&self) -> Option<u64> {
        self.id
    }

    pub fn open(
        &mut self,
        target_pid: Option<i32>) -> IOResult<()> {
        let pid = target_pid.unwrap_or(-1);

        let fd = perf_event_open(
            &self.attributes,
            pid,
            self.cpu as i32,
            -1,
            0)?;

        self.fd = Some(fd as i32);
        self.id = Some(self.read_id()?);

        Ok(())
    }

    pub fn create_reader(
        &self,
        page_count: usize) -> IOResult<CpuRingReader> {
        if self.fd.is_none() {
            return Err(io_error(
                "Ring buffer is not open."));
        }

        let page_count = page_count.next_power_of_two() + 1;

        unsafe {
            const SC_PAGE_SIZE: i32 = 30;
            const PROT_READ: i32 = 1;
            const PROT_WRITE: i32 = 2;
            const MAP_SHARED: i32 = 1;
            const MAP_FAILED: *mut u8 = !0 as *mut u8;

            let page_size = sysconf(SC_PAGE_SIZE);
            let pages_len = page_count as isize * page_size;

            let pages = mmap64(
                std::ptr::null_mut::<u8>(),
                pages_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                self.fd.unwrap(),
                0);

            if pages == MAP_FAILED {
                return Err(IOError::last_os_error());
            }

            Ok(CpuRingReader::new(
                pages,
                pages_len))
        }
    }

    pub fn enable(
        &self) -> IOResult<()> {
        if self.fd.is_none() {
            return Err(io_error(
                "Ring buffer is not open."));
        }

        unsafe {
            let result = ioctl(
                self.fd.unwrap(),
                PERF_EVENT_IOC_ENABLE);

            if result != 0 {
                return Err(IOError::last_os_error());
            }
        };

        Ok(())
    }

    pub fn disable(
        &self) -> IOResult<()> {
        if self.fd.is_none() {
            return Err(io_error(
                "Ring buffer is not open."));
        }

        unsafe {
            let result = ioctl(
                self.fd.unwrap(),
                PERF_EVENT_IOC_DISABLE);

            if result != 0 {
                return Err(IOError::last_os_error());
            }
        };

        Ok(())
    }

    pub fn redirect_to(
        &self, 
        target: &Self) -> IOResult<()> {
        if self.fd.is_none() || target.fd.is_none() {
            return Err(io_error(
                "Ring buffer or target is not open."));
        }

        unsafe {
            let result = ioctl(
                self.fd.unwrap(),
                PERF_EVENT_IOC_SET_OUTPUT,
                target.fd.unwrap());

            if result == -1 {
                return Err(IOError::last_os_error());
            }

            Ok(())
        }
    }
}

impl Drop for CpuRingBuf {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe {
                close(fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swap(
        source: &[u8],
        dest: &mut [u8]) {
        let mut i: usize = 0;

        for b in source {
            dest[i] = *b;
            i += 1;
        }
    }

    #[test]
    fn reader() {
        let mut temp = Vec::new();

        let mut data = Vec::new();
        data.resize(2 * 4096, 0);

        let slice = data.as_mut_slice();

        /* Data Offset: 4096 */
        swap(
            &4096u64.to_ne_bytes(),
            &mut slice[1040..1048]);

        /* Data Size: 4096 */
        swap(
            &4096u64.to_ne_bytes(),
            &mut slice[1048..1056]);

        /* Write a few entries */
        let mut entry = Vec::new();

        /* 1 */
        abi::Header::write(1024, 0, &1u64.to_ne_bytes(), &mut entry);

        /* 2 */
        abi::Header::write(1024, 0, &2u64.to_ne_bytes(), &mut entry);

        /* 3 */
        abi::Header::write(1024, 0, &3u64.to_ne_bytes(), &mut entry);

        /* Add entry to ring buffer */
        swap(
            entry.as_slice(),
            &mut slice[4096..]);

        /* Head position */
        swap(
            &(entry.len() as u64).to_ne_bytes(),
            &mut slice[1024..1032]);

        /* Tail position */
        swap(
            &0u64.to_ne_bytes(),
            &mut slice[1032..1040]);

        let mut reader = CpuRingReader::new(
            data.as_mut_ptr(),
            data.len() as isize);

        let mut cursor = CpuRingCursor::default();
        reader.begin_reading(&mut cursor);

        assert_eq!(true, cursor.more());

        /* 1 */
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        let header = abi::Header::from_slice(read).unwrap();
        assert_eq!(1024, header.entry_type);
        assert_eq!(16, header.size);
        assert_eq!(16, read.len());
        assert_eq!(1, u64::from_ne_bytes(read[8..16].try_into().unwrap()));

        /* 2 */
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        let header = abi::Header::from_slice(read).unwrap();
        assert_eq!(1024, header.entry_type);
        assert_eq!(16, header.size);
        assert_eq!(16, read.len());
        assert_eq!(2, u64::from_ne_bytes(read[8..16].try_into().unwrap()));

        /* 3 */
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        let header = abi::Header::from_slice(read).unwrap();
        assert_eq!(1024, header.entry_type);
        assert_eq!(16, header.size);
        assert_eq!(16, read.len());
        assert_eq!(3, u64::from_ne_bytes(read[8..16].try_into().unwrap()));

        /* Reading after end results in 0 sized slice */
        assert_eq!(false, cursor.more());
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        assert_eq!(0, read.len());

        reader.end_reading(&cursor);
        drop(reader);

        let slice = data.as_mut_slice();

        /* Add wrapping entry */
        entry.clear();

        /* 4 */
        abi::Header::write(1024, 0, &4u64.to_ne_bytes(), &mut entry);

        /* Add entry to ring buffer */
        swap(
            &entry.as_slice()[0..8],
            &mut slice[8184..8192]);

        swap(
            &entry.as_slice()[8..16],
            &mut slice[4096..4104]);

        /* Head position: 8200 */
        swap(
            &8200u64.to_ne_bytes(),
            &mut slice[1024..1032]);

        /* Tail position: 8184 */
        swap(
            &8184u64.to_ne_bytes(),
            &mut slice[1032..1040]);

        let mut reader = CpuRingReader::new(
            data.as_mut_ptr(),
            data.len() as isize);

        reader.begin_reading(&mut cursor);

        assert_eq!(true, cursor.more());

        /* 4 */
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        let header = abi::Header::from_slice(read).unwrap();
        assert_eq!(1024, header.entry_type);
        assert_eq!(16, header.size);
        assert_eq!(16, read.len());
        assert_eq!(4, u64::from_ne_bytes(read[8..16].try_into().unwrap()));

        /* Reading after end results in 0 sized slice */
        assert_eq!(false, cursor.more());
        let read = reader.read(&mut cursor, &mut temp).unwrap();
        assert_eq!(0, read.len());

        reader.end_reading(&cursor);

        /* Ensure update stuck */
        reader.begin_reading(&mut cursor);
        assert_eq!(false, cursor.more());
        reader.end_reading(&cursor);
    }

    #[test]
    #[ignore]
    fn open_close() {
        println!("NOTE: Requires sudo/SYS_CAP_ADMIN/tracefs access.");

        let cpu = 0;
        let pid = Some(0);
        let mut rb_head = RingBufBuilder::for_kernel().build().for_cpu(cpu);

        rb_head.open(pid).unwrap();

        let kernel = RingBufBuilder::for_kernel()
            .with_mmap_records();

        let page_count = 1;
        let _reader = rb_head.create_reader(page_count).unwrap();

        let mut rb = kernel.build().for_cpu(cpu);
        rb.open(pid).unwrap();
        rb.redirect_to(&rb_head).unwrap();
        rb.enable().unwrap();
    }
}
