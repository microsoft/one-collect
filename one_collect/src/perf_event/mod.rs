// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs::File;

use std::time::Duration;
use std::array::TryFromSliceError;
use std::collections::{HashSet, HashMap};
use std::rc::Rc;

use super::*;
use crate::sharing::*;
use crate::event::*;


#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

pub mod abi;
pub mod rb;
mod events;
mod bpf;

use abi::*;

pub use rb::source::RingBufSessionBuilder;
pub use rb::{RingBufOptions, RingBufBuilder};
pub use rb::cpu_count;

static EMPTY: &[u8] = &[];

#[derive(Default)]
pub struct AncillaryData {
    cpu: u32,
    attributes: Rc<perf_event_attr>,
}

impl AncillaryData {
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    pub fn config(&self) -> u64 {
        self.attributes.config
    }

    pub fn event_type(&self) -> u32 {
        self.attributes.event_type
    }

    pub fn sample_type(&self) -> u64 {
        self.attributes.sample_type
    }

    pub fn read_format(&self) -> u64 {
        self.attributes.read_format
    }

    pub fn non_sampled_id_offsets(&self) -> Option<SampleIdOffsets> {
        self.attributes.non_sampled_id_offsets()
    }
}

impl Clone for AncillaryData {
    fn clone(&self) -> Self {
        Self {
            cpu: self.cpu,
            attributes: self.attributes.clone(),
        }
    }
}

pub struct PerfData<'a> {
    pub ancillary: AncillaryData,
    pub raw_data: &'a [u8],
}

impl<'a> Default for PerfData<'a> {
    fn default() -> Self {
        Self {
            ancillary: AncillaryData::default(),
            raw_data: EMPTY,
        }
    }
}

impl<'a> PerfData<'a> {
    fn has_format(
        &self,
        format: u64) -> bool {
        self.ancillary.attributes.has_format(format)
    }

    fn has_read_format(
        &self,
        format: u64) -> bool {
        self.ancillary.attributes.has_read_format(format)
    }

    fn regs_user_count(&self) -> usize {
        self.ancillary.attributes.sample_regs_user.count_ones() as usize
    }

    fn non_sampled_id_offsets(&self) -> Option<SampleIdOffsets> {
        self.ancillary.non_sampled_id_offsets()
    }

    fn read_format_size(&self) -> usize {
        let mut size: usize = 0;

        if self.has_read_format(abi::PERF_FORMAT_TOTAL_TIME_ENABLED) {
            size += 8;
        }

        if self.has_read_format(abi::PERF_FORMAT_TOTAL_TIME_RUNNING) {
            size += 8;
        }

        if self.has_read_format(abi::PERF_FORMAT_ID) {
            size += 8;
        }

        if self.has_read_format(abi::PERF_FORMAT_GROUP) {
            size += 8;
        }

        if self.has_read_format(abi::PERF_FORMAT_LOST) {
            size += 8;
        }

        size
    }

    fn read_u64(
        &self,
        offset: usize) -> Result<u64, TryFromSliceError> {
        let slice = self.raw_data[offset .. offset + 8].try_into()?;

        Ok(u64::from_ne_bytes(slice))
    }

    fn read_u32(
        &self,
        offset: usize) -> Result<u32, TryFromSliceError> {
        let slice = self.raw_data[offset .. offset + 4].try_into()?;

        Ok(u32::from_ne_bytes(slice))
    }

    fn read_u16(
        &self,
        offset: usize) -> Result<u16, TryFromSliceError> {
        let slice = self.raw_data[offset .. offset + 2].try_into()?;

        Ok(u16::from_ne_bytes(slice))
    }
}

pub struct PerfDataFile {
    id: u64,
    fd: i32,
}

impl PerfDataFile {
    pub fn new(
        id: u64,
        fd: i32) -> Self {
        Self {
            id,
            fd,
        }
    }

    pub fn id(&self) -> u64 { self.id }

    pub fn fd(&self) -> i32 { self.fd }
}

pub trait PerfDataSource {
    fn enable(&mut self) -> IOResult<()>;

    fn disable(&mut self) -> IOResult<()>;

    fn target_pids(&self) -> Option<&[i32]>;

    fn create_bpf_files(
        &mut self,
        event: Option<&Event>) -> IOResult<Vec<PerfDataFile>>;

    fn add_event(
        &mut self,
        event: &Event) -> IOResult<()>;

    fn begin_reading(&mut self);

    fn read(
        &mut self,
        timeout: Duration) -> Option<PerfData<'_>>;

    fn end_reading(&mut self);

    fn more(&self) -> bool;
}

pub struct PerfSession {
    source: Box<dyn PerfDataSource>,
    source_enabled: bool,
    events: HashMap<usize, Event>,
    errors: Vec<anyhow::Error>,
    event_error_callback: Option<Box<dyn Fn(&Event, &anyhow::Error)>>,

    /* Raw data fields */
    ip_field: DataFieldRef,
    pid_field: DataFieldRef,
    tid_field: DataFieldRef,
    time_field: DataFieldRef,
    address_field: DataFieldRef,
    id_field: DataFieldRef,
    stream_id_field: DataFieldRef,
    cpu_field: DataFieldRef,
    period_field: DataFieldRef,
    read_field: DataFieldRef,
    callchain_field: DataFieldRef,
    raw_field: DataFieldRef,
    branch_stack_field: DataFieldRef,
    regs_user_field: DataFieldRef,
    stack_user_field: DataFieldRef,

    /* Options */
    read_timeout: Duration,

    /* Events */
    cpu_profile_event: Event,
    cswitch_profile_event: Event,
    lost_event: Event,
    comm_event: Event,
    exit_event: Event,
    fork_event: Event,
    mmap_event: Event,
    lost_samples_event: Event,
    cswitch_event: Event,
    soft_page_fault_event: Event,
    hard_page_fault_event: Event,
    drop_event: Event,

    /* BPF */
    bpf_events: HashMap<u64, Writable<Event>>,
    bpf_map_files: Vec<File>,

    /* Ancillary data */
    ancillary: Writable<AncillaryData>,

    /* Header data (static) */
    misc_field: DataFieldRef,
    data_type_field: DataFieldRef,
}

impl Drop for PerfSession {
    fn drop(&mut self) {
        self.drop_event.process(
            EMPTY,
            EMPTY,
            &mut self.errors);

        self.log_errors(&self.drop_event);
    }
}

impl PerfSession {
    pub fn new(
        source: Box<dyn PerfDataSource>) -> Self {
        /* Increase rlimit for open files */
        unsafe {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                limit.rlim_cur = limit.rlim_max;
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }

        let session = Self {
            source,
            source_enabled: false,
            events: HashMap::new(),
            errors: Vec::new(),
            event_error_callback: None,

            /* Events */
            ip_field: DataFieldRef::new(),
            pid_field: DataFieldRef::new(),
            tid_field: DataFieldRef::new(),
            time_field: DataFieldRef::new(),
            address_field: DataFieldRef::new(),
            id_field: DataFieldRef::new(),
            stream_id_field: DataFieldRef::new(),
            cpu_field: DataFieldRef::new(),
            period_field: DataFieldRef::new(),
            read_field: DataFieldRef::new(),
            callchain_field: DataFieldRef::new(),
            raw_field: DataFieldRef::new(),
            branch_stack_field: DataFieldRef::new(),
            regs_user_field: DataFieldRef::new(),
            stack_user_field: DataFieldRef::new(),

            /* BPF */
            bpf_events: HashMap::new(),
            bpf_map_files: Vec::new(),

            /* Options */
            read_timeout: Duration::from_millis(15),

            /* Events */
            cpu_profile_event: Event::new(0, "__cpu_profile".into()),
            cswitch_profile_event: Event::new(0, "__cswitch_profile".into()),
            soft_page_fault_event: Event::new(0, "__soft_page_fault".into()),
            hard_page_fault_event: Event::new(0, "__hard_page_fault".into()),
            lost_event: events::lost(),
            comm_event: events::comm(),
            exit_event: events::exit(),
            fork_event: events::fork(),
            mmap_event: events::mmap(),
            lost_samples_event: events::lost_samples(),
            cswitch_event: events::cswitch(),
            drop_event: Event::new(0, "__session_drop".into()),

            /* Ancillary data */
            ancillary: Writable::new(AncillaryData::default()),

            /* Header data */
            misc_field: DataFieldRef::new(),
            data_type_field: DataFieldRef::new(),
        };

        /* Header static offsets */
        session.data_type_field.update(0, 4);
        session.misc_field.update(4, 2);

        session
    }

    pub fn set_event_error_callback(
        &mut self,
        callback: impl Fn(&Event, &anyhow::Error) + 'static) {
        self.event_error_callback = Some(Box::new(callback));
    }

    pub fn ancillary_data(&self) -> ReadOnly<AncillaryData> {
        self.ancillary.read_only()
    }

    pub fn cpu_profile_event(&mut self) -> &mut Event {
        &mut self.cpu_profile_event
    }

    pub fn cswitch_profile_event(&mut self) -> &mut Event {
        &mut self.cswitch_profile_event
    }

    pub fn soft_page_fault_event(&mut self) -> &mut Event {
        &mut self.soft_page_fault_event
    }

    pub fn hard_page_fault_event(&mut self) -> &mut Event {
        &mut self.hard_page_fault_event
    }

    pub fn lost_event(&mut self) -> &mut Event {
        &mut self.lost_event
    }

    pub fn comm_event(&mut self) -> &mut Event {
        &mut self.comm_event
    }

    pub fn exit_event(&mut self) -> &mut Event {
        &mut self.exit_event
    }

    pub fn fork_event(&mut self) -> &mut Event {
        &mut self.fork_event
    }

    pub fn mmap_event(&mut self) -> &mut Event {
        &mut self.mmap_event
    }

    pub fn lost_samples_event(&mut self) -> &mut Event {
        &mut self.lost_samples_event
    }

    pub fn cswitch_event(&mut self) -> &mut Event {
        &mut self.cswitch_event
    }

    pub fn drop_event(&mut self) -> &mut Event {
        &mut self.drop_event
    }

    pub fn misc_data_ref(&self) -> DataFieldRef {
        self.misc_field.clone()
    }

    pub fn data_type_ref(&self) -> DataFieldRef {
        self.data_type_field.clone()
    }

    pub fn ip_data_ref(&self) -> DataFieldRef {
        self.ip_field.clone()
    }

    pub fn pid_field_ref(&self) -> DataFieldRef {
        self.pid_field.clone()
    }

    pub fn tid_data_ref(&self) -> DataFieldRef {
        self.tid_field.clone()
    }

    pub fn time_data_ref(&self) -> DataFieldRef {
        self.time_field.clone()
    }

    pub fn address_data_ref(&self) -> DataFieldRef {
        self.address_field.clone()
    }

    pub fn id_data_ref(&self) -> DataFieldRef {
        self.id_field.clone()
    }

    pub fn stream_id_data_ref(&self) -> DataFieldRef {
        self.stream_id_field.clone()
    }

    pub fn cpu_data_ref(&self) -> DataFieldRef {
        self.cpu_field.clone()
    }

    pub fn period_data_ref(&self) -> DataFieldRef {
        self.period_field.clone()
    }

    pub fn read_data_ref(&self) -> DataFieldRef {
        self.read_field.clone()
    }

    pub fn callchain_data_ref(&self) -> DataFieldRef {
        self.callchain_field.clone()
    }

    pub fn raw_data_ref(&self) -> DataFieldRef {
        self.raw_field.clone()
    }

    pub fn branch_stack_data_ref(&self) -> DataFieldRef {
        self.branch_stack_field.clone()
    }

    pub fn regs_user_data_ref(&self) -> DataFieldRef {
        self.regs_user_field.clone()
    }

    pub fn stack_user_data_ref(&self) -> DataFieldRef {
        self.stack_user_field.clone()
    }

    pub fn set_read_timeout(
        &mut self,
        timeout: Duration) {
        self.read_timeout = timeout;
    }

    pub fn create_bpf_files(
        &mut self,
        event: Option<&Event>) -> IOResult<Vec<PerfDataFile>> {
        self.source.create_bpf_files(event)
    }

    pub fn attach_to_bpf_map_path(
        &mut self,
        path: &str,
        event: Event) -> IOResult<()> {
        let path = std::ffi::CString::new(path)?;

        let fd = bpf::bpf_get_map_fd_by_path(&path)?;

        self.attach_to_bpf_map_fd(fd, event)
    }

    pub fn attach_to_bpf_map_id(
        &mut self,
        id: u32,
        event: Event) -> IOResult<()> {
        let fd = bpf::bpf_get_map_fd(id)?;

        self.attach_to_bpf_map_fd(fd, event)
    }

    pub fn attach_to_bpf_map_fd(
        &mut self,
        fd: i32,
        event: Event) -> IOResult<()> {
        let bpf_files = match self.create_bpf_files(Some(&event)) {
            Ok(bpf_files) => { bpf_files },
            Err(err) => {
                /* Close FD, no BPF programs */
                unsafe {
                    libc::close(fd);
                }

                return Err(err);
            }
        };

        let event = Writable::new(event);

        for (i, perf_file) in bpf_files.iter().enumerate() {
            match bpf::bpf_set_map_element(
                fd,
                i as u64,
                (perf_file.fd()) as u64) {
                Ok(()) => {
                    /* Take ownership of FD */
                    let file = unsafe {
                        File::from_raw_fd(fd)
                    };

                    self.bpf_map_files.push(file);
                    self.bpf_events.insert(perf_file.id(), event.clone());
                },
                Err(err) => {
                    /* Close FD on error */
                    unsafe {
                        libc::close(fd);
                    }

                    return Err(err);
                }
            }
        }

        Ok(())
    }

    pub fn add_event(
        &mut self,
        event: Event) -> IOResult<()> {
        self.source.add_event(&event)?;

        self.events.insert(event.id(), event);

        Ok(())
    }

    pub fn enable(&mut self) -> IOResult<()> {
        self.source_enabled = true;
        self.source.enable()
    }

    pub fn disable(&mut self) -> IOResult<()> {
        self.source_enabled = false;
        self.source.disable()
    }

    pub fn parse_all(&mut self) -> Result<(), TryFromSliceError> {
        self.parse_until(|| false)
    }

    pub fn parse_for_duration(
        &mut self,
        duration: Duration) -> Result<(), TryFromSliceError> {
        let now = std::time::Instant::now();

        self.parse_until(|| { now.elapsed() >= duration })
    }

    fn log_errors(
        &self,
        event: &Event) {
        for error in &self.errors {
            if let Some(callback) = &self.event_error_callback {
                callback(event, error);
            } else {
                eprintln!("Error: Event '{}': {}", event.name(), error);
            }
        }
    }

    fn parse_perf_data(
        &mut self,
        perf_data: Option<PerfData>) -> Result<bool, TryFromSliceError> {
        let perf_data = perf_data.or_else(|| {
            self.source.read(self.read_timeout)
        });

        if perf_data.is_none() {
            return Ok(false);
        }

        let perf_data = perf_data.unwrap();
        let header = abi::Header::from_slice(perf_data.raw_data)?;

        self.ancillary.write(|value| {
            *value = perf_data.ancillary.clone();
        });

        /* Always populate available fields for non-samples */
        if header.entry_type != abi::PERF_RECORD_SAMPLE {
            match perf_data.non_sampled_id_offsets() {
                Some(offsets) => {
                    let mut offset = header.size as usize - offsets.size;

                    if offsets.pid.is_some() {
                        offset += self.pid_field.update(offset, 4);
                    } else {
                        self.pid_field.reset();
                    }

                    if offsets.tid.is_some() {
                        offset += self.tid_field.update(offset, 4);
                    } else {
                        self.tid_field.reset();
                    }

                    if offsets.time.is_some() {
                        offset += self.time_field.update(offset, 8);
                    } else {
                        self.time_field.reset();
                    }

                    if offsets.id.is_some() {
                        offset += self.id_field.update(offset, 8);
                    } else {
                        self.id_field.reset();
                    }

                    if offsets.stream_id.is_some() {
                        offset += self.stream_id_field.update(offset, 8);
                    } else {
                        self.stream_id_field.reset();
                    }

                    if offsets.cpu.is_some() {
                        offset += self.cpu_field.update(offset, 8);
                    } else {
                        self.cpu_field.reset();
                    }

                    if offsets.identifier.is_some() {
                        self.id_field.update(offset, 8);
                    }
                },

                /* These fields are not-present outside of event */
                None => {
                    self.pid_field.reset();
                    self.tid_field.reset();
                    self.time_field.reset();
                    self.id_field.reset();
                    self.stream_id_field.reset();
                    self.cpu_field.reset();
                }
            }
        }

        /* Process record payloads */
        match header.entry_type {
            abi::PERF_RECORD_SAMPLE => {
                let mut offset: usize = abi::Header::data_offset();
                let mut id: Option<usize> = None;

                /* PERF_SAMPLE_IDENTIFER */
                if perf_data.has_format(abi::PERF_SAMPLE_IDENTIFIER) {
                    offset += self.id_field.update(offset, 8);
                } else {
                    self.id_field.reset();
                }

                /* PERF_SAMPLE_IP */
                if perf_data.has_format(abi::PERF_SAMPLE_IP) {
                    offset += self.ip_field.update(offset, 8);
                } else {
                    self.ip_field.reset();
                }

                /* PERF_SAMPLE_TID */
                if perf_data.has_format(abi::PERF_SAMPLE_TID) {
                    offset += self.pid_field.update(offset, 4);
                    offset += self.tid_field.update(offset, 4);
                } else {
                    self.pid_field.reset();
                    self.tid_field.reset();
                }

                /* PERF_SAMPLE_TIME */
                if perf_data.has_format(abi::PERF_SAMPLE_TIME) {
                    offset += self.time_field.update(offset, 8);
                } else {
                    self.time_field.reset();
                }

                /* PERF_SAMPLE_ADDR */
                if perf_data.has_format(abi::PERF_SAMPLE_ADDR) {
                    offset += self.address_field.update(offset, 8);
                } else {
                    self.address_field.reset();
                }

                /* PERF_SAMPLE_ID */
                if perf_data.has_format(abi::PERF_SAMPLE_ID) {
                    /* Update only, no reset */
                    offset += self.id_field.update(offset, 8);
                }

                /* PERF_SAMPLE_STREAM_ID */
                if perf_data.has_format(abi::PERF_SAMPLE_STREAM_ID) {
                    offset += self.stream_id_field.update(offset, 8);
                } else {
                    self.stream_id_field.reset();
                }

                /* PERF_SAMPLE_CPU */
                if perf_data.has_format(abi::PERF_SAMPLE_CPU) {
                    offset += self.cpu_field.update(offset, 8);
                } else {
                    self.cpu_field.reset();
                }

                /* PERF_SAMPLE_PERIOD */
                if perf_data.has_format(abi::PERF_SAMPLE_PERIOD) {
                    offset += self.period_field.update(offset, 8);
                } else {
                    self.period_field.reset();
                }

                /* PERF_SAMPLE_READ */
                if perf_data.has_format(abi::PERF_SAMPLE_READ) {
                    let read_size = perf_data.read_format_size();
                    offset += self.read_field.update(offset, read_size);
                } else {
                    self.read_field.reset();
                }

                /* PERF_SAMPLE_CALLCHAIN */
                if perf_data.has_format(abi::PERF_SAMPLE_CALLCHAIN) {
                    let count = perf_data.read_u64(offset)?;
                    let size = (count * 8) as usize;
                    offset += 8;
                    offset += self.callchain_field.update(offset, size);
                } else {
                    self.callchain_field.reset();
                }

                /* PERF_SAMPLE_RAW */
                if perf_data.has_format(abi::PERF_SAMPLE_RAW) {
                    let size = perf_data.read_u32(offset)? as usize;
                    offset += 4;
                    id = Some(perf_data.read_u16(offset)? as usize);
                    offset += self.raw_field.update(offset, size);
                } else {
                    self.raw_field.reset();
                }

                /* PERF_SAMPLE_BRANCH_STACK */
                if perf_data.has_format(abi::PERF_SAMPLE_BRANCH_STACK) {
                    let count = perf_data.read_u64(offset)? as usize;
                    offset += 8;
                    let size = count * 24;
                    offset += self.branch_stack_field.update(offset, size);
                } else {
                    self.branch_stack_field.reset();
                }

                /* PERF_SAMPLE_REGS_USER */
                if perf_data.has_format(abi::PERF_SAMPLE_REGS_USER) {
                    let abi = perf_data.read_u64(offset)?;
                    offset += 8;
                    let count = perf_data.regs_user_count();
                    /*
                     * ABI is 0 for none, 1 for 32-bit, 2 for 64-bit:
                     * Therefore, abi * 4 gives us the bytes per-reg.
                     */
                    let size = count * (abi * 4) as usize;
                    offset += self.regs_user_field.update(offset, size);
                } else {
                    self.regs_user_field.reset();
                }

                /* PERF_SAMPLE_STACK_USER */
                if perf_data.has_format(abi::PERF_SAMPLE_STACK_USER) {
                    let size = perf_data.read_u64(offset)? as usize;
                    offset += 8;

                    if size > 0 {
                        let stack_start = offset;
                        offset += size;
                        /* Actual size of read stack data */
                        let dyn_size = perf_data.read_u64(offset)? as usize;
                        offset += 8;
                        /* Caller is only given read stack data */
                        self.stack_user_field.update(stack_start, dyn_size);
                    } else {
                        self.stack_user_field.reset();
                    }
                } else {
                    self.stack_user_field.reset();
                }

                /* TODO: Remaining abi format types */

                /* For now print warning if we see this */
                if offset > perf_data.raw_data.len() {
                    eprintln!("WARN: Truncated sample");
                }

                /* Process if we have an ID to use */
                if perf_data.ancillary.config() == PERF_COUNT_SW_BPF_OUTPUT {
                    /* BPF Event */
                    let full_data = perf_data.raw_data;

                    if let Some(id) = self.id_field.try_get_u64(full_data) {
                        if let Some(event) = self.bpf_events.get_mut(&id) {
                            let event_data = self.raw_field.get_data(full_data);

                            event.borrow_mut().process(
                                full_data,
                                event_data,
                                &mut self.errors);
                        }

                        if !self.errors.is_empty() {
                            if let Some(event) = self.bpf_events.get(&id) {
                                self.log_errors(&event.borrow());
                            }
                        }
                    }
                } else if let Some(id) = &id {
                    /* Tracepoint Event */
                    if let Some(event) = self.events.get_mut(id) {
                        let full_data = perf_data.raw_data;
                        let event_data = self.raw_field.get_data(full_data);

                        event.process(
                            full_data,
                            event_data,
                            &mut self.errors);
                    }

                    if !self.errors.is_empty() {
                        if let Some(event) = self.events.get(id) {
                            self.log_errors(&event);
                        }
                    }
                } else {
                    /* Non-event profile sample */
                    match perf_data.ancillary.event_type() {
                        /* Software */
                        PERF_TYPE_SOFTWARE => {
                            match perf_data.ancillary.config() {
                                /* CPU */
                                PERF_COUNT_SW_CPU_CLOCK => {
                                    self.cpu_profile_event.process(
                                        perf_data.raw_data,
                                        perf_data.raw_data,
                                        &mut self.errors);

                                    self.log_errors(&self.cpu_profile_event);
                                },

                                /* CSWITCH */
                                PERF_COUNT_SW_CONTEXT_SWITCHES => {
                                    self.cswitch_profile_event.process(
                                        perf_data.raw_data,
                                        perf_data.raw_data,
                                        &mut self.errors);

                                    self.log_errors(&self.cswitch_profile_event);
                                },

                                /* SOFT PAGE FAULT */
                                PERF_COUNT_SW_PAGE_FAULTS_MIN => {
                                    self.soft_page_fault_event.process(
                                        perf_data.raw_data,
                                        perf_data.raw_data,
                                        &mut self.errors);

                                    self.log_errors(&self.soft_page_fault_event);
                                },

                                /* HARD PAGE FAULT */
                                PERF_COUNT_SW_PAGE_FAULTS_MAJ => {
                                    self.hard_page_fault_event.process(
                                        perf_data.raw_data,
                                        perf_data.raw_data,
                                        &mut self.errors);

                                    self.log_errors(&self.hard_page_fault_event);
                                },

                                /* Unsupported */
                                _ => { },
                            }
                        },

                        /* Unsupported */
                        _ => { },
                    }
                }
            },

            abi::PERF_RECORD_LOST => {
                let offset = abi::Header::data_offset();

                self.lost_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.lost_event);
            },

            abi::PERF_RECORD_COMM => {
                let offset = abi::Header::data_offset();

                self.comm_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.comm_event);
            },

            abi::PERF_RECORD_EXIT => {
                let offset = abi::Header::data_offset();

                self.exit_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.exit_event);
            },

            abi::PERF_RECORD_FORK => {
                let offset = abi::Header::data_offset();

                self.fork_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.fork_event);
            },

            abi::PERF_RECORD_MMAP2 => {
                let offset = abi::Header::data_offset();

                self.mmap_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.mmap_event);
            },

            abi::PERF_RECORD_LOST_SAMPLES => {
                let offset = abi::Header::data_offset();

                self.lost_samples_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.lost_samples_event);
            },

            abi::PERF_RECORD_SWITCH_CPU_WIDE => {
                let offset = abi::Header::data_offset();

                self.cswitch_event.process(
                    perf_data.raw_data,
                    &perf_data.raw_data[offset..],
                    &mut self.errors);

                self.log_errors(&self.cswitch_event);
            },

            _ => {
                /* TODO: Remaining abi record types */
            },
        }

        /* Always clear errors */
        self.errors.clear();

        Ok(true)
    }

    fn parse_drain(
        &mut self) -> Result<(), TryFromSliceError> {
        self.source.begin_reading();

        while self.parse_perf_data(None)? {
            /* Nothing */
        }

        self.source.end_reading();

        Ok(())
    }

    pub fn parse_until(
        &mut self,
        should_stop: impl Fn() -> bool) -> Result<(), TryFromSliceError> {

        loop {
            let mut i: u32 = 0;

            self.source.begin_reading();

            while self.parse_perf_data(None)? {
                /* Ensure we cannot read forever without a should_stop call */
                if i >= 100 {
                    break;
                }

                i += 1;
            }

            self.source.end_reading();

            if should_stop() || !self.source.more() {
                break;
            }
        }

        Ok(())
    }

    pub fn capture_environment_comms(
        &mut self,
        pid_lookup: &Option<HashSet<i32>>) {
        let attributes = RingBufBuilder::common_attributes();
        let enabled = self.source_enabled;

        // Re-use buffers for capture
        let mut event_data: Vec<u8> = Vec::new();
        let mut full_data: Vec<u8> = Vec::new();

        let id_bytes = 0u64.to_ne_bytes();

        procfs::iter_processes(move |pid, path_buf| {
            // Skip non-target PIDs if we have them
            if let Some(pid_lookup) = &pid_lookup {
                if !pid_lookup.contains(&(pid as i32)) {
                    return;
                }
            }

            // Comm is encoded as a UTF-8 string.
            let comm = procfs::get_comm(path_buf)
                .unwrap_or(String::new());

            // Clear previous data
            event_data.clear();
            full_data.clear();

            // Allocate and fill the payload.
            // For new processes, pid == tid.
            let pid_bytes = pid.to_ne_bytes();
            event_data.extend_from_slice(&pid_bytes);
            event_data.extend_from_slice(&pid_bytes);
            event_data.extend_from_slice(comm.as_bytes());
            event_data.push(0);

            // Common attributes has SAMPLE_ID_ALL:
            // Need to push TID/TIME/IDENTIFIER in that order.
            event_data.extend_from_slice(&pid_bytes);
            event_data.extend_from_slice(&pid_bytes);

            // If the source is already enabled drain
            // the events to try to get as close as
            // possible to in-time-ordered events.
            if enabled {
                let _ = self.parse_drain();
            }

            let capture_time = rb::perf_timestamp(&attributes);
            let time_bytes = capture_time.to_ne_bytes();

            event_data.extend_from_slice(&time_bytes);
            event_data.extend_from_slice(&id_bytes);

            abi::Header::write(PERF_RECORD_COMM, 0, &event_data, &mut full_data);

            // Create PerfData and parse as if from buffer
            let perf_data = PerfData {
                ancillary: AncillaryData {
                    cpu: 0,
                    attributes: Rc::new(attributes),
                },
                raw_data: &full_data,
            };

            let _ = self.parse_perf_data(Some(perf_data));
        });
    }

    pub fn capture_environment_modules(
        &mut self,
        pid_lookup: &Option<HashSet<i32>>) {
        let attributes = RingBufBuilder::common_attributes();
        let enabled = self.source_enabled;
        let mut event_data: Vec<u8> = Vec::new();
        let mut full_data: Vec<u8> = Vec::new();

        let gen_bytes = 0u64.to_ne_bytes();
        /* PROT_EXEC */
        let prot_bytes = 4u32.to_ne_bytes();
        let flag_bytes = 0u32.to_ne_bytes();
        let id_bytes = 0u64.to_ne_bytes();

        procfs::iter_modules(move |pid, module| {
            if !module.is_exec() || module.path.is_none() {
                return;
            }

            // Skip non-target PIDs if we have them
            if let Some(pid_lookup) = &pid_lookup {
                if !pid_lookup.contains(&(pid as i32)) {
                    return;
                }
            }

            let path = module.path.unwrap();

            event_data.clear();
            full_data.clear();

            let pid_bytes = pid.to_ne_bytes();
            let addr_bytes = module.start_addr.to_ne_bytes();
            let len_bytes = module.len().to_ne_bytes();
            let offset_bytes = module.offset.to_ne_bytes();
            let maj_bytes = module.dev_maj.to_ne_bytes();
            let min_bytes = module.dev_min.to_ne_bytes();
            let ino_bytes = module.ino.to_ne_bytes();

            event_data.extend_from_slice(&pid_bytes);
            event_data.extend_from_slice(&pid_bytes);
            event_data.extend_from_slice(&addr_bytes);
            event_data.extend_from_slice(&len_bytes);
            event_data.extend_from_slice(&offset_bytes);
            event_data.extend_from_slice(&maj_bytes);
            event_data.extend_from_slice(&min_bytes);
            event_data.extend_from_slice(&ino_bytes);
            event_data.extend_from_slice(&gen_bytes);
            event_data.extend_from_slice(&prot_bytes);
            event_data.extend_from_slice(&flag_bytes);
            event_data.extend_from_slice(path.as_bytes());
            event_data.push(0);

            // If the source is already enabled drain
            // the events to try to get as close as
            // possible to in-time-ordered events.
            if enabled {
                let _ = self.parse_drain();
            }

            let capture_time = rb::perf_timestamp(&attributes);
            let time_bytes = capture_time.to_ne_bytes();

            event_data.extend_from_slice(&time_bytes);
            event_data.extend_from_slice(&id_bytes);

            abi::Header::write(PERF_RECORD_MMAP2, 0, &event_data, &mut full_data);

            // Create PerfData and parse as if from buffer
            let perf_data = PerfData {
                ancillary: AncillaryData {
                    cpu: 0,
                    attributes: Rc::new(attributes),
                },
                raw_data: &full_data,
            };

            let _ = self.parse_perf_data(Some(perf_data));
        });
    }

    pub fn capture_environment(&mut self) {
        let mut pid_lookup = None;

        if let Some(pids) = self.source.target_pids() {
            let mut lookup = HashSet::new();

            for pid in pids {
                lookup.insert(*pid);
            }

            pid_lookup = Some(lookup);
        }

        self.capture_environment_comms(&pid_lookup);
        self.capture_environment_modules(&pid_lookup);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct MockData {
        data: Vec<u8>,
        entries: Vec<(usize, usize)>,
        attr: Rc<perf_event_attr>,
        index: usize,
    }

    impl MockData {
        pub fn new(
            sample_type: u64,
            read_format: u64) -> Self {
            let mut attr = perf_event_attr::default();

            attr.sample_type = sample_type;
            attr.read_format = read_format;

            Self {
                data: Vec::new(),
                entries: Vec::new(),
                attr: Rc::new(attr),
                index: 0,
            }
        }

        pub fn push(
            &mut self,
            slice: &[u8]) {
            let entry: (usize, usize) = (self.data.len(), slice.len());

            self.entries.push(entry);

            for byte in slice {
                self.data.push(*byte);
            }
        }
    }

    impl PerfDataSource for MockData {
        fn enable(&mut self) -> IOResult<()> { Ok(()) }

        fn disable(&mut self) -> IOResult<()> { Ok(()) }

        fn target_pids(&self) -> Option<&[i32]> { None }

        fn create_bpf_files(
            &mut self,
            _event: Option<&Event>) -> IOResult<Vec<PerfDataFile>> {
            Ok(Vec::new())
        }

        fn add_event(
            &mut self,
            _event: &Event) -> IOResult<()> { Ok(()) }

        fn begin_reading(&mut self) { }

        fn read(
            &mut self,
            _timeout: Duration) -> Option<PerfData<'_>> {
            if !self.more() {
                return None;
            }

            let entry = self.entries[self.index];

            self.index += 1;

            let start = entry.0;
            let end = start + entry.1;

            Some(PerfData {
                ancillary: AncillaryData {
                    cpu: 0,
                    attributes: self.attr.clone(),
                },
                raw_data: &self.data[start .. end],
            })
        }

        fn end_reading(&mut self) { }

        fn more(&self) -> bool {
            self.index < self.entries.len()
        }
    }

    #[test]
    fn it_works() {
        let mock = MockData::new(abi::PERF_SAMPLE_RAW, 0);
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));
        format.add_field(
            EventField::new(
                "2".into(), "unsigned char".into(),
                LocationType::Static, 1, 1));
        format.add_field(
            EventField::new(
                "3".into(), "unsigned char".into(),
                LocationType::Static, 2, 1));

        let mut session = PerfSession::new(Box::new(mock));

        let count = Arc::new(AtomicUsize::new(0));

        let first = format.get_field_ref("1").unwrap();
        let second = format.get_field_ref("2").unwrap();
        let third = format.get_field_ref("3").unwrap();

        e.add_callback(move |data| {
            let format = data.format();
            let event_data = data.event_data();

            let a = format.get_data(first, event_data);
            let b = format.get_data(second, event_data);
            let c = format.get_data(third, event_data);

            assert!(a[0] == 1u8);
            assert!(b[0] == 2u8);
            assert!(c[0] == 3u8);

            count.fetch_add(1, Ordering::Relaxed);

            Ok(())
        });

        session.add_event(e).unwrap();
    }

    #[test]
    fn mock_data_sanity() {
        let mut mock = MockData::new(0, 0);
        let mut data: Vec<u8> = Vec::new();

        data.push(1);
        mock.push(data.as_slice());
        data.clear();

        data.push(2);
        mock.push(data.as_slice());
        data.clear();

        data.push(3);
        mock.push(data.as_slice());
        data.clear();
        drop(data);

        let timeout = Duration::from_millis(100);

        let first = mock.read(timeout).unwrap();
        assert_eq!(1, first.raw_data[0]);
        assert_eq!(1, first.raw_data.len());

        let second = mock.read(timeout).unwrap();
        assert_eq!(2, second.raw_data[0]);
        assert_eq!(1, second.raw_data.len());

        let third = mock.read(timeout).unwrap();
        assert_eq!(3, third.raw_data[0]);
        assert_eq!(1, third.raw_data.len());

        assert!(mock.read(timeout).is_none());
        assert!(!mock.more());
    }

    #[test]
    fn mock_data_perf_session() {
        let count = Arc::new(AtomicUsize::new(0));

        let sample_format =
            abi::PERF_SAMPLE_TIME |
            abi::PERF_SAMPLE_RAW;

        /* Create our mock data */
        let mut mock = MockData::new(sample_format, 0);
        let mut perf_data = Vec::new();
        let mut raw_data = Vec::new();
        let mut event_data = Vec::new();

        let id: u16 = 1;
        let magic: u64 = 1234;
        let time: u64 = 4321;

        /* Our actual event payload (common_type + magic fields) */
        event_data.extend_from_slice(&id.to_ne_bytes());
        event_data.extend_from_slice(&magic.to_ne_bytes());

        /* PERF_SAMPLE_TIME DataField within perf */
        Sample::write_time(time, &mut raw_data);

        /* PERF_SAMPLE_RAW DataField withn perf */
        Sample::write_raw(event_data.as_slice(), &mut raw_data);

        /* Perf header that encapsulates the above data as a PERF_RECORD_SAMPLE */
        Header::write(abi::PERF_RECORD_SAMPLE, 0, raw_data.as_slice(), &mut perf_data);
        mock.push(perf_data.as_slice());
        perf_data.clear();

        /* Create session with our mock data */
        let mut session = PerfSession::new(Box::new(mock));

        /* Create a Mock event that describes our mock data */
        let mut e = Event::new(id as usize, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "common_type".into(), "unsigned short".into(),
                LocationType::Static, 0, 2));

        format.add_field(
            EventField::new(
                "magic".into(), "u64".into(),
                LocationType::Static, 2, 8));

        /* Params we want to capture in the closure/callback */
        let callback_count = Arc::clone(&count);
        let time_data = session.time_data_ref();
        let magic_ref = format.get_field_ref("magic").unwrap();

        /* Parse upon being read with this code */
        e.add_callback(move |data| {
            let full_data = data.full_data();
            let format = data.format();
            let event_data = data.event_data();

            let read_time = time_data.try_get_u64(full_data).unwrap();
            let read_magic = format.try_get_u64(magic_ref, event_data).unwrap();

            assert_eq!(4321, read_time);
            assert_eq!(1234, read_magic);

            callback_count.fetch_add(1, Ordering::Relaxed);

            Ok(())
        });

        /* Add the event to the session now that we setup the rules */
        session.add_event(e).unwrap();

        /* Parse until more() returns false in the source (MockData) */
        session.parse_all().unwrap();

        /* Ensure we only saw 1 event and our assert checks ran */
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
