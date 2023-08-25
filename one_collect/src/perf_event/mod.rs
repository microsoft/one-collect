use std::time::Duration;
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::rc::Rc;

use crate::event::*;

pub mod abi;
pub mod rb;
mod events;

use abi::*;

pub type IOResult<T> = std::io::Result<T>;
pub type IOError = std::io::Error;

pub fn io_error(message: &str) -> IOError {
    IOError::new(
        std::io::ErrorKind::Other,
        message)
}

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

pub trait PerfDataSource {
    fn enable(&mut self) -> IOResult<()>;

    fn disable(&mut self) -> IOResult<()>;

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
    events: HashMap<usize, Event>,

    /* Raw data fields */
    ip_field: DataFieldRef,
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

    /* Ancillary data */
    ancillary: Writable<AncillaryData>,
}

impl PerfSession {
    pub fn new(
        source: Box<dyn PerfDataSource>) -> Self {
        Self {
            source,
            events: HashMap::new(),

            /* Events */
            ip_field: DataFieldRef::new(),
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

            /* Options */
            read_timeout: Duration::from_millis(15),

            /* Events */
            cpu_profile_event: Event::new(0, "__cpu_profile".into()),
            cswitch_profile_event: Event::new(0, "__cswitch_profile".into()),
            lost_event: events::lost(),
            comm_event: events::comm(),
            exit_event: events::exit(),
            fork_event: events::fork(),
            mmap_event: events::mmap(),
            lost_samples_event: events::lost_samples(),

            /* Ancillary data */
            ancillary: Writable::new(AncillaryData::default()),
        }
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

    pub fn ip_data_ref(&self) -> DataFieldRef {
        self.ip_field.clone()
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

    pub fn set_read_timeout(
        &mut self,
        timeout: Duration) {
        self.read_timeout = timeout;
    }

    pub fn add_event(
        &mut self,
        event: Event) -> IOResult<()> {
        self.source.add_event(&event)?;

        self.events.insert(event.id(), event);

        Ok(())
    }

    pub fn enable(&mut self) -> IOResult<()> {
        self.source.enable()
    }

    pub fn disable(&mut self) -> IOResult<()> {
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

    pub fn parse_until(
        &mut self,
        should_stop: impl Fn() -> bool) -> Result<(), TryFromSliceError> {
        loop {
            let mut i: u32 = 0;

            self.source.begin_reading();

            while let Some(perf_data) = self.source.read(
                self.read_timeout) {
                let header = abi::Header::from_slice(perf_data.raw_data)?;

                self.ancillary.write(|value| {
                    *value = perf_data.ancillary.clone();
                });

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
                            offset += self.tid_field.update(offset, 8);
                        } else {
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
                            offset += self.id_field.update(offset, 8);
                        } else {
                            self.id_field.reset();
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

                        /* TODO: Remaining abi format types */

                        /* For now print warning if we see this */
                        if offset > perf_data.raw_data.len() {
                            println!("WARN: Truncated sample");
                        }

                        /* Process if we have an ID to use */
                        if let Some(id) = &id {
                            if let Some(event) = self.events.get_mut(id) {
                                let full_data = perf_data.raw_data;
                                let event_data = self.raw_field.get_data(full_data);

                                event.process(full_data, event_data);
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
                                                perf_data.raw_data);
                                        },

                                        /* CSWITCH */
                                        PERF_COUNT_SW_CONTEXT_SWITCHES => {
                                            self.cswitch_profile_event.process(
                                                perf_data.raw_data,
                                                perf_data.raw_data);
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
                            &perf_data.raw_data[offset..]);
                    },

                    abi::PERF_RECORD_COMM => {
                        let offset = abi::Header::data_offset();

                        self.comm_event.process(
                            perf_data.raw_data,
                            &perf_data.raw_data[offset..]);
                    },

                    abi::PERF_RECORD_EXIT => {
                        let offset = abi::Header::data_offset();

                        self.exit_event.process(
                            perf_data.raw_data,
                            &perf_data.raw_data[offset..]);
                    },

                    abi::PERF_RECORD_FORK => {
                        let offset = abi::Header::data_offset();

                        self.fork_event.process(
                            perf_data.raw_data,
                            &perf_data.raw_data[offset..]);
                    },

                    abi::PERF_RECORD_MMAP2 => {
                        let offset = abi::Header::data_offset();

                        self.mmap_event.process(
                            perf_data.raw_data,
                            &perf_data.raw_data[offset..]);
                    },

                    abi::PERF_RECORD_LOST_SAMPLES => {
                        let offset = abi::Header::data_offset();

                        self.lost_samples_event.process(
                            perf_data.raw_data,
                            &perf_data.raw_data[offset..]);
                    },

                    _ => {
                        /* TODO: Remaining abi record types */
                    },
                }

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

        e.set_callback(move |_full_data, format, event_data| {
            let a = format.get_data(first, event_data);
            let b = format.get_data(second, event_data);
            let c = format.get_data(third, event_data);

            assert!(a[0] == 1u8);
            assert!(b[0] == 2u8);
            assert!(c[0] == 3u8);

            count.fetch_add(1, Ordering::Relaxed);
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
        e.set_callback(move |full_data, format, event_data| {
            let read_time = time_data.try_get_u64(full_data).unwrap();
            let read_magic = format.try_get_u64(magic_ref, event_data).unwrap();

            assert_eq!(4321, read_time);
            assert_eq!(1234, read_magic);

            callback_count.fetch_add(1, Ordering::Relaxed);
        });

        /* Add the event to the session now that we setup the rules */
        session.add_event(e).unwrap();

        /* Parse until more() returns false in the source (MockData) */
        session.parse_all().unwrap();

        /* Ensure we only saw 1 event and our assert checks ran */
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
