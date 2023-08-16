use std::time::Duration;
use std::array::TryFromSliceError;
use std::collections::HashMap;

use crate::event::*;

pub mod abi;

static EMPTY: &[u8] = &[];

pub struct PerfData<'a> {
    pub cpu: u32,
    pub sample_format: u64,
    pub read_format: u64,
    pub raw_data: &'a [u8],
}

impl Default for PerfData<'_> {
    fn default() -> Self {
        Self {
            cpu: Default::default(),
            sample_format: 0,
            read_format: 0,
            raw_data: EMPTY,
        }
    }
}

impl PerfData<'_> {
    fn has_format(
        &self,
        format: u64) -> bool {
        (self.sample_format & format) == format
    }

    fn has_read_format(
        &self,
        format: u64) -> bool {
        (self.read_format & format) == format
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
    fn read(
        &mut self,
        timeout: Duration) -> Option<PerfData<'_>>;

    fn more(&self) -> bool;
}

pub struct PerfSession {
    source: Box<dyn PerfDataSource>,
    events: HashMap<usize, Event>,
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
    read_timeout: Duration,
}

impl PerfSession {
    pub fn new(
        source: Box<dyn PerfDataSource>) -> Self {
        Self {
            source,
            events: HashMap::new(),
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
            read_timeout: Duration::from_millis(100),
        }
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
        event: Event) {
        self.events.insert(event.id(), event);
    }

    pub fn parse_all(&mut self) -> Result<(), TryFromSliceError> {
        self.parse_until(|| true )
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

            while let Some(perf_data) = self.source.read(self.read_timeout) {
                let header = abi::Header::from_slice(perf_data.raw_data)?;

                match header.entry_type {
                    abi::PERF_RECORD_SAMPLE => {
                        let mut offset: usize = abi::Header::data_offset();
                        let mut id: Option<usize> = None;

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
                        }
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

    use crate::perf_event::abi::*;

    struct MockData {
        data: Vec<u8>,
        entries: Vec<(usize, usize)>,
        sample_format: u64,
        read_format: u64,
        index: usize,
    }

    impl MockData {
        pub fn new(
            sample_format: u64,
            read_format: u64) -> Self {
            Self {
                data: Vec::new(),
                entries: Vec::new(),
                sample_format,
                read_format,
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
        fn read<'a>(
            &'a mut self,
            _timeout: Duration) -> Option<PerfData<'a>> {
            if !self.more() {
                return None;
            }

            let entry = self.entries[self.index];

            self.index += 1;

            let start = entry.0;
            let end = start + entry.1;

            Some(PerfData {
                cpu: 0,
                sample_format: self.sample_format,
                read_format: self.read_format,
                raw_data: &self.data[start .. end],
            })
        }

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

        session.add_event(e);
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
        session.add_event(e);

        /* Parse until more() returns false in the source (MockData) */
        session.parse_all().unwrap();

        /* Ensure we only saw 1 event and our assert checks ran */
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
