use std::array::TryFromSliceError;
use std::io;
use std::time::Duration;

use super::*;
use crate::helpers::callstack::{CallstackHelper, CallstackReader, CallstackHelp};
use crate::perf_event::PerfSession;
use crate::perf_event::rb::{RingBufBuilder, source::RingBufSessionBuilder};
use crate::state::ProcessTrackingOptions;

pub enum SessionEgress<'a> {
    File(FileSessionEgress<'a>),
    Live,
}

pub struct FileSessionEgress<'a> {
    path: &'a str,
}

impl<'a> FileSessionEgress<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            path
        }
    }

    pub fn path(&self) -> &str {
        self.path
    }
}

pub struct SessionBuilder<'a> {
    egress: SessionEgress<'a>,
    with_profiling: bool,
    with_call_stacks: bool,
    page_count: usize,
    profiling_frequency : u64,
    process_tracking_options: ProcessTrackingOptions,
}

impl<'a> SessionBuilder<'a> {
    pub fn new(egress: SessionEgress<'a>) -> Self {
        Self {
            egress,
            with_profiling: false,
            with_call_stacks: false,
            page_count: 8,
            profiling_frequency: 1000,
            process_tracking_options: ProcessTrackingOptions::default(),
        }
    }

    pub fn with_profiling(self, frequency: u64) -> Self {
        Self {
            with_profiling: true,
            profiling_frequency: frequency,
            ..self
        }
    }

    pub fn with_call_stacks(self) -> Self {
        Self {
            with_call_stacks: true,
            page_count: 256,
            ..self
        }
    }

    pub fn track_process_state(self, options: ProcessTrackingOptions) -> Self {
        Self {
            process_tracking_options: options,
            ..self
        }
    }

    pub fn build(self) -> Result<Session<'a>, io::Error> {
        Session::build(self)
    }
}

pub struct Session<'a> {
    egress: SessionEgress<'a>,
    perf_session: Option<PerfSession>,
    stack_reader: Option<CallstackReader>,
}

impl<'a> Session<'a> {
    pub(crate) fn build(builder: SessionBuilder<'a>) -> Result<Self, io::Error> {

        let mut stack_reader = None;

        let mut ring_buf_builder = RingBufSessionBuilder::new()
            .with_page_count(builder.page_count);

        if builder.with_profiling {
            let profiling_builder = RingBufBuilder::for_profiling(
                builder.profiling_frequency);

            ring_buf_builder = ring_buf_builder.with_profiling_events(profiling_builder);
        }

        if builder.with_call_stacks {
            let stack_helper = CallstackHelper::new()
                .with_dwarf_unwinding();

            ring_buf_builder = ring_buf_builder.with_callstack_help(&stack_helper);
            stack_reader = Some(stack_helper.to_reader());
        }

        // Enable comm events by default.
        let kernel_builder = RingBufBuilder::for_kernel()
            .with_comm_records();
        ring_buf_builder = ring_buf_builder.with_kernel_events(kernel_builder);

        // Enable process tracking if requested.
        if builder.process_tracking_options.any() {
            ring_buf_builder = ring_buf_builder.track_process_state(
                builder.process_tracking_options);
        }

        let mut session = Self {
            egress: builder.egress,
            perf_session: None,
            stack_reader,
        };

        match ring_buf_builder.build() {
            Ok(perf_session) => session.perf_session = Some(perf_session),
            Err(e) => return Err(e),
        }

        Ok(session)
    }

    pub fn egress_info(&self) -> &SessionEgress<'a> {
        &self.egress
    }

    pub fn perf_session_mut(&mut self) -> &mut Option<PerfSession> {
        &mut self.perf_session
    }

    pub fn enable(&mut self) -> IOResult<()> {
        self.perf_session.as_mut().unwrap().enable()
    }

    pub fn disable(&mut self) -> IOResult<()> {
        self.perf_session.as_mut().unwrap().disable()
    }

    pub fn parse_all(
        &mut self) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_all()
    }

    pub fn parse_for_duration(
        &mut self,
        duration: Duration) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_for_duration(duration)
    }

    pub fn parse_until(
        &mut self,
        should_stop: impl Fn() -> bool) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_until(should_stop)
    }

    fn capture_environment(&mut self) {
        let session = self.perf_session.as_mut().unwrap();

        if session.process_tracking_options().process_names() {
            session.capture_environment();
        }
    }

    pub fn stack_reader(&self) -> Option<CallstackReader> {
        match &self.stack_reader {
            Some(reader) => Some(reader.clone()),
            None => None
        }
    }
}
