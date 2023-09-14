use std::array::TryFromSliceError;
use std::io;
use std::time::Duration;

use super::*;
use crate::perf_event::PerfSession;
use crate::perf_event::rb::{RingBufOptions, RingBufBuilder, source::RingBufSessionBuilder};
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
    profiling_frequency : u64,
    process_tracking_options: ProcessTrackingOptions,
}

impl<'a> SessionBuilder<'a> {
    pub fn new(egress: SessionEgress<'a>) -> Self {
        Self {
            egress,
            with_profiling: false,
            with_call_stacks: false,
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
}

impl<'a> Session<'a> {
    pub(crate) fn build(builder: SessionBuilder<'a>) -> Result<Self, io::Error> {
        let perf_session: Option<PerfSession>;
        if builder.with_profiling {
            match Self::build_perf_session(&builder) {
                Ok(session) => perf_session = Some(session),
                Err(e) => return Err(e),
            }
        }
        else {
            perf_session = None;
        }

        Ok(Self {
            egress: builder.egress,
            perf_session,
        })
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

    fn build_perf_session(builder: &SessionBuilder<'a>) -> IOResult<PerfSession> {
        let mut ring_buf_builder = RingBufSessionBuilder::new()
            .with_page_count(8);

        // Enable comm events by default.
        let kernel_builder = RingBufBuilder::for_kernel()
            .with_comm_records();
        ring_buf_builder = ring_buf_builder.with_kernel_events(kernel_builder);

        // Enable call stacks if requested.
        let mut options = RingBufOptions::new();

        if builder.with_call_stacks {
            options = options.with_callchain_data();
        }

        // Enable profiling if requested.
        if builder.with_profiling {
            let profiling_builder = RingBufBuilder::for_profiling(
                &options,
                builder.profiling_frequency);

            ring_buf_builder = ring_buf_builder.with_profiling_events(profiling_builder);
        }

        // Enable process tracking if requested.
        if builder.process_tracking_options.any() {
            ring_buf_builder = ring_buf_builder.track_process_state(
                builder.process_tracking_options)
        }

        ring_buf_builder.build()
    }

}