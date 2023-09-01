use std::io;
use crate::perf_event::PerfSession;
use crate::perf_event::rb::{RingBufOptions, RingBufBuilder, source::RingBufSessionBuilder};
pub type IOResult<T> = std::io::Result<T>;

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
}

impl<'a> SessionBuilder<'a> {
    pub fn new(egress: SessionEgress<'a>) -> Self {
        Self {
            egress,
            with_profiling: false,
            with_call_stacks: false,
            profiling_frequency: 1000,
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
            perf_session
        })
    }

    pub fn egress_info(&self) -> &SessionEgress<'a> {
        &self.egress
    }

    pub fn perf_session_mut(&mut self) -> &mut Option<PerfSession> {
        &mut self.perf_session
    }

    fn build_perf_session(builder: &SessionBuilder<'a>) -> IOResult<PerfSession> {
        let mut options = RingBufOptions::new();

        if builder.with_call_stacks {
            options = options.with_callchain_data();
        }

        let profiling_builder = RingBufBuilder::for_profiling(
            &options,
            builder.profiling_frequency);

        RingBufSessionBuilder::new()
            .with_page_count(8)
            .with_profiling_events(profiling_builder)
            .build()
    }

}