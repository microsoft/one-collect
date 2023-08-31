use crate::perf_event::PerfSession;
use crate::perf_event::rb::{RingBufOptions, RingBufBuilder, source::RingBufSessionBuilder};

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

    pub fn build(self) -> Session<'a> {
        Session::new(self)
    }
}

pub struct Session<'a> {
    egress: SessionEgress<'a>,
    perf_session: Option<PerfSession>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(builder: SessionBuilder<'a>) -> Self {
        let perf_session: Option<PerfSession>;
        if builder.with_profiling {
            perf_session = Some(Self::build_perf_session(&builder));
        }
        else {
            perf_session = None;
        }

        Self {
            egress: builder.egress,
            perf_session
        }
    }

    pub fn egress_info(&self) -> &SessionEgress<'a> {
        &self.egress
    }

    pub fn enable(self) -> Self {
        let perf_session : Option<PerfSession>;
        if let Some(mut session) = self.perf_session {
            session.profile_event().set_callback(move |full_data,format,event_data| {
                println!("Event: {:#?}", event_data);
            });

            session.enable().unwrap();
            session.parse_for_duration(
                std::time::Duration::from_secs(1)).unwrap();
            session.disable().unwrap();

            perf_session = Some(session);
        }
        else {
            perf_session = None;
        }

        Self {
            perf_session,
            ..self
        }
    }

    fn build_perf_session(builder: &SessionBuilder<'a>) -> PerfSession {
        let mut options = RingBufOptions::new();

        if builder.with_call_stacks {
            options = options.with_callchain_data();
        }

        let profiling_builder = RingBufBuilder::for_profiling(
            &options,
            builder.profiling_frequency);

        let session = RingBufSessionBuilder::new()
            .with_page_count(8)
            .with_profiling_events(profiling_builder)
            .build()
            .unwrap();

        // TODO: Set profiling callback.

        session
    }

}