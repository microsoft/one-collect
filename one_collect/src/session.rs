use std::array::TryFromSliceError;
use std::io;
use std::time::Duration;

use super::*;
use crate::helpers::callstack::{CallstackHelper, CallstackReader, CallstackHelp};
use crate::perf_event::PerfSession;
use crate::perf_event::rb::{RingBufBuilder, source::RingBufSessionBuilder};
use crate::state::ProcessTrackingOptions;

/// Specifies the mode of session data output.
///
/// The enum has two variants:
/// - File: This variant is used when session data is to be written to a file. It holds a `FileSessionEgress` instance which contains the path of the output file.
/// - Live: This variant is used when session data is to be outputted live.
///
pub enum SessionEgress<'a> {
    File(FileSessionEgress<'a>),
    Live,
}

/// Configures the file output for a session.
///
/// This struct holds the path of the output file.
///
/// # Methods
///
/// * `new(path: &'a str) -> Self`: Constructs a new `FileSessionEgress` with the given file path.
/// * `path() -> &str`: Returns the path of the output file.
///
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

/// Builder for configuring and creating a `Session`.
///
/// This builder allows you to configure a session with options such as profiling, call stacks, page count, profiling frequency, and process tracking options.
///
/// # Methods
///
/// * `new(egress: SessionEgress<'a>) -> Self`: Constructs a new `SessionBuilder` with the given egress mode.
/// * `with_profiling(self, frequency: u64) -> Self`: Enables profiling with the given frequency.
/// * `with_call_stacks(self) -> Self`: Enables call stacks.
/// * `track_process_state(self, options: ProcessTrackingOptions) -> Self`: Tracks the process state with the given options.
/// * `build(self) -> Result<Session<'a>, io::Error>`: Builds and returns a `Session`.
///
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

/// A `Session` represents a profiling session.
///
/// This struct contains the configuration and state of a profiling session, including the mode of session data output, a
/// `PerfSession` for interfacing with perf_events, and a `CallstackReader` for reading call stacks.
///
/// # Methods
///
/// * `build(builder: SessionBuilder<'a>) -> Result<Self, io::Error>`: Builds a `Session` from a `SessionBuilder`.
/// * `egress_info(&self) -> &SessionEgress<'a>`: Returns information about the egress mode.
/// * `perf_session_mut(&mut self) -> &mut Option<PerfSession>`: Returns a mutable reference to the `PerfSession`.
///
/// # Example
///
/// ```
/// use one_collect::session::{SessionBuilder, FileSessionEgress, SessionEgress};
/// use one_collect::state::ProcessTrackingOptions;
///
/// let session_builder = SessionBuilder::new(SessionEgress::File(FileSessionEgress::new("output.txt")))
///     .with_profiling(1000)
///     .with_call_stacks()
///     .track_process_state(ProcessTrackingOptions::default());
/// let session = session_builder.build();
/// ```
pub struct Session<'a> {
    egress: SessionEgress<'a>,
    perf_session: Option<PerfSession>,
    stack_reader: Option<CallstackReader>,
}

impl<'a> Session<'a> {
    /// Builds a new `Session` from a given `SessionBuilder`.
    ///
    /// This method also configures the `PerfSession` and `CallstackReader` based on the settings in the `SessionBuilder`.
    ///
    /// # Arguments
    ///
    /// * `builder` - A `SessionBuilder` instance containing the configuration for the new `Session`.
    ///
    /// # Returns
    ///
    /// * `Result<Session, io::Error>` - Returns a new `Session` if successful, or an `io::Error` if an error occurred during the build.
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

    /// Returns a reference to the `SessionEgress` of the `Session`.
    ///
    /// # Returns
    ///
    /// * `&SessionEgress` - A reference to the `SessionEgress` of the `Session`.
    pub fn egress_info(&self) -> &SessionEgress<'a> {
        &self.egress
    }

    /// Returns a mutable reference to the `PerfSession` of the `Session`.
    ///
    /// # Returns
    ///
    /// * `&mut Option<PerfSession>` - A mutable reference to the `PerfSession` of the `Session`.
    pub fn perf_session_mut(&mut self) -> &mut Option<PerfSession> {
        &mut self.perf_session
    }

    /// Enables the session. It primarily enables the perf session if it exists.
    ///
    /// # Returns
    ///
    /// This function returns an IOResult, which can either be Ok if the session was successfully enabled, or an error if one occurred.
    ///
    pub fn enable(&mut self) -> IOResult<()> {
        self.perf_session.as_mut().unwrap().enable()
    }

    /// Disables the session. It primarily disables the perf session if it exists.
    ///
    /// # Returns
    ///
    /// This function returns an IOResult, which can either be Ok if the session was successfully disabled, or an error if one occurred.
    ///
    pub fn disable(&mut self) -> IOResult<()> {
        self.perf_session.as_mut().unwrap().disable()
    }

    /// Parses all the events in the session.
    ///
    /// This method captures the environment and calls the `parse_all` method on the `perf_session`.
    ///
    /// # Returns
    ///
    /// This function returns a Result. If the events are successfully parsed, Ok is returned. If an error occurs, the error is returned in the Result.
    ///
    pub fn parse_all(
        &mut self) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_all()
    }

    /// Parses events in the session for a specified duration.
    ///
    /// This method captures the environment and calls the `parse_for_duration` method on the `perf_session`.
    ///
    /// # Parameters
    ///
    /// * `duration`: The duration for which events should be parsed.
    ///
    /// # Returns
    ///
    /// This function returns a Result. If the events are successfully parsed for the given duration, Ok is returned. If an error occurs, the error is returned in the Result.
    ///
    pub fn parse_for_duration(
        &mut self,
        duration: Duration) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_for_duration(duration)
    }

    /// Parses events in the session until a certain condition is met.
    ///
    /// This method captures the environment and calls the `parse_until` method on the `perf_session`.
    ///
    /// # Parameters
    ///
    /// * `should_stop`: A function that returns a boolean value. Parsing continues until this function returns true.
    ///
    /// # Returns
    ///
    /// This function returns a Result. If the events are successfully parsed until the condition is met, Ok is returned. If an error occurs, the error is returned in the Result.
    ///
    pub fn parse_until(
        &mut self,
        should_stop: impl Fn() -> bool) -> Result<(), TryFromSliceError> {
            self.capture_environment();
            self.perf_session.as_mut().unwrap().parse_until(should_stop)
    }

    /// Captures the current environment of the session.
    ///
    /// This method checks if the process tracking options require process names. If so, it calls the `capture_environment` method on the `perf_session`.
    ///
    fn capture_environment(&mut self) {
        let session = self.perf_session.as_mut().unwrap();

        if session.process_tracking_options().process_names() {
            session.capture_environment();
        }
    }

    /// Provides the call stack reader for the session.
    ///
    /// This method checks if the `stack_reader` is available and returns a clone of it if available. If the `stack_reader` is not available, it returns `None`.
    ///
    /// # Returns
    ///
    /// This function returns an `Option` that contains a `CallstackReader` if it is available, or `None` if it is not.
    pub fn stack_reader(&self) -> Option<CallstackReader> {
        match &self.stack_reader {
            Some(reader) => Some(reader.clone()),
            None => None
        }
    }
}
