// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{info, debug};

use super::*;

pub type SessionBuilder = os::SessionBuilder;

pub struct UniversalBuildSessionContext {
    /* Placeholder */
}

pub struct UniversalParsedContext<'a> {
    pub machine: &'a mut ExportMachine,
}

impl<'a> UniversalParsedContext<'a> {
    pub fn machine(&'a self) -> &'a ExportMachine { &self.machine }

    pub fn machine_mut(&'a mut self) -> &'a mut ExportMachine { self.machine }
}

type BoxedSettingsCallback = Box<dyn FnMut(ExportSettings) -> anyhow::Result<ExportSettings>>;
type BoxedBuildCallback = Box<dyn FnMut(SessionBuilder, &mut UniversalBuildSessionContext) -> anyhow::Result<SessionBuilder>>;
type BoxedExportCallback = Box<dyn FnMut(&Writable<ExportMachine>) -> anyhow::Result<()>>;
type BoxedParsedCallback = Box<dyn FnMut(&mut UniversalParsedContext) -> anyhow::Result<()>>;
type BoxedDropCallback = Box<dyn FnMut()>;

enum BufferSize {
    PerBuffer(usize),
    Total(usize),
}

pub struct UniversalExporter {
    settings: Option<ExportSettings>,
    setting_hooks: Vec<BoxedSettingsCallback>,
    build_hooks: Vec<BoxedBuildCallback>,
    export_hooks: Vec<BoxedExportCallback>,
    parsed_hooks: Vec<BoxedParsedCallback>,
    drop_hooks: Vec<BoxedDropCallback>,
    buffer_size: BufferSize,
}

const MIN_BUFFER_BYTES: usize = 64 * 1024;

pub trait UniversalExporterOSHooks {
    fn os_parse_until(
        self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>>;
}

impl UniversalExporter {
    pub fn new(settings: ExportSettings) -> Self {
        let mut per_buffer_size_bytes = MIN_BUFFER_BYTES;

        if settings.has_unwinder() {
            /* Unwinders need more data per-CPU than normal */
            per_buffer_size_bytes = 1024*1024;
        }

        Self {
            settings: Some(settings),
            setting_hooks: Vec::new(),
            build_hooks: Vec::new(),
            export_hooks: Vec::new(),
            parsed_hooks: Vec::new(),
            drop_hooks: Vec::new(),
            buffer_size: BufferSize::PerBuffer(per_buffer_size_bytes),
        }
    }

    pub fn add_event(
        &mut self,
        event: Event,
        built: impl FnMut(&mut ExportBuiltContext) -> anyhow::Result<()> + 'static,
        trace: impl FnMut(&mut ExportTraceContext) -> anyhow::Result<()> + 'static) {
        if let Some(settings) = self.settings.take() {
            self.settings = Some(settings.with_event(
                event,
                built,
                trace));
        }
    }

    pub fn swap_settings(
        &mut self,
        mut func: impl FnMut(ExportSettings) -> ExportSettings) {
        if let Some(settings) = self.settings.take() {
            self.settings = Some(func(settings));
        }
    }

    /// Sets an upper bound for each underlying platform buffer.
    ///
    /// On Linux, this bounds each per-CPU perf ring buffer.
    /// On Windows, ETW uses a session-wide buffer pool, so this is the size of
    /// each ETW buffer rather than a per-CPU allocation. A platform minimum
    /// may require a larger buffer than the requested bound.
    ///
    /// Use [`Self::with_buffer_size_bytes`] when the caller has a total session
    /// size and wants the Universal layer to apply the platform-specific
    /// normalization policy.
    pub fn with_per_cpu_buffer_bytes(
        mut self,
        bytes: usize) -> Self {
        self.buffer_size = BufferSize::PerBuffer(bytes);
        self
    }

    /// Sets an upper bound for the total event buffer data capacity across all
    /// underlying platform buffers.
    ///
    /// The Universal layer divides the capacity by the number of buffers the
    /// active platform creates, then applies that platform's sizing rules. It
    /// replaces the default capacity rather than raising it, so a small value
    /// reduces the capacity that would otherwise be used. The resulting
    /// capacity does not exceed `bytes` unless the minimum size for each
    /// underlying buffer requires more. Because the total is divided and then
    /// reduced to a size the platform accepts, the delivered capacity can be as
    /// low as half the request. Platform metadata is not counted against this
    /// bound. On Linux, metadata adds one system page per buffer.
    ///
    /// Use [`Self::with_per_cpu_buffer_bytes`] to bound each underlying buffer
    /// directly instead.
    pub fn with_buffer_size_bytes(
        mut self,
        bytes: usize) -> Self {
        self.buffer_size = BufferSize::Total(bytes);
        self
    }

    pub fn with_settings_hook(
        mut self,
        hook: impl FnMut(ExportSettings) -> anyhow::Result<ExportSettings> + 'static) -> Self {
        self.setting_hooks.push(Box::new(hook));
        self
    }

    pub fn with_build_hook(
        mut self,
        hook: impl FnMut(SessionBuilder, &mut UniversalBuildSessionContext) -> anyhow::Result<SessionBuilder> + 'static) -> Self {
        self.build_hooks.push(Box::new(hook));
        self
    }

    pub fn with_parsed_hook(
        mut self,
        hook: impl FnMut(&mut UniversalParsedContext) -> anyhow::Result<()> + 'static) -> Self {
        self.parsed_hooks.push(Box::new(hook));
        self
    }

    pub fn with_export_hook(
        mut self,
        hook: impl FnMut(&Writable<ExportMachine>) -> anyhow::Result<()> + 'static) -> Self {
        self.export_hooks.push(Box::new(hook));
        self
    }

    pub fn with_export_drop_hook(
        mut self,
        hook: impl FnMut() + 'static) -> Self {
        self.drop_hooks.push(Box::new(hook));
        self
    }

    pub fn parse_for_duration(
        self,
        name: &str,
        duration: std::time::Duration) -> anyhow::Result<Writable<ExportMachine>> {
        info!("Starting export parse: name={}, duration={:?}", name, duration);
        let now = std::time::Instant::now();

        self.parse_until(
            name,
            move || { now.elapsed() >= duration })
    }

    pub fn cleanup(&mut self) {
        /* Ensure drop hooks run if they haven't already */
        for mut hook in self.drop_hooks.drain(..) {
            hook();
        }
    }

    pub fn parse_until(
        mut self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        /* Run Setting Hooks */
        if let Some(mut settings) = self.settings.take() {
            for hook in &mut self.setting_hooks {
                settings = hook(settings)?;
            }

            self.settings = Some(settings);
        }

        self.os_parse_until(
            name,
            until)
    }

    pub(crate) fn per_buffer_size_bytes(
        &self,
        underlying_buffer_count: usize) -> usize {
        match self.buffer_size {
            BufferSize::PerBuffer(bytes) => bytes,
            BufferSize::Total(bytes) => {
                (bytes / underlying_buffer_count.max(1)).max(MIN_BUFFER_BYTES)
            },
        }
    }

    pub(crate) fn run_build_hooks(
        &mut self,
        mut builder: SessionBuilder) -> anyhow::Result<SessionBuilder> {
        debug!("Running build hooks: count={}", self.build_hooks.len());
        let mut context = UniversalBuildSessionContext {
        };

        for hook in &mut self.build_hooks {
            builder = hook(builder, &mut context)?;
        }

        Ok(builder)
    }

    pub(crate) fn run_export_hooks(
        &mut self,
        machine: &Writable<ExportMachine>) -> anyhow::Result<()> {
        debug!("Running export hooks: count={}", self.export_hooks.len());
        for hook in &mut self.export_hooks {
            hook(machine)?;
        }

        Ok(())
    }

    pub(crate) fn run_parsed_hooks(
        &mut self,
        machine: &Writable<ExportMachine>) -> anyhow::Result<()> {
        /* Ensure drop hooks get run by the ExportMachine */
        for hook in self.drop_hooks.drain(..) {
            machine.borrow_mut().add_drop_closure(hook);
        }

        let mut context = UniversalParsedContext {
            machine: &mut machine.borrow_mut(),
        };

        for hook in &mut self.parsed_hooks {
            hook(&mut context)?;
        }

        Ok(())
    }

    pub(crate) fn settings(
        &mut self) -> anyhow::Result<ExportSettings> {
        match self.settings.take() {
            Some(settings) => { Ok(settings) },
            None => { anyhow::bail!("No settings.") },
        }
    }

    pub(crate) const fn settings_mut(&mut self) -> Option<&mut ExportSettings> {
        self.settings.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_buffer_size_is_divided_across_buffers() {
        let exporter = UniversalExporter::new(ExportSettings::default())
            .with_buffer_size_bytes(1024 * 1024);

        assert_eq!(1024 * 1024, exporter.per_buffer_size_bytes(1));
        assert_eq!(256 * 1024, exporter.per_buffer_size_bytes(4));
        assert_eq!(349525, exporter.per_buffer_size_bytes(3));
    }

    #[test]
    fn total_buffer_size_enforces_minimum_buffer_size() {
        let exporter = UniversalExporter::new(ExportSettings::default())
            .with_buffer_size_bytes(1);

        assert_eq!(MIN_BUFFER_BYTES, exporter.per_buffer_size_bytes(1));
        assert_eq!(
            MIN_BUFFER_BYTES,
            exporter.per_buffer_size_bytes(usize::MAX));
    }

    #[test]
    fn per_buffer_size_does_not_depend_on_buffer_count() {
        let exporter = UniversalExporter::new(ExportSettings::default())
            .with_per_cpu_buffer_bytes(1234);

        assert_eq!(1234, exporter.per_buffer_size_bytes(1));
        assert_eq!(1234, exporter.per_buffer_size_bytes(usize::MAX));
    }

    #[test]
    fn total_buffer_size_tolerates_an_unknown_buffer_count() {
        let exporter = UniversalExporter::new(ExportSettings::default())
            .with_buffer_size_bytes(1024 * 1024);

        assert_eq!(1024 * 1024, exporter.per_buffer_size_bytes(0));
    }
}
