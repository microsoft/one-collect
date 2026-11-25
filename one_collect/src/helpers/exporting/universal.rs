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

pub struct UniversalExporter {
    settings: Option<ExportSettings>,
    setting_hooks: Vec<BoxedSettingsCallback>,
    build_hooks: Vec<BoxedBuildCallback>,
    export_hooks: Vec<BoxedExportCallback>,
    parsed_hooks: Vec<BoxedParsedCallback>,
    drop_hooks: Vec<BoxedDropCallback>,
    cpu_buf_bytes: usize,
}

pub trait UniversalExporterOSHooks {
    fn os_parse_until(
        self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>>;
}

impl UniversalExporterOSHooks for UniversalExporter {
    fn os_parse_until(
        self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        self.os_parse_controlled(name, crate::stop::CaptureStop::Predicate(Box::new(until)))
    }
}

impl UniversalExporter {
    pub fn new(settings: ExportSettings) -> Self {
        let mut cpu_buf_bytes = 64*1024;

        if settings.has_unwinder() {
            /* Unwinders need more data per-CPU than normal */
            cpu_buf_bytes = 1024*1024;
        }

        Self {
            settings: Some(settings),
            setting_hooks: Vec::new(),
            build_hooks: Vec::new(),
            export_hooks: Vec::new(),
            parsed_hooks: Vec::new(),
            drop_hooks: Vec::new(),
            cpu_buf_bytes,
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

    pub fn with_per_cpu_buffer_bytes(
        mut self,
        bytes: usize) -> Self {
        self.cpu_buf_bytes = bytes;
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
        self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        self.apply_settings()?.os_parse_until(name, until)
    }

    /// Collect until notified, then finalize the capture before returning the machine.
    /// An already-stopped token returns [`crate::ParseCancelledBeforeStart`] before running any hooks.
    /// On Linux, stop wakes the reader independently of the data wakeup threshold.
    /// The reader also rechecks for records below that threshold when its read timeout
    /// expires (15 ms by default), without waiting for another event or for shutdown.
    ///
    /// Register the handle with your application's shutdown callback. Requesting stop
    /// does not wait; the collecting thread receives the finalized machine.
    ///
    /// ```no_run
    /// use one_collect::{helpers::exporting::UniversalExporter, StopHandle};
    ///
    /// # fn collect(on_shutdown: impl FnOnce(Box<dyn Fn() + Send + Sync>)) -> anyhow::Result<()> {
    /// let exporter = UniversalExporter::new(Default::default());
    /// let (stop, token) = StopHandle::pair()?;
    /// on_shutdown(Box::new(move || stop.request_stop()));
    /// let machine = exporter.parse_until_stop_requested("my-app-trace", token)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_until_stop_requested(self, name: &str, token: crate::StopToken)
        -> anyhow::Result<Writable<ExportMachine>> {
        token.check_before_start()?;
        self.apply_settings()?.os_parse_controlled(name, crate::stop::CaptureStop::Token(token))
    }

    fn apply_settings(mut self) -> anyhow::Result<Self> {
        /* Run Setting Hooks */
        if let Some(mut settings) = self.settings.take() {
            for hook in &mut self.setting_hooks {
                settings = hook(settings)?;
            }

            self.settings = Some(settings);
        }

        Ok(self)
    }

    pub(crate) const fn cpu_buf_bytes(&self) -> usize { self.cpu_buf_bytes }

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
    fn pre_stopped_token_skips_export_setup() {
        let exporter = UniversalExporter::new(ExportSettings::default())
            .with_settings_hook(|_| panic!("must not configure a skipped capture"));
        let (stop, token) = crate::StopHandle::pair().unwrap();
        stop.request_stop();
        let result = exporter.parse_until_stop_requested("unused", token);
        assert!(matches!(result, Err(e) if e.is::<crate::ParseCancelledBeforeStart>()));
    }
}
