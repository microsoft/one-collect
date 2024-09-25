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

type BoxedBuildCallback = Box<dyn FnMut(SessionBuilder, &mut UniversalBuildSessionContext) -> anyhow::Result<SessionBuilder>>;
type BoxedParsedCallback = Box<dyn FnMut(&mut UniversalParsedContext) -> anyhow::Result<()>>;

pub struct UniversalExporter {
    settings: Option<ExportSettings>,
    build_hooks: Vec<BoxedBuildCallback>,
    parsed_hooks: Vec<BoxedParsedCallback>,
}

impl UniversalExporter {
    pub fn new(settings: ExportSettings) -> Self {
        Self {
            settings: Some(settings),
            build_hooks: Vec::new(),
            parsed_hooks: Vec::new(),
        }
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

    pub fn parse_for_duration(
        self,
        name: &str,
        duration: std::time::Duration) -> anyhow::Result<Writable<ExportMachine>> {
        let now = std::time::Instant::now();

        self.parse_until(
            name,
            move || { now.elapsed() >= duration })
    }

    fn run_build_hooks(
        &mut self,
        mut builder: SessionBuilder) -> anyhow::Result<SessionBuilder> {
        let mut context = UniversalBuildSessionContext {
        };

        for hook in &mut self.build_hooks {
            builder = hook(builder, &mut context)?;
        }

        Ok(builder)
    }

    fn run_parsed_hooks(
        &mut self,
        machine: &Writable<ExportMachine>) -> anyhow::Result<()> {
        let mut context = UniversalParsedContext {
            machine: &mut machine.borrow_mut(),
        };

        for hook in &mut self.parsed_hooks {
            hook(&mut context)?;
        }

        Ok(())
    }

    fn settings(
        &mut self) -> anyhow::Result<ExportSettings> {
        match self.settings.take() {
            Some(settings) => { Ok(settings) },
            None => { anyhow::bail!("No settings.") },
        }
    }

    pub fn parse_until(
        self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        self.os_parse_until(
            name,
            until)
    }

    #[cfg(target_os = "linux")]
    fn os_parse_until(
        mut self,
        _name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        use crate::perf_event::*;

        let settings = self.settings()?;

        /*
         * TODO:
         * Make per-CPU buffer size universally
         * configurable within ExportSettings
         */
        let builder = RingBufSessionBuilder::new()
            .with_page_count(256)
            .with_exporter_events(&settings);

        let mut builder = self.run_build_hooks(builder)?;

        let mut session = builder.build()?;

        let exporter = session.build_exporter(settings)?;

        session.capture_environment();

        session.enable()?;
        session.parse_until(until)?;
        session.disable()?;

        self.run_parsed_hooks(&exporter)?;

        Ok(exporter)
    }

    #[cfg(target_os = "windows")]
    fn os_parse_until(
        mut self,
        name: &str,
        until: impl Fn() -> bool + Send + 'static) -> anyhow::Result<Writable<ExportMachine>> {
        use crate::etw::*;
        use crate::helpers::callstack::*;

        let settings = self.settings()?;

        let callstack_helper = match settings.callstack_helper.as_ref() {
            Some(helper) => { helper },
            None => { anyhow::bail!("CallstackHelper is not set."); },
        };

        let mut session = EtwSession::new()
            .with_callstack_help(&callstack_helper);

        session = self.run_build_hooks(session)?;

        let exporter = session.build_exporter(settings)?;

        session.capture_environment();

        session.parse_until(name, until)?;

        self.run_parsed_hooks(&exporter)?;

        Ok(exporter)
    }
}
