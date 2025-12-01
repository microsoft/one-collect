// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::os::system_page_size;
use crate::tracefs::TraceFS;
use crate::scripting::ScriptEvent;
use crate::event::Event;
use crate::page_size_to_mask;
use crate::Writable;

use rhai::{Engine, EvalAltResult};

pub(crate) fn version() -> (u16, u16) {
    let mut major = 0;
    let mut minor = 0;

    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let mut numbers = release.split('.');

        if let Some(first) = numbers.next() {
            major = first.parse::<u16>().unwrap_or_default();

            if let Some(second) = numbers.next() {
                minor = second.parse::<u16>().unwrap_or_default();
            }
        }
    }

    (major, minor)
}

pub struct OSScriptEngine {
    probe_cleanups: Writable<Vec<String>>,
}

impl Default for OSScriptEngine {
    fn default() -> Self {
        Self {
            probe_cleanups: Writable::new(Vec::new()),
        }
    }
}

impl OSScriptEngine {
    fn event_from_probe(
        tracefs: Writable<std::io::Result<TraceFS>>,
        system: &str,
        name: &str,
        command: &str) -> anyhow::Result<Event> {
        match tracefs.borrow().as_ref() {
            Ok(tracefs) => {
                match tracefs.dynamic_event_command(&command) {
                    Ok(()) => {
                        match tracefs.find_event(&system, &name) {
                            Ok(event) => { Ok(event.into()) },
                            Err(_) => {
                                anyhow::bail!("Event \"{}/{}\" not found.", &system, &name);
                            },
                        }
                    },
                    Err(err) => {
                        anyhow::bail!("Dynamic events parsing error: {}", err);
                    }
                }
            },
            Err(err) => {
                anyhow::bail!("TraceFS is not accessible: {}", err);
            }
        }
    }

    fn elf_symbol_offset(
        path: &str,
        name: &str) -> anyhow::Result<u64> {
        use ruwind::elf::{self, SHT_DYNSYM, SHT_SYMTAB};
        use std::fs::File;

        let mut file = File::open(path)?;
        let mut sections = Vec::new();
        let page_size = system_page_size();
        let page_mask = page_size_to_mask(page_size);

        let load_header = elf::get_load_header(&mut file)?;

        /* Get symbol sections */
        elf::get_section_metadata(&mut file, None, SHT_SYMTAB, &mut sections)?;
        elf::get_section_metadata(&mut file, None, SHT_DYNSYM, &mut sections)?;

        let mut offset = None;

        /* Get symbols from those sections and pass to caller */
        elf::get_symbols(
            &mut file,
            &load_header,
            page_mask,
            &sections,
            |symbol| {
                if symbol.name() == name {
                    offset = Some(symbol.start());
            }
        })?;

        match offset {
            Some(offset) => { Ok(offset) },
            None =>{
                anyhow::bail!("Symbol \"{}\" not found in {}", name, path);
            }
        }
    }

    pub fn enable(
        &mut self,
        engine: &mut Engine) {
        /* Use single tracefs for all function invocations */
        let tracefs = Writable::new(TraceFS::open());

        let fn_tracefs = tracefs.clone();

        engine.register_fn(
            "event_from_tracefs",
            move |system: String, name: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            match fn_tracefs.borrow().as_ref() {
                Ok(tracefs) => {
                    match tracefs.find_event(&system, &name) {
                        Ok(event) => { Ok(event.into()) },
                        Err(_) => {
                            Err(format!(
                                "Event \"{}/{}\" not found.", &system, &name).into())
                        },
                    }
                },
                Err(err) => {
                    Err(format!("TraceFS is not accessible: {}", err).into())
                }
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_uprobe",
            move |
            system: String,
            name: String,
            path: String,
            symbol: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let offset = match Self::elf_symbol_offset(&path, &symbol) {
                Ok(offset) => { offset },
                Err(err) => { return Err(format!("Error: {}", err).into()); },
            };

            let command = format!(
                "p:{}/{} {}:0x{:x} {}",
                &system,
                &name,
                &path,
                offset,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_ret_uprobe",
            move |
            system: String,
            name: String,
            path: String,
            symbol: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let offset = match Self::elf_symbol_offset(&path, &symbol) {
                Ok(offset) => { offset },
                Err(err) => { return Err(format!("Error: {}", err).into()); },
            };

            let command = format!(
                "r:{}/{} {}:0x{:x} {}",
                &system,
                &name,
                &path,
                offset,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_kprobe",
            move |
            system: String,
            name: String,
            symbol: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let command = format!(
                "p:{}/{} {} {}",
                &system,
                &name,
                &symbol,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_ret_kprobe",
            move |
            system: String,
            name: String,
            symbol: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let command = format!(
                "r:{}/{} {} {}",
                &system,
                &name,
                &symbol,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_fprobe",
            move |
            system: String,
            name: String,
            symbol: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let command = format!(
                "f:{}/{} {} {}",
                &system,
                &name,
                &symbol,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });

        let fn_tracefs = tracefs.clone();
        let fn_cleanup = self.probe_cleanups.clone();

        engine.register_fn(
            "event_from_tprobe",
            move |
            system: String,
            name: String,
            tracepoint: String,
            args: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let command = format!(
                "t:{}/{} {} {}",
                &system,
                &name,
                &tracepoint,
                &args);

            match Self::event_from_probe(fn_tracefs.clone(), &system, &name, &command) {
                Ok(event) => {
                    fn_cleanup.borrow_mut().push(
                        format!("-:{}/{}", system, name));

                    Ok(event.into())
                },
                Err(err) => { Err(format!("Error: {}", err).into()) },
            }
        });
    }

    pub fn cleanup_task(&mut self) -> Box<dyn FnMut()> {
        let probe_cleanups = self.probe_cleanups.clone();

        Box::new(move || {
            /* Cleanup any probes with best effort */
            if let Ok(tracefs) = TraceFS::open() {
                for cleanup in probe_cleanups.borrow().iter() {
                    _ = tracefs.dynamic_event_command(&cleanup);
                }
            }
        })
    }
}
