// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::tracefs::TraceFS;
use crate::scripting::ScriptEvent;
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

#[derive(Default)]
pub struct OSScriptEngine {
}

impl OSScriptEngine {
    pub fn enable(
        &mut self,
        engine: &mut Engine) {
        /* Use single tracefs for all function invocations */
        let tracefs = match TraceFS::open() {
            Ok(tracefs) => { Some(tracefs) },
            Err(_) => { None },
        };

        let fn_tracefs = Writable::new(tracefs);

        engine.register_fn(
            "event_from_tracefs",
            move |system: String, name: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
                if let Some(tracefs) = fn_tracefs.borrow().as_ref() {
                    match tracefs.find_event(&system, &name) {
                        Ok(event) => { Ok(event.into()) },
                        Err(_) => {
                            Err(format!(
                                "Event \"{}/{}\" not found.", &system, &name).into())
                        },
                    }
                } else {
                    Err("TraceFS is not accessible (check permissions).".into())
                }
            });
    }
}
