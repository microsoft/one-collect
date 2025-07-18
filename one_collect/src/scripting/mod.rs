// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::cell::RefCell;

use crate::event::*;

use rhai::{Engine, CustomType, TypeBuilder};

mod os;
use os::OSScriptEngine;

pub struct ScriptEvent {
    event: RefCell<Option<Event>>,
}

impl ScriptEvent {
    pub fn to_event(self) -> Option<Event> {
        self.event.take()
    }

    pub fn without_callstacks(&mut self) {
        if let Some(event) = self.event.borrow_mut().as_mut() {
            event.set_no_callstack_flag();
        }
    }

    pub fn append_field(
        &mut self,
        name: String,
        type_name: String,
        size: i64) {
        if let Some(event) = self.event.borrow_mut().as_mut() {
            let format = event.format_mut();
            let mut offset = 0;

            if let Some(field) = format.fields().last() {
                offset = field.offset + field.size;
            }

            let location = if type_name.starts_with("__rel_loc") {
                LocationType::DynRelative
            } else if type_name.starts_with("__data_loc") {
                LocationType::DynAbsolute
            } else {
                if type_name == "wchar" || type_name == "string" {
                    LocationType::StaticUTF16String
                } else {
                    LocationType::Static
                }
            };

            format.add_field(
                EventField::new(
                    name,
                    type_name,
                    location,
                    offset,
                    size as usize));
        }
    }
}

impl CustomType for ScriptEvent {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("append_field", Self::append_field)
            .with_fn("without_callstacks", Self::without_callstacks);
    }
}

impl From<Event> for ScriptEvent {
    fn from(event: Event) -> Self {
        Self {
            event: RefCell::new(Some(event)),
        }
    }
}

impl Clone for ScriptEvent {
    fn clone(&self) -> Self {
        Self {
            event: self.event.take().into(),
        }
    }
}

#[derive(Clone)]
pub struct ScriptEnvironment {
    os_major: u16,
    os_minor: u16,
}

impl Default for ScriptEnvironment {
    fn default() -> Self {
        let (os_major, os_minor) = os::version();

        Self {
            os_major,
            os_minor,
        }
    }
}

impl CustomType for ScriptEnvironment {
    fn build(mut builder: TypeBuilder<Self>) {
        builder
            .with_fn("engine_major", Self::engine_major)
            .with_fn("engine_minor", Self::engine_minor)
            .with_fn("os_major", Self::os_major)
            .with_fn("os_minor", Self::os_minor)
            .with_fn("is_os", Self::is_os);
    }
}

impl ScriptEnvironment {
    pub fn is_os(
        &mut self,
        os: String) -> bool {
        match os.as_str() {
            "windows" => {
                #[cfg(target_os = "windows")]
                return true;

                #[cfg(not(target_os = "windows"))]
                return false;
            },

            "linux" => {
                #[cfg(target_os = "linux")]
                return true;

                #[cfg(not(target_os = "linux"))]
                return false;
            },

            _ => { false },
        }
    }

    pub fn engine_major(&mut self) -> u16 { 1 }

    pub fn engine_minor(&mut self) -> u16 { 0 }

    pub fn os_major(&mut self) -> u16 { self.os_major }

    pub fn os_minor(&mut self) -> u16 { self.os_minor }
}

pub struct ScriptEngine {
    engine: Engine,
    os: OSScriptEngine,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        engine.
            build_type::<ScriptEvent>().
            build_type::<ScriptEnvironment>().
            register_fn(
                "new_environment",
                || -> ScriptEnvironment { ScriptEnvironment::default() });

        Self {
            engine,
            os: OSScriptEngine::default(),
        }
    }

    pub(crate) fn rhai_engine(&mut self) -> &mut Engine { &mut self.engine }

    pub fn enable_os_scripting(&mut self) {
        self.os.enable(&mut self.engine);
    }

    pub fn eval<T: Clone + 'static>(
        &self,
        script: &str) -> anyhow::Result<T> {
        match self.engine.eval(script) {
            Ok(value) => { Ok(value) },
            Err(err) => {
                anyhow::bail!("Error: {}", err);
            }
        }
    }

    pub fn run(
        &self,
        script: &str) -> anyhow::Result<()> {
        match self.engine.run(script) {
            Ok(()) => { Ok(()) },
            Err(err) => {
                anyhow::bail!("Error: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_scripting() {
        let mut engine = ScriptEngine::new();

        engine.enable_os_scripting();

        let result = engine.eval::<bool>("new_environment().is_os(\"windows\")").unwrap();

        #[cfg(target_os = "windows")]
        assert_eq!(true, result);

        #[cfg(target_os = "linux")]
        assert_eq!(false, result);

        let result = engine.eval::<bool>("new_environment().is_os(\"linux\")").unwrap();

        #[cfg(target_os = "windows")]
        assert_eq!(false, result);

        #[cfg(target_os = "linux")]
        assert_eq!(true, result);
    }

    #[test]
    fn it_works() {
        let engine = ScriptEngine::new();

        let i = engine.eval::<i64>("42").unwrap();

        assert_eq!(42, i);
    }
}
