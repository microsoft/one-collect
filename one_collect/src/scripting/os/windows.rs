// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::event::*;
use crate::Guid;

use crate::scripting::ScriptEvent;

use rhai::{Engine, EvalAltResult};
use tracing::{debug, info, warn, error};

#[repr(C)]
struct NtOsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
}

impl Default for NtOsVersionInfo {
    fn default() -> Self {
        NtOsVersionInfo {
            size: 276,
            major: 0,
            minor: 0,
            build: 0,
            platform: 0,
            csd: [0; 128],
        }
    }
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(version: &mut NtOsVersionInfo) -> u32;
}

pub(crate) fn version() -> (u16, u16) {
    let mut version = NtOsVersionInfo::default();

    let status = unsafe { RtlGetVersion(&mut version) };

    if status != 0 {
        /* Revert to default if any errors */
        version = NtOsVersionInfo::default();
    }

    (version.major as u16, version.minor as u16)
}

#[derive(Default)]
pub struct OSScriptEngine {
}

impl OSScriptEngine {
    fn provider_from_str(provider: &str) -> Result<Guid, Box<EvalAltResult>> {
        let provider = provider
            .replace("{", "")
            .replace("}", "")
            .replace("-", "");

        let provider = match u128::from_str_radix(provider.trim(), 16) {
            Ok(provider) => { provider },
            Err(_) => { return Err("Invalid provider format.".into()); }
        };

        Ok(Guid::from_u128(provider))
    }

    fn event_from_parts(
        provider: String,
        keyword: i64,
        level: i64,
        id: i64,
        name: String) -> Result<Event, Box<EvalAltResult>> {
        let provider = Self::provider_from_str(&provider)?;

        if level > 255 {
            return Err("Level must be 8-bit.".into());
        }

        if id > u32::max as i64 {
            return Err("Id must be 32-bit.".into());
        }

        let mut event = Event::new(id as usize, name);

        *event.extension_mut().provider_mut() = provider;
        *event.extension_mut().level_mut() = level as u8;
        *event.extension_mut().keyword_mut() = keyword as u64;

        Ok(event)
    }

    pub fn enable(
        &mut self,
        engine: &mut Engine) {
        engine.register_fn(
            "event_from_etw",
            move |
            provider: String,
            keyword: i64,
            level: i64,
            id: i64,
            name: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let event = Self::event_from_parts(
                provider,
                keyword,
                level,
                id,
                name)?;

            Ok(event.into())
        });

        engine.register_fn(
            "event_from_etw",
            move |
            provider: String,
            lookup_provider: String,
            keyword: i64,
            level: i64,
            id: i64,
            name: String| -> Result<ScriptEvent, Box<EvalAltResult>> {
            let lookup_provider = Self::provider_from_str(&lookup_provider)?;

            let mut event = Self::event_from_parts(
                provider,
                keyword,
                level,
                id,
                name)?;

            *event.extension_mut().lookup_provider_mut() = Some(lookup_provider);

            Ok(event.into())
        });
    }

    pub fn cleanup_task(&mut self) -> Box<dyn FnMut()> {
        /* Nothing */
        Box::new(|| {})
    }
}
