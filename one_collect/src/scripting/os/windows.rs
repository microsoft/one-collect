use crate::event::*;
use crate::etw::Guid;

use crate::scripting::ScriptEvent;

use rhai::{Engine, EvalAltResult};

#[derive(Default)]
pub struct OSScriptEngine {
}

impl OSScriptEngine {
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
            let provider = provider.replace("-", "");

            let provider = match u128::from_str_radix(provider.trim(), 16) {
                Ok(provider) => { provider },
                Err(_) => { return Err("Invalid provider format.".into()); }
            };

            if level > 255 {
                return Err("Level must be 8-bit.".into());
            }

            if id > u32::max as i64 {
                return Err("Id must be 32-bit.".into());
            }

            let mut event = Event::new(id as usize, name);

            *event.extension_mut().provider_mut() = Guid::from_u128(provider);
            *event.extension_mut().level_mut() = level as u8;
            *event.extension_mut().keyword_mut() = keyword as u64;

            Ok(event.into())
        });
    }
}
