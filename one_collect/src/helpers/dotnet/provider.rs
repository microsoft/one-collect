// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::Guid;

pub(crate) fn event_full_name(provider_name: &str, guid: Guid, event_name: &str) -> String {
    use std::fmt::Write;

    let mut full = String::new();

    full.push_str(provider_name);
    full.push_str(":{");

    let _ = write!(
        full,
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.data1, guid.data2, guid.data3,
        guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
        guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]);

    full.push_str("}/");
    full.push_str(event_name);

    full
}

pub(crate) fn guid_from_provider(provider_name: &str) -> anyhow::Result<Guid> {
    match provider_name {
        "Microsoft-Windows-DotNETRuntime" => {
            Ok(Guid::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4))
        },
        "Microsoft-Windows-DotNETRuntimeRundown" => {
            Ok(Guid::from_u128(0xA669021C_C450_4609_A035_5AF59AF4DF18))
        },
        "Microsoft-Windows-DotNETRuntimeStress" => {
            Ok(Guid::from_u128(0xCC2BCBBA_16B6_4cf3_8990_D74C2E8AF500))
        },
        "Microsoft-Windows-DotNETRuntimePrivate" => {
            Ok(Guid::from_u128(0x763FD754_7086_4dfe_95EB_C01A46FAF4CA))
        },
        "Microsoft-DotNETRuntimeMonoProfiler" => {
            Ok(Guid::from_u128(0x7F442D82_0F1D_5155_4B8C_1529EB2E31C2))
        },
        _ => {
            if provider_name.starts_with("{") {
                /* Direct Guid */
                let provider = provider_name
                    .replace("-", "")
                    .replace("{", "")
                    .replace("}", "");

                match u128::from_str_radix(provider.trim(), 16) {
                    Ok(provider) => { Ok(Guid::from_u128(provider)) },
                    Err(_) => { anyhow::bail!("Invalid provider format."); }
                }
            } else {
                /* Event Source */
                let namespace_bytes: [u8; 16] = [
                    0x48, 0x2C, 0x2D, 0xB2,
                    0xC3, 0x90, 0x47, 0xC8,
                    0x87, 0xF8, 0x1A, 0x15,
                    0xBF, 0xC1, 0x30, 0xFB];

                /* EventSource encodes the name as upper-case UTF-16BE */
                let mut name_bytes = Vec::with_capacity(provider_name.len() * 2);
                for c in provider_name.to_uppercase().chars() {
                    name_bytes.extend_from_slice(&(c as u16).to_be_bytes());
                }

                Ok(Guid::v5_from_name(&namespace_bytes, &name_bytes))
            }
        }
    }
}

#[derive(Default, Clone)]
pub(crate) struct DotNetProviderFlags {
    callstacks: bool,
    callstack_keywords: u64,
}

impl DotNetProviderFlags {
    #[cfg(feature = "scripting")]
    pub(crate) const fn with_callstacks(&mut self) {
        self.callstacks = true;
        self.callstack_keywords = u64::MAX;
    }

    #[cfg(feature = "scripting")]
    pub(crate) const fn with_callstacks_for_keywords(
        &mut self,
        keywords: u64) {
        self.callstacks = true;
        self.callstack_keywords = keywords;
    }

    #[allow(dead_code)]
    pub(crate) fn callstacks(&self) -> bool { self.callstacks }

    #[allow(dead_code)]
    pub(crate) fn callstack_keywords(&self) -> u64 { self.callstack_keywords }
}
