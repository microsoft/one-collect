// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{Guid, guid_from_provider_name_hash};

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
                /* Event Source: name-hashed control GUID.  Delegates to the
                 * shared `guid_from_provider_name_hash` so the namespace seed
                 * and encoding live in exactly one place. */
                Ok(guid_from_provider_name_hash(provider_name))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The `.NET` runtime special-cases must keep returning their fixed legacy
    /// GUIDs (they intentionally override the name-hash, so this guards the
    /// match arms after the refactor to delegate the generic branch).
    #[test]
    fn dotnet_runtime_special_case_is_unchanged() {
        assert_eq!(
            guid_from_provider("Microsoft-Windows-DotNETRuntime").unwrap().to_bytes(),
            Guid::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4).to_bytes());
    }

    /// A non-special name now delegates to `guid_from_provider_name_hash`; verify
    /// the result is byte-identical to that shared primitive (the refactor must
    /// not change any resolved GUID).
    #[test]
    fn generic_name_delegates_to_eventsource_hash() {
        let name = "OneCollect-Test-Provider";
        assert_eq!(
            guid_from_provider(name).unwrap().to_bytes(),
            guid_from_provider_name_hash(name).to_bytes());
    }

    /// A `{GUID}` literal is still parsed directly.
    #[test]
    fn guid_literal_is_parsed() {
        assert_eq!(
            guid_from_provider("{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}").unwrap().to_bytes(),
            Guid::from_u128(0xE13C0D23_CCBC_4E12_931B_D9CC2EEE27E4).to_bytes());
    }
}
