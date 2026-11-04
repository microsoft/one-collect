// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fmt;

use clap::{Args, ValueEnum};
use one_collect::helpers::exporting::{ExportSettings, ExportSettingsLinuxExt};
use one_collect::perf_event::PerfClock;
use tracing::info;

#[derive(Args, Debug)]
pub(crate) struct OSArgs {
    #[arg(long = "clockid", visible_alias = "clock-id", short = 'k', default_value_t = ClockId::MonotonicRaw, help = "Clock shared by perf events and export timestamps")]
    clock_id: ClockId,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ClockId {
    #[value(name = "monotonic", alias = "mono", alias = "CLOCK_MONOTONIC")]
    Monotonic,
    #[value(name = "monotonic_raw", alias = "raw", alias = "CLOCK_MONOTONIC_RAW")]
    MonotonicRaw,
}

impl fmt::Display for ClockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monotonic => write!(f, "monotonic"),
            Self::MonotonicRaw => write!(f, "monotonic_raw"),
        }
    }
}

impl OSArgs {
    pub(crate) fn apply_to(&self, settings: ExportSettings) -> ExportSettings {
        let clock = match self.clock_id {
            ClockId::Monotonic => PerfClock::Monotonic,
            ClockId::MonotonicRaw => PerfClock::MonotonicRaw,
        };
        settings.with_perf_clock(clock)
    }

    pub(crate) fn write_to_log(&self) {
        info!("Arguments parsed: clock_id={}", self.clock_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commandline::{Args as CommandArgs, RecordArgs};
    use clap::Parser;
    use one_collect::helpers::exporting::ExportMachine;

    #[test]
    fn clockid_default_and_all_aliases_reach_export_settings() {
        let default = RecordArgs::parse(["record-trace", "--on-cpu"]);
        assert_eq!(ClockId::MonotonicRaw, default.os.clock_id);
        for (option, value, expected) in [
            ("--clockid", "monotonic", ClockId::Monotonic),
            ("--clockid", "mono", ClockId::Monotonic),
            ("--clockid", "CLOCK_MONOTONIC", ClockId::Monotonic),
            ("--clockid", "monotonic_raw", ClockId::MonotonicRaw),
            ("--clockid", "raw", ClockId::MonotonicRaw),
            ("--clockid", "CLOCK_MONOTONIC_RAW", ClockId::MonotonicRaw),
            ("--clock-id", "mono", ClockId::Monotonic),
            ("-k", "raw", ClockId::MonotonicRaw),
        ] {
            let args = RecordArgs::parse(["record-trace", "--on-cpu", option, value]);
            assert_eq!(expected, args.os.clock_id);
        }

        let monotonic = RecordArgs::parse(["record-trace", "--on-cpu", "--clockid", "monotonic"]);
        for (args, clock) in [(default, PerfClock::MonotonicRaw), (monotonic, PerfClock::Monotonic)] {
            let machine = ExportMachine::new(args.os.apply_to(ExportSettings::default()));
            let before = clock.timestamp();
            let timestamp = machine.qpc_time();
            let after = clock.timestamp();
            assert!((before..=after).contains(&timestamp));
        }
    }

    #[test]
    fn clockid_rejects_unsupported_and_missing_values() {
        for value in ["realtime", "invalid"] {
            let error = CommandArgs::try_parse_from(["record-trace", "--clockid", value])
                .err().expect("unsupported clock must fail");
            assert_eq!(clap::error::ErrorKind::InvalidValue, error.kind());
        }
        let error = CommandArgs::try_parse_from(["record-trace", "--clockid"])
            .err().expect("missing clock must fail");
        assert_eq!(clap::error::ErrorKind::InvalidValue, error.kind());
    }

    #[test]
    fn clockid_rejects_multiple_spellings_even_with_equal_values() {
        for args in [
            ["record-trace", "--clockid", "mono", "--clockid", "mono"],
            ["record-trace", "--clockid", "mono", "--clock-id", "raw"],
            ["record-trace", "--clock-id", "mono", "-k", "mono"],
        ] {
            let error = CommandArgs::try_parse_from(args)
                .err().expect("duplicate clock must fail");
            assert_eq!(clap::error::ErrorKind::ArgumentConflict, error.kind());
        }
    }
}
