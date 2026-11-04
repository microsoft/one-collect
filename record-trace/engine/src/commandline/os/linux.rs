// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fmt;

use clap::{Args, ValueEnum};
use one_collect::helpers::exporting::{ExportSettings, ExportSettingsLinuxExt};
use one_collect::perf_event::PerfClock;
use tracing::info;

#[derive(Args, Debug)]
pub(crate) struct OSArgs {
    #[arg(long = "clockid", default_value_t = ClockId::MonotonicRaw, help = "Clock shared by perf events and export timestamps")]
    clock_id: ClockId,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ClockId {
    #[value(name = "CLOCK_MONOTONIC")]
    Monotonic,
    #[value(name = "CLOCK_MONOTONIC_RAW")]
    MonotonicRaw,
}

impl fmt::Display for ClockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Monotonic => write!(f, "CLOCK_MONOTONIC"),
            Self::MonotonicRaw => write!(f, "CLOCK_MONOTONIC_RAW"),
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
