// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use clap::Args;
use one_collect::helpers::exporting::ExportSettings;

#[derive(Args, Debug)]
pub(crate) struct OSArgs {}

impl OSArgs {
    pub(crate) fn apply_to(&self, settings: ExportSettings) -> ExportSettings {
        settings
    }

    pub(crate) fn write_to_log(&self) {}
}
