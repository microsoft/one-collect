// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod commandline;
mod export;
mod recorder;

use commandline::RecordArgs;
use recorder::Recorder;

fn main() {
    let mut recorder = Recorder::new(RecordArgs::parse());
    recorder.run();
}