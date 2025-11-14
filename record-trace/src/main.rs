// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{info, debug};

use engine::commandline::RecordArgs;
use engine::recorder::Recorder;
use engine::EngineOutput;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let mut output = EngineOutput::default();

    let continue_recording = Arc::new(AtomicBool::new(true));
    let handler_clone = continue_recording.clone();

    // Record until the user hits CTRL+C.
    ctrlc::set_handler(move || {
        debug!("CTRL+C signal received");
        handler_clone.store(false, Ordering::SeqCst);
    }).expect("Unable to setup CTRL+C handler");

    output.with_progress(move |_| {
        if !continue_recording.load(Ordering::SeqCst) {
            1
        } else {
            0
        }
    });

    // Tell users to hit CTRL+C to stop.
    output.with_start(|output| {
        println!("{}  Press CTRL+C to stop.", output);
        0
    });

    // Skip CTRL+C character before ending.
    output.with_end(|output| {
        println!("\n{}", output);
        0
    });

    // Record.
    let mut recorder = Recorder::new(
        RecordArgs::parse(std::env::args_os()),
        output);

    let exit_code = recorder.run();
    info!("record-trace exiting: exit_code={}", exit_code);
}
