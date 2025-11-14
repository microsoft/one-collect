// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use engine::commandline::RecordArgs;
use engine::recorder::Recorder;
use engine::EngineOutput;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// Parse logging-related arguments from command line before full parsing
fn parse_logging_args() -> (Option<String>, Option<String>, Option<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut log_filter = None;
    let mut log_path = None;
    let mut output_path = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--log-filter" && i + 1 < args.len() {
            log_filter = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--log-path" && i + 1 < args.len() {
            log_path = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--out" && i + 1 < args.len() {
            output_path = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    (log_filter, log_path, output_path)
}

/// Resolve the log file path based on provided arguments
fn resolve_log_path(log_path: Option<String>, output_path: Option<String>) -> PathBuf {
    if let Some(path) = log_path {
        return PathBuf::from(path);
    }

    if let Some(out) = output_path {
        let out_path = PathBuf::from(out);
        
        // Check if it has an extension (is a file)
        if out_path.extension().is_some() {
            // It's a file, use stem.log
            if let Some(stem) = out_path.file_stem() {
                if let Some(parent) = out_path.parent() {
                    return parent.join(format!("{}.log", stem.to_string_lossy()));
                } else {
                    return PathBuf::from(format!("{}.log", stem.to_string_lossy()));
                }
            }
        } else {
            // It's a directory, use <dir>/trace.log
            return out_path.join("trace.log");
        }
    }

    // Default to current directory
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("trace.log")
}

/// Initialize tracing/logging with file output
fn init_logging(filter: &Option<String>, path: &PathBuf) {
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open log file at {}: {}", path.display(), e);
            return;
        }
    };

    let filter_str = filter.as_deref().unwrap_or("info");
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter_str))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_writer(file)
        .with_env_filter(env_filter)
        .with_ansi(false)
        .init();
    
    tracing::info!("Logging initialized. Log file: {}", path.display());
    tracing::info!("Log filter: {}", filter_str);
}

fn main() {
    // Parse logging args early, before full argument parsing
    let (log_filter, log_path, output_path) = parse_logging_args();
    let resolved_log_path = resolve_log_path(log_path, output_path);
    
    // Initialize logging before anything else
    init_logging(&log_filter, &resolved_log_path);

    let mut output = EngineOutput::default();

    let continue_recording = Arc::new(AtomicBool::new(true));
    let handler_clone = continue_recording.clone();

    // Record until the user hits CTRL+C.
    ctrlc::set_handler(move || {
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

    recorder.run();
}
