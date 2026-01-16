// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{info, debug};

use engine::commandline::RecordArgs;
use engine::recorder::Recorder;
use engine::EngineOutput;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// Resolve the log file path based on provided arguments
fn resolve_log_path(log_path: &Option<String>, output_path: &PathBuf) -> PathBuf {
    if let Some(path) = log_path {
        return PathBuf::from(path);
    }

    // Check if output_path has an extension (is a file)
    if output_path.extension().is_some() {
        // It's a file, use stem.log
        if let Some(stem) = output_path.file_stem() {
            if let Some(parent) = output_path.parent() {
                return parent.join(format!("{}.log", stem.to_string_lossy()));
            } else {
                return PathBuf::from(format!("{}.log", stem.to_string_lossy()));
            }
        }
    } else {
        // It's a directory, use <dir>/trace.log
        return output_path.join("trace.log");
    }

    // Default to current directory
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("trace.log")
}

/// Initialize tracing/logging with file output
fn init_logging(filter: &Option<String>, path: &PathBuf) {
    const DEFAULT_FILTER: &str = "info";
    
    let file = match std::fs::OpenOptions::new()
        .create(true)      // Create the file if it doesn't exist
        .write(true)       // Open the file for writing
        .truncate(true)    // Clear the file contents if it already exists
        .open(path)        // Open the file at the specified path
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open log file at {}: {}", path.display(), e);
            return;
        }
    };

    // Build filter with default "info" level plus any user-specified rules
    let filter_str = if let Some(user_filter) = filter {
        format!("{},{}", DEFAULT_FILTER, user_filter)
    } else {
        DEFAULT_FILTER.to_string()
    };
    
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&filter_str))
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    let filter_str = env_filter.to_string();

    tracing_subscriber::fmt()
        .with_writer(file)                  // Write logs to the file instead of stdout
        .with_env_filter(env_filter)        // Apply the configured filter to control log levels
        .with_ansi(false)                   // Disable ANSI color codes in log output
        .init();                            // Initialize the subscriber as the global default
    
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Log filter: {}", filter_str);
}

fn main() {
    let args = RecordArgs::parse(std::env::args_os());

    // Initialize logging before anything else
    let resolved_log_path = resolve_log_path(args.log_path(), args.output_path());
    init_logging(args.log_filter(), &resolved_log_path);

    // Log the parsed arguments
    args.write_to_log();

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
        args,
        output);

    let exit_code = recorder.run();
    info!("record-trace exiting: exit_code={}", exit_code);
}
