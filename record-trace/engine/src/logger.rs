// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::commandline::{RecordArgs, LogMode};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// Resolve the log file path based on provided arguments.
/// 
/// Log path resolution:
///   - If --log-path is specified, uses that path
///   - If --out has a file extension, uses <out_dir>/<stem>.log
///   - If --out is a directory, uses <out_dir>/trace.log
///   - Otherwise, creates a trace.log in the current directory
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

/// Initialize tracing/logging
fn init_logging(filter: &Option<String>, path: Option<PathBuf>, args: &RecordArgs) {
    const DEFAULT_FILTER: &str = "info";
    
    // Check if logging is disabled
    if args.log_mode() == LogMode::Disabled {
        return;
    }

    // Build filter with default "info" level plus any user-specified rules
    let filter_str = if let Some(user_filter) = filter {
        format!("{},{}", DEFAULT_FILTER, user_filter)
    } else {
        DEFAULT_FILTER.to_string()
    };
    
    let env_filter =
        EnvFilter::try_new(&filter_str)
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    let filter_str = env_filter.to_string();

    match args.log_mode() {
        LogMode::Disabled => {
            // Already returned above, but include to satisfy the compiler
            return;
        }
        LogMode::Console => {
            // Log to console (stdout)
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)        // Apply the configured filter to control log levels
                .with_ansi(true)                    // Enable ANSI color codes for console output
                .init();                            // Initialize the subscriber as the global default
        }
        LogMode::File => {
            // Log to file
            let path = path.expect("Path must be provided for file logging");
            let file = match std::fs::OpenOptions::new()
                .create(true)      // Create the file if it doesn't exist
                .write(true)       // Open the file for writing
                .truncate(true)    // Clear the file contents if it already exists
                .open(&path)       // Open the file at the specified path
            {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open log file at {}: {}", path.display(), e);
                    return;
                }
            };

            tracing_subscriber::fmt()
                .with_writer(file)                  // Write logs to the file instead of stdout
                .with_env_filter(env_filter)        // Apply the configured filter to control log levels
                .with_ansi(false)                   // Disable ANSI color codes in log output
                .init();                            // Initialize the subscriber as the global default
        }
    }
    
    tracing::info!("Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Log filter: {}", filter_str);
    args.write_to_log();
}

/// Common initialization logic for logging
fn start(args: &RecordArgs) {
    let path =
        if args.log_mode() == LogMode::File {
            Some(resolve_log_path(args.log_path(), args.output_path()))
        } else {
            None
        };

    init_logging(args.log_filter(), path, args);
}

/// Initialize logging for the executable (always logs)
pub fn start_for_exe(args: &RecordArgs) {
    start(args);
}

/// Initialize logging for FFI (only logs if filter or log_path was provided)
pub fn start_for_ffi(args: &RecordArgs) {
    // Only initialize logging if user explicitly requested it
    if args.log_filter().is_some() || args.log_path().is_some() {
        start(args);
    }
}
