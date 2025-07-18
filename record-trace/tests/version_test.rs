// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::process::Command;

#[test]
fn test_version_output_contains_dev() {
    // Test that the default build shows development version
    let output = Command::new("cargo")
        .args(&["run", "--", "--version"])
        .current_dir(".")
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8");
    
    // Should contain "0.1.0-dev" when built normally
    assert!(stdout.contains("0.1.0-dev"), "Version should contain '0.1.0-dev', got: {}", stdout);
    assert!(stdout.contains("record-trace"), "Output should contain 'record-trace', got: {}", stdout);
}

#[test]
fn test_version_flag_works() {
    // Test that --version flag is available and works
    let output = Command::new("cargo")
        .args(&["run", "--", "--version"])
        .current_dir(".")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8");
    assert!(!stdout.is_empty(), "Version output should not be empty");
}