# record-trace - Command-Line Trace Recording Tool Design Document

## Overview

The record-trace system provides a command-line interface for recording system-wide performance traces. The architecture is factored into three separate crates:

- **Engine Crate**: Core trace recording logic and session management
- **FFI Crate**: Foreign Function Interface for language interoperability  
- **Record-Trace Executable Crate**: Command-line application that uses the engine

## Purpose and Responsibilities

- **User Interface**: Provide a command-line interface for trace recording
- **Configuration Management**: Handle recording configuration and validation
- **Output Management**: Coordinate trace data export to various output formats
- **Error Reporting**: Present clear, actionable error messages to users

## Module Deep Dive

### Command Line Interface (`commandline.rs`)

#### `RecordArgs` Structure
Central configuration structure containing:
- **Event Selection**: Which events to collect (CPU, context switches, etc.)
- **Output Configuration**: Format and destination settings
- **Filtering Options**: Event filtering and sampling configuration

#### Argument Parsing Strategy
- Uses `clap` derive macros for declarative argument definition
- Structured validation of argument combinations
- Context-aware help text and error messages

#### Validation Logic
Multi-phase validation:
1. **Syntax Validation**: Clap handles basic argument parsing
2. **Semantic Validation**: Custom validation for argument combinations
3. **Resource Validation**: Permission and capability checking (Happens in one_collect APIs)

### Core Recording Logic (`recorder.rs`)

#### `Recorder` Structure
Main orchestrator containing:
- Configuration from command-line arguments
- Export pipeline setup
- Event collection coordination
- Signal handling registration

#### Event Source Integration
- **CPU Profiling**: sampled CPU with configurable frequency
- **Context Switches**: scheduler event tracking
- **System Calls**: syscall entry/exit monitoring
- **Hardware Events**: PMU (Performance Monitoring Unit) events

### Export Coordination (`export.rs`)

#### Export Format Management
- **Format Detection**: Format selection based on file extension
- **Format Configuration**: Format-specific option handling

## Adding New File Formats

To add a new export format to record-trace, implement the format in the one_collect export system and integrate it with the command-line interface:

### 1. Implement an Exporter
```rust
// In your format implementation
pub struct MyCustomFormatExporter {
    // Format-specific configuration
}

impl Exporter for MyCustomFormatExporter {
    fn validate(&mut self, args: &RecordArgs) -> anyhow::Result<()> {
        // Format-specific export logic
        Ok(())
    }

    fn run(&mut self, machine: &mut ExportMachine, args: &RecordArgs) -> anyhow::Result<()> {
        // Format-specific export logic
        Ok(())
    }
}
```

### 2. Add the File Format to the Format Enum
```rust
// In commandline.rs
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Format {
    Nettrace,
    PerfviewXML,
    MyCustomFormat,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Nettrace => write!(f, "nettrace"),
            Format::PerfviewXML => write!(f, "perfview-xml"),
            Format::MyCustomFormat => write!(f, "my-custom-format"),
        }
    }
}
```

### 3. Update RecordArgs
```rust
// In commandline.rs
pub (crate) fn format(&self) -> Box<dyn Exporter> {
    match self.format {
        Format::Nettrace => Box::new(NetTraceExporter::new()),
        Format::PerfviewXML => Box::new(PerfViewExporter::new()),
        Format::MyCustomFormat => Box::new(MyCustomFormatExporter::new())
    }
}
```

## Example Usages

### Basic CPU Profiling
```bash
record-trace --on-cpu --output trace.nettrace
```
### On-CPU and Off-CPU Profiling
```bash
record-trace --on-cpu --off-cpu --output trace.nettrace
```

### Filter by Process IDs
```bash
record-trace --on-cpu --pid 42
```

### Capture Script File
```bash
record-trace --script-file script.file
```
