# record-trace - Command-Line Trace Recording Tool Design Document

## Overview

The record-trace system provides a command-line interface for recording system-wide performance traces. The architecture is planned to be refactored into three separate crates:

- **Engine Crate**: Core trace recording logic and session management
- **FFI Crate**: Foreign Function Interface for language interoperability  
- **Record-Trace Executable Crate**: Command-line application that uses the engine

Currently implemented as a single crate built on top of the `one_collect` library, providing an easy-to-use interface for recording system-wide performance traces.

## Purpose and Responsibilities

- **User Interface**: Provide an intuitive command-line interface for trace recording
- **Configuration Management**: Handle recording configuration and validation
- **Session Management**: Manage trace recording sessions with proper lifecycle handling
- **Signal Handling**: Gracefully handle interruption signals (Ctrl+C)
- **Output Management**: Coordinate trace data export to various output formats
- **Error Reporting**: Present clear, actionable error messages to users

## Architecture Overview

### Application Structure

The application follows a clean separation of concerns with four main modules:

#### `main.rs`
- Application entry point
- Minimal bootstrap logic
- Delegates to recorder for actual functionality

#### `commandline.rs`
- Command-line argument parsing using `clap`
- Configuration validation
- Help text and usage information

#### `recorder.rs`
- Core recording logic implementation
- Integration with `one_collect` framework
- Session lifecycle management

#### `export.rs`
- Output format implementations
- Export configuration handling
- Format-specific logic

### Design Patterns

#### Builder Pattern
Configuration and setup use builder patterns for:
- Export settings construction
- Event pipeline configuration
- Complex object initialization

#### Command Pattern
Recording operations encapsulated as commands:
- Clear separation of parsing and execution
- Testable business logic
- Configurable operation parameters

#### Strategy Pattern
Different recording strategies based on:
- Target platforms (Linux vs Windows)
- Event types (CPU profiling, context switches, etc.)
- Output formats (various export formats)

## Module Deep Dive

### Command Line Interface (`commandline.rs`)

#### `RecordArgs` Structure
Central configuration structure containing:
- **Recording Duration**: Time-based or manual termination
- **Event Selection**: Which events to collect (CPU, context switches, etc.)
- **Output Configuration**: Format and destination settings
- **Platform Options**: Platform-specific recording options
- **Filtering Options**: Event filtering and sampling configuration

#### Argument Parsing Strategy
- Uses `clap` derive macros for declarative argument definition
- Structured validation of argument combinations
- Context-aware help text and error messages
- Support for both short and long argument forms

#### Validation Logic
Multi-phase validation:
1. **Syntax Validation**: Clap handles basic argument parsing
2. **Semantic Validation**: Custom validation for argument combinations
3. **Platform Validation**: Platform-specific option checking
4. **Resource Validation**: Permission and capability checking

### Core Recording Logic (`recorder.rs`)

#### `Recorder` Structure
Main orchestrator containing:
- Configuration from command-line arguments
- Export pipeline setup
- Event collection coordination
- Signal handling registration

#### Event Source Integration

##### Linux Integration
- **CPU Profiling**: perf events with configurable frequency
- **Context Switches**: scheduler event tracking
- **System Calls**: syscall entry/exit monitoring
- **Hardware Events**: PMU (Performance Monitoring Unit) events

##### Windows Integration  
- **CPU Profiling**: ETW-based sampling
- **Context Switches**: ETW scheduler events
- **System Activities**: ETW system provider events

#### Error Handling Strategy
Layered error handling approach:
- **OS Errors**: Platform-specific error translation
- **Configuration Errors**: User-friendly validation messages
- **Runtime Errors**: Graceful degradation when possible
- **Fatal Errors**: Clear reporting and clean shutdown

### Export Coordination (`export.rs`)

#### Export Format Management
- **Format Detection**: Automatic format selection based on file extension
- **Format Validation**: Ensure format supports requested features
- **Format Configuration**: Format-specific option handling

#### Supported Export Formats
The tool supports various output formats through the one_collect export system:
- **Native Formats**: Framework-specific formats for maximum fidelity
- **Standard Formats**: Industry-standard profiling formats
- **Custom Formats**: User-defined export formats via scripting

## Cross-Platform Considerations

### Platform Abstraction
While built on the cross-platform one_collect library, the tool handles platform differences:

#### Linux Specifics
- **Privilege Requirements**: Some events require root privileges
- **Kernel Support**: Feature detection for kernel capabilities
- **perf Events**: Direct integration with Linux perf subsystem

#### Windows Specifics
- **Elevation Requirements**: ETW often requires elevated privileges
- **Provider Management**: ETW provider registration and lifecycle
- **Session Management**: ETW session creation and cleanup

### Permission Handling
Graceful handling of insufficient permissions:
- **Detection**: Early detection of permission requirements
- **Guidance**: Clear error messages explaining required permissions
- **Fallback**: Reduced functionality when full privileges unavailable

## Adding New File Formats

To add a new export format to record-trace, implement the format in the one_collect export system and integrate it with the command-line interface:

### 1. Define the Format Structure
```rust
// In your format implementation
pub struct MyCustomFormat {
    // Format-specific configuration
}

impl ExportFormat for MyCustomFormat {
    fn export(&mut self, data: &ExportData) -> anyhow::Result<()> {
        // Format-specific export logic
        Ok(())
    }
}
```

### 2. Add Command-Line Support
```rust
// In commandline.rs
#[derive(Parser)]
pub struct RecordArgs {
    // ... existing fields ...
    
    /// Enable my custom format output
    #[arg(long)]
    pub my_format: bool,
}
```

### 3. Integrate with Export Pipeline
```rust
// In recorder.rs
impl Recorder {
    fn setup_exports(&mut self) -> anyhow::Result<()> {
        if self.args.my_format {
            let format = MyCustomFormat::new();
            self.export_pipeline.add_format(Box::new(format))?;
        }
        Ok(())
    }
}
```

## Testing and Quality Assurance

### Testing Scope
Testing is limited to the command line parser.

## Example Usages

### Basic CPU Profiling
```bash
record-trace --on-cpu --output trace.nettrace
```

### Filter by Process IDs
```bash
record-trace --on-cpu --pid 42
```

### Capture Script File
```bash
record-trace --script-file script.file
```
