# record-trace - Command-Line Trace Recording Tool Design Document

## Overview

The `record-trace` crate is a command-line application built on top of the `one_collect` library that provides an easy-to-use interface for recording system-wide performance traces. It serves as both a practical tool for performance analysis and a reference implementation demonstrating how to use the one_collect framework.

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

#### Recording Flow
1. **Initialization Phase**:
   - Validate configuration compatibility
   - Set up export pipeline with appropriate settings
   - Configure event sources based on platform

2. **Setup Phase**:
   - Initialize platform-specific event collectors
   - Register event handlers with export pipeline
   - Set up signal handlers for graceful termination

3. **Collection Phase**:
   - Start event collection from OS sources
   - Process events through pipeline in real-time
   - Monitor for termination conditions

4. **Cleanup Phase**:
   - Stop event collection gracefully
   - Flush remaining data through pipeline
   - Finalize output files
   - Report collection statistics

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

#### Output File Management
- **File Creation**: Safe file creation with overwrite protection
- **Path Validation**: Ensure output directories exist and are writable
- **Atomic Writing**: Temporary files with atomic rename for consistency

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

## Configuration and Extensibility

### Configuration Sources
Multiple configuration sources in priority order:
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration files
4. Built-in defaults (lowest priority)

### Extensibility Points

#### Custom Event Sources
New event sources can be integrated by:
- Extending the one_collect event system
- Adding command-line options for new event types
- Implementing platform-specific collection logic

#### Custom Export Formats
New output formats supported through:
- one_collect export trait implementation
- Command-line format selection integration
- Format-specific validation logic

#### Custom Processing
Data processing customization via:
- Event handler registration
- Pipeline modification
- Script-based processing (when scripting feature enabled)

## Performance Characteristics

### Memory Usage
- **Streaming Processing**: Events processed as they arrive
- **Bounded Buffers**: Ring buffers prevent unbounded memory growth
- **Lazy Initialization**: Components initialized only when needed

### CPU Overhead
- **Minimal Hot Path**: Optimized event processing pipeline
- **Batch Processing**: Events processed in batches for efficiency
- **Platform Optimization**: Platform-specific performance tuning

### I/O Efficiency
- **Buffered Output**: Output buffering to reduce syscall overhead
- **Async I/O**: Non-blocking I/O where supported
- **Compression**: Optional output compression for large traces

## Signal Handling and Lifecycle

### Graceful Shutdown
Comprehensive signal handling for clean termination:
- **SIGINT/SIGTERM**: Graceful shutdown with data preservation
- **Cleanup Registration**: Resource cleanup handlers
- **Timeout Handling**: Bounded cleanup time to prevent hangs

### Resource Management
Careful resource lifecycle management:
- **RAII Patterns**: Automatic resource cleanup
- **Exception Safety**: Safe cleanup even during errors
- **Platform Resources**: Platform-specific resource management

## Testing Strategy

### Unit Tests
- **Command Parsing**: Argument parsing logic validation
- **Configuration**: Validation logic testing
- **Error Handling**: Error condition testing

### Integration Tests
- **End-to-End**: Full recording session testing
- **Platform Testing**: Platform-specific functionality
- **Format Testing**: Output format validation

### Manual Testing
- **Performance Testing**: Real workload profiling
- **Stress Testing**: Long-running session validation
- **Compatibility Testing**: Various system configurations

## Usage Patterns

### Basic CPU Profiling
```bash
record-trace --cpu --duration 30s --output profile.data
```

### Comprehensive System Tracing
```bash
record-trace --cpu --context-switches --syscalls --output trace.data
```

### Filtered Recording
```bash
record-trace --cpu --process-filter myapp --output filtered.data
```

### Custom Export Format
```bash
record-trace --cpu --format flamegraph --output profile.svg
```

## Future Extensions

### Planned Features
- **Remote Collection**: Network-based trace collection
- **Live Analysis**: Real-time trace analysis and visualization
- **Custom Scripting**: User-defined processing scripts
- **Distributed Tracing**: Multi-machine trace correlation

### Architecture Extensibility
The current design supports future extensions through:
- **Plugin Architecture**: Loadable modules for new functionality
- **API Stability**: Stable interfaces for external integration
- **Configuration Schema**: Extensible configuration format