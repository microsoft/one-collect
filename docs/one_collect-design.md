# one_collect - Event Collection Framework Design Document

## Overview

The `one_collect` crate is the core library of the one-collect framework, providing a high-performance, cross-platform solution for collecting, processing, and exporting system events and profiling data. It supports Linux perf events and Windows ETW (Event Tracing for Windows) with a unified, composable pipeline architecture.

## Purpose and Responsibilities

- **Event Collection**: Capture system-wide events from OS-specific sources (perf events on Linux, ETW on Windows)
- **Pipeline Processing**: Route events through configurable processing pipelines with closure-based handlers
- **Data Export**: Transform collected data into various output formats for analysis tools
- **Cross-Platform Abstraction**: Provide consistent APIs across Linux and Windows platforms
- **Performance Optimization**: Minimize overhead during high-frequency event collection
- **Extensibility**: Enable custom event sources, processors, and export formats

## Architecture Overview

### Core Design Principles

#### Event-Driven Pipeline Architecture
The framework is built around an event-driven model where:
- Events are defined by format specifications (`EventFormat`)
- Data flows through pipelines of registered closures
- Each event type can have multiple handlers
- Handlers can be chained and composed

#### Composable Design
- Components can be mixed and matched
- Pre-built pipelines for common scenarios
- Custom pipelines for specialized use cases
- Trait-based extension points throughout

#### Zero-Copy Processing
- Event data processed in-place where possible
- Minimal allocations during event handling
- Efficient memory management for high-frequency scenarios

### Key Architectural Components

#### Event System (`event` module)

##### `Event`
Central event management structure that:
- Maintains event format information
- Manages registered event handlers (closures)
- Processes incoming event data
- Handles error collection and reporting

**Code Reference**: [`one_collect/src/event/mod.rs:1392`](one_collect/src/event/mod.rs#L1392-L1559)

##### `EventData`
Wrapper around raw event data providing:
- Access to full event payload
- Event-specific data extraction
- Format-aware data interpretation

**Code Reference**: [`one_collect/src/event/mod.rs:14`](one_collect/src/event/mod.rs#L14-L56)

##### `EventFormat`
Describes the structure and meaning of event data:
- Field definitions and types
- Parsing rules and constraints
- Platform-specific format variations

**Code Reference**: [`one_collect/src/event/mod.rs:350`](one_collect/src/event/mod.rs#L350-L1382)

#### Sharing System (`sharing` module)

##### `Writable<T>` and `ReadOnly<T>`
Type-safe shared data containers using `Rc<RefCell<T>>`:
- `Writable<T>`: Allows both reading and writing
- `ReadOnly<T>`: Read-only view of shared data
- Compile-time access control
- Interior mutability with runtime checks

```rust
pub type Writable<T> = SharedData<T, DataOwner>;
pub type ReadOnly<T> = SharedData<T, DataReader>;
```

#### Platform-Specific Tracers

The framework provides platform-specific event collection through direct integration with OS tracing facilities. Event closures can be hooked directly to these tracers for low-level event processing.

##### Linux: perf_events Integration

On Linux, the framework integrates with the kernel's perf_events subsystem to collect system-wide events:

**Code Reference**: [`one_collect/src/perf_event/mod.rs`](one_collect/src/perf_event/mod.rs)

```rust
use one_collect::perf_event::*;
use one_collect::event::*;

// Create a perf event for CPU cycles
let mut event = Event::new(0, "cpu-cycles".to_string());

// Get field references outside the closure for high performance
let cpu_field_ref = event.format().get_field_ref("cpu").unwrap();

// Register a closure to handle each event
event.add_callback(move |event_data: &EventData| -> anyhow::Result<()> {
    let cpu_id = event_data.format().get_u32(
        cpu_field_ref, 
        event_data.event_data()
    )?;
    
    println!("CPU cycles event on CPU {}", cpu_id);
    Ok(())
});

// Configure perf_event attributes
let mut builder = RingBufSessionBuilder::new();
builder.add_event(
    PERF_TYPE_HARDWARE,
    PERF_COUNT_HW_CPU_CYCLES,
    event
)?;

// Start collection
let session = builder.start()?;
```

##### Windows: ETW Integration

On Windows, the framework integrates with Event Tracing for Windows (ETW) for comprehensive system monitoring:

**Code Reference**: [`one_collect/src/etw/mod.rs`](one_collect/src/etw/mod.rs)

```rust
use one_collect::etw::*;
use one_collect::event::*;

// Create an ETW event
let mut event = Event::new(1, "process-start".to_string());

// Configure ETW provider information
let provider_guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
event.extension_mut().provider_mut().clone_from(&provider_guid);
*event.extension_mut().level_mut() = LEVEL_INFORMATION;
*event.extension_mut().keyword_mut() = 0x10; // Process keyword

// Get field references outside the closure for high performance
let process_id_field_ref = event.format().get_field_ref("ProcessId").unwrap();
let image_name_field_ref = event.format().get_field_ref("ImageFileName").unwrap();

// Register event handler
event.add_callback(move |event_data: &EventData| -> anyhow::Result<()> {
    let process_id = event_data.format().get_u32(
        process_id_field_ref,
        event_data.event_data()
    )?;
    
    let image_name = event_data.format().get_str(
        image_name_field_ref,
        event_data.event_data()
    )?;
    
    println!("Process started: {} (PID: {})", image_name, process_id);
    Ok(())
});

// Start ETW session
let mut session = TraceSession::new("MySession")?;
session.enable_provider(provider_guid, LEVEL_INFORMATION, 0x10)?;
session.add_event(event);
session.start()?;
```

#### Universal Export Framework

The Universal Export Framework provides the highest level of abstraction in the one-collect architecture. It operates above event closures and platform-specific tracers (perf_events/ETW), offering a scenario-based approach to profiling and tracing.

**Code Reference**: [`one_collect/src/helpers/exporting/universal.rs`](one_collect/src/helpers/exporting/universal.rs)

##### Core Components

###### ExportSettings
Configuration system that determines what data to collect and how to export it:

**Code Reference**: [`one_collect/src/helpers/exporting/mod.rs`](one_collect/src/helpers/exporting/mod.rs)

```rust
use one_collect::helpers::exporting::*;

// Create export settings for CPU profiling with stacks
let mut settings = ExportSettings::new();
settings.set_cpu_sampling_interval(Duration::from_millis(1));
settings.enable_callstacks(true);
settings.add_scenario("cpu_profiling");

// Settings automatically determine required events
// No need to manually specify individual events
```

###### ExportMachine  
Central state management that aggregates all collected data:

```rust
// The export machine accumulates data from all enabled scenarios
let machine = Writable::new(ExportMachine::new());

// Scenarios automatically enable required events and handle rundown
// for existing processes, kernel modules, etc.
```

###### Universal Structs
Cross-platform data representations that abstract OS differences:

```rust
use one_collect::helpers::exporting::record::*;

// Universal record types work across Linux and Windows
let process_record = UniversalProcessRecord {
    pid: 1234,
    name: "myapp.exe".to_string(),
    command_line: "myapp.exe --verbose".to_string(),
    // ... other fields
};
```

##### End-to-End Example

Here's a complete example showing how to capture CPU profiling data and export to multiple formats:

```rust
use one_collect::helpers::exporting::*;
use one_collect::helpers::exporting::universal::*;
use std::time::Duration;

// 1. Configure export settings
let mut settings = ExportSettings::new();
settings.set_cpu_sampling_interval(Duration::from_millis(1));
settings.enable_callstacks(true);
settings.set_output_path("profile_trace");

// Enable CPU profiling scenario - this automatically:
// - Determines what events are needed (timer, context switch, etc.)
// - Handles rundown for existing processes
// - Sets up appropriate event handlers
settings.add_scenario("cpu_profiling_with_stacks");

// 2. Create universal exporter
let mut exporter = UniversalExporter::new(settings);

// 3. Add export hooks for different formats
exporter.add_export_hook(|machine: &Writable<ExportMachine>| {
    // Export as PerfView-compatible ETL format
    machine.read(|export_machine| {
        export_machine.export_perfview("profile.etl")?;
        Ok(())
    })
});

exporter.add_export_hook(|machine: &Writable<ExportMachine>| {
    // Export as .NET nettrace format from same data
    machine.read(|export_machine| {
        export_machine.export_nettrace("profile.nettrace")?;
        Ok(())
    })
});

// 4. Start collection
let machine = exporter.start_collection("profiling_session")?;

// 5. Collection runs automatically...
std::thread::sleep(Duration::from_secs(10));

// 6. Stop and export
exporter.stop_and_export()?;
```

##### Scenario-Based Model

The Universal Export Framework moves beyond individual event specification to a scenario-based approach:

```rust
// Instead of manually specifying events:
// session.add_event(timer_event);
// session.add_event(context_switch_event);
// session.add_event(process_event);
// ... dozens more

// Simply enable scenarios:
settings.add_scenario("cpu_profiling");           // CPU sampling + stacks
settings.add_scenario("memory_tracking");         // Heap allocations
settings.add_scenario("io_monitoring");           // File/network I/O
settings.add_scenario("dotnet_gc_analysis");      // .NET GC events

// Each scenario automatically determines required events
// and handles cross-platform differences
```

#### Helpers System (`helpers` module)

##### Callstack Helper (`helpers::callstack`)
Stack unwinding integration:
- Integrates with `ruwind` library
- Manages unwinding context and state
- Provides callstack symbolization

##### .NET Helper (`helpers::dotnet`)
Managed code profiling support:
- CLR event processing
- Managed/native boundary handling
- .NET-specific data extraction

##### Scripting Integration (`helpers::scripting`)

The scripting engine integrates at the universal layer, allowing runtime customization of data processing. It hooks into the `ExportMachine` after all data has been aggregated:

**Code Reference**: [`one_collect/src/helpers/exporting/scripting.rs`](one_collect/src/helpers/exporting/scripting.rs)

```rust
use one_collect::helpers::exporting::*;

// Scripting hooks into the universal layer
let mut exporter = UniversalExporter::new(settings);

// Add script that processes aggregated data
exporter.add_parsed_hook(|context: &mut UniversalParsedContext| {
    let machine = context.machine_mut();
    
    // Script has access to all aggregated data
    // and can perform custom analysis/filtering
    machine.apply_custom_filter(|record| {
        // Custom filtering logic
        true
    })?;
    
    machine.add_custom_metric("my_metric", calculate_metric(&machine))?;
    Ok(())
});

// Result is an ExportMachine with all data aggregated
// and custom processing applied
let final_machine = exporter.process_with_scripts()?;
```

#### Utility Modules

##### Interning (`intern` module)
Memory-efficient string and data management through deduplication:

**Code Reference**: [`one_collect/src/intern.rs`](one_collect/src/intern.rs)

###### String Interning
```rust
use one_collect::intern::InternedStrings;

// Create an interned strings container
let mut strings = InternedStrings::new();

// Store strings with deduplication
let id1 = strings.intern("kernel32.dll");
let id2 = strings.intern("kernel32.dll"); // Same string, same ID
let id3 = strings.intern("ntdll.dll");    // Different string, different ID

assert_eq!(id1, id2); // Same ID for identical strings

// Retrieve strings by ID
let name = strings.get(id1).unwrap();
println!("Module: {}", name); // "kernel32.dll"
```

###### Callstack Interning
```rust
use one_collect::intern::InternedCallstacks;

// Create a callstack interning container
let mut callstacks = InternedCallstacks::new();

// Store callstack with automatic deduplication
let addresses = vec![0x7FF123456789, 0x7FF987654321, 0x7FF111222333];
let callstack_id = callstacks.intern(addresses.clone());

// Same callstack gets same ID
let duplicate_id = callstacks.intern(addresses);
assert_eq!(callstack_id, duplicate_id);

// Access the stored callstack
if let Some(stack) = callstacks.get(callstack_id) {
    for addr in stack {
        println!("Frame: 0x{:x}", addr);
    }
}
```

## Data Flow Architecture

### Event Processing Pipeline

1. **Event Source**: Platform-specific event collection (perf events, ETW)
2. **Event Registration**: Events registered with format specifications
3. **Data Ingestion**: Raw event data received from OS
4. **Format Parsing**: Data interpreted according to event format
5. **Handler Execution**: Registered closures process event data
6. **Error Handling**: Errors collected and reported
7. **Export Processing**: Processed data routed to export pipeline

### Export Pipeline

1. **Data Aggregation**: Events aggregated into export records
2. **Format Conversion**: Data converted to target format specifications
3. **Interning**: Strings and callstacks deduplicated
4. **Serialization**: Final data serialized to output format
5. **Output Generation**: Files/streams written with exported data

## Key Design Patterns

### Closure-Based Event Handling
Events are processed through closures registered for specific event types:
```rust
event.register(|event_data: &EventData| -> anyhow::Result<()> {
    // Process event data
    Ok(())
});
```

### Trait-Based Extensibility
Core functionality exposed through traits:
- Custom event sources via platform abstraction
- Custom export formats via export traits
- Custom data processors via pipeline traits

### Error Accumulation
Rather than failing fast, the framework:
- Collects errors during processing
- Continues processing when possible
- Reports all errors at completion
- Enables partial success scenarios

### Platform Abstraction

Platform-specific code is isolated behind common interfaces using the OS trait pattern. The framework creates an `OS*` trait for each abstraction layer and implements it for each supported operating system.

**Code Reference**: [`one_collect/src/helpers/exporting/os/`](one_collect/src/helpers/exporting/os/)

#### OS Trait Pattern Example

```rust
// Define the OS abstraction trait
pub trait OSExportMachine {
    fn create_session(&self, settings: &ExportSettings) -> anyhow::Result<Box<dyn OSSession>>;
    fn collect_system_info(&self) -> anyhow::Result<SystemInfo>;
    fn get_process_list(&self) -> anyhow::Result<Vec<ProcessInfo>>;
}

// Linux implementation
#[cfg(target_os = "linux")]
pub struct LinuxExportMachine;

#[cfg(target_os = "linux")]
impl OSExportMachine for LinuxExportMachine {
    fn create_session(&self, settings: &ExportSettings) -> anyhow::Result<Box<dyn OSSession>> {
        // Use perf_events for Linux
        let builder = RingBufSessionBuilder::new();
        // Configure with Linux-specific settings
        Ok(Box::new(builder.build()?))
    }
    
    fn collect_system_info(&self) -> anyhow::Result<SystemInfo> {
        // Read from /proc/cpuinfo, /proc/meminfo, etc.
        SystemInfo::from_procfs()
    }
    
    fn get_process_list(&self) -> anyhow::Result<Vec<ProcessInfo>> {
        // Enumerate /proc/*/stat files
        ProcessInfo::from_procfs()
    }
}

// Windows implementation  
#[cfg(target_os = "windows")]
pub struct WindowsExportMachine;

#[cfg(target_os = "windows")]
impl OSExportMachine for WindowsExportMachine {
    fn create_session(&self, settings: &ExportSettings) -> anyhow::Result<Box<dyn OSSession>> {
        // Use ETW for Windows
        let session = TraceSession::new("one-collect")?;
        // Configure with Windows-specific settings
        Ok(Box::new(session))
    }
    
    fn collect_system_info(&self) -> anyhow::Result<SystemInfo> {
        // Use Windows APIs
        SystemInfo::from_windows_apis()
    }
    
    fn get_process_list(&self) -> anyhow::Result<Vec<ProcessInfo>> {
        // Use Windows Process32First/Next APIs
        ProcessInfo::from_windows_apis()
    }
}

// Cross-platform usage
pub fn create_exporter() -> Box<dyn OSExportMachine> {
    #[cfg(target_os = "linux")]
    return Box::new(LinuxExportMachine);
    
    #[cfg(target_os = "windows")]
    return Box::new(WindowsExportMachine);
}
```

This pattern enables:
- **Conditional Compilation**: Platform features selected at compile time
- **Consistent APIs**: Same interface across platforms  
- **Platform-Specific Optimizations**: Each implementation can use OS-specific optimizations
- **Easy Testing**: Mock implementations for unit testing

## Module Organization

### Core Modules

#### `lib.rs`
- Public API exports
- Platform feature selection
- Common type definitions

#### `event/mod.rs`
- Event system implementation
- Event data processing
- Format management

#### `sharing.rs`
- Shared data containers
- Type-safe access control
- Memory management utilities

#### `intern.rs`
- String and data interning
- Memory deduplication
- Hash-based storage

### Platform Modules

#### `perf_event/` (Linux)
- Linux perf events interface
- Ring buffer management
- Event parsing and processing

#### `etw/` (Windows)
- ETW session management
- Event consumption
- Windows-specific optimizations

#### `procfs.rs` (Linux)
- `/proc` filesystem access
- Process information extraction
- System state queries

#### `tracefs.rs` (Linux)
- Linux trace filesystem support
- Kernel trace point access
- Dynamic tracing support

### Helper Modules

#### `helpers/exporting/`
- Export pipeline implementation
- Format conversion logic
- Output generation

#### `helpers/callstack/`
- Stack unwinding integration
- Symbol resolution
- Callstack processing

#### `helpers/dotnet/`
- .NET runtime integration
- Managed code profiling
- CLR event processing

## Performance Considerations

### Memory Management
- Object pooling for frequently allocated types
- Arena allocation for temporary data
- Reference counting for shared data
- Lazy initialization where appropriate

### Event Processing
- Minimal allocations in hot paths
- Zero-copy data access patterns
- Batch processing for efficiency
- Lock-free data structures where possible

### Platform Optimization
- Platform-specific assembly optimizations
- Vectorized operations where applicable
- Cache-friendly data layouts
- NUMA-aware memory allocation

## Extension Points

### Custom Event Sources
New event sources can be added by:
1. Implementing platform-specific event collection
2. Defining event formats for new data types
3. Integrating with the event pipeline
4. Adding platform feature flags

### Export Formats
New export formats supported via:
1. Implementing export traits
2. Defining format-specific record types
3. Adding serialization logic
4. Integrating with the export pipeline

### Data Processing
Custom processors can be added through:
1. Event handler registration
2. Pipeline composition
3. Custom helper modules
4. Scripting integration

## Testing Strategy

### Unit Tests
- Individual component testing
- Mock implementations for isolation
- Cross-platform compatibility validation

### Integration Tests
- End-to-end pipeline testing
- Platform-specific functionality validation
- Performance regression testing

### Benchmarks
- Event processing throughput
- Memory usage profiling
- Export performance measurement

## Configuration and Deployment

### Feature Flags
- Platform-specific feature selection
- Optional functionality enablement
- Compile-time optimization

### Runtime Configuration
- Export settings customization
- Event filtering options
- Performance tuning parameters

### Dependencies
- Minimal external dependencies
- Platform-specific conditional dependencies
- Optional feature dependencies