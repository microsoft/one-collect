# one_collect - Event Collection Framework Design Document

## Overview

The `one_collect` crate is the core library of the one-collect framework, providing a high-performance, cross-platform solution for collecting, processing, and exporting system events and profiling data. It supports Linux perf events and Windows ETW (Event Tracing for Windows) with a unified, composable pipeline architecture.

## Purpose and Responsibilities

- **Event Collection**: Capture system-wide events from OS-specific sources (perf events on Linux, ETW on Windows)
- **Pipeline Processing**: Route events through configurable processing pipelines with closure-based handlers
- **Data Export**: Transform collected data into various output formats for analysis tools
- **Cross-Platform Abstraction**: Provide consistent APIs across Linux and Windows platforms
- **Universal Services**: The higher-level universal layer handles commonly required services such as rundown, stack capture, and symbol resolution
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
use one_collect::tracefs::TraceFS;
use one_collect::event::*;

// Create a tracepoint event using tracefs for scheduler wakeups
let tracefs = TraceFS::open()?;
let mut event = tracefs.find_event("sched", "sched_waking")?;

// Get field references outside the closure for high performance
let pid_field_ref = event.format().get_field_ref("pid")?;
let comm_field_ref = event.format().get_field_ref("comm")?;

// Register a closure to handle each event
event.add_callback(move |event_data: &EventData| -> anyhow::Result<()> {
    let pid = event_data.format().get_u32(
        pid_field_ref, 
        event_data.event_data()
    )?;
    
    let comm = std::str::from_utf8(
        event_data.format().get_data(
            comm_field_ref,
            event_data.event_data()
        )
    )?;
    
    println!("Process {} ({}) is waking up", comm, pid);
    Ok(())
});

// Configure tracepoint session
let mut session = RingBufSessionBuilder::new()
    .with_tracepoint_events(RingBufBuilder::for_tracepoint())
    .build()?;

session.add_event(event);
session.start()?;
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

// Add fields to the event format
event.format_mut().add_field(EventField::new(
    "ProcessId".to_string(),
    "u32".to_string(),
    LocationType::Static,
    0,
    4
));
event.format_mut().add_field(EventField::new(
    "ImageFileName".to_string(),
    "string".to_string(),
    LocationType::StaticUTF16String,
    20,
    0
));

// Get field references outside the closure for high performance
let process_id_field_ref = event.format().get_field_ref("ProcessId").unwrap();
let image_name_field_ref = event.format().get_field_ref("ImageFileName").unwrap();

// Register event handler
event.add_callback(move |event_data: &EventData| -> anyhow::Result<()> {
    let process_id = event_data.format().get_u32(
        process_id_field_ref,
        event_data.event_data()
    )?;
    
    let image_name_data = event_data.format().get_data(
        image_name_field_ref,
        event_data.event_data()
    );
    let utf16_chars: Vec<u16> = image_name_data.chunks_exact(2)
        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();
    let image_name = String::from_utf16(&utf16_chars)?;
    
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
settings.with_cpu_profiling(Duration::from_millis(1));

// Settings automatically determine required events
// No need to manually specify individual events
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

Here's a complete example from the `perf_export.rs` sample showing how to capture CPU profiling data and export to multiple formats:

```rust
use one_collect::helpers::exporting::*;
use one_collect::helpers::dotnet::*;

let duration = std::time::Duration::from_secs(5);

let settings = ExportSettings::default()
    .with_cpu_profiling(1000)
    .with_cswitches();

let dotnet = UniversalDotNetHelper::default()
    .with_dynamic_symbols();

let universal = UniversalExporter::new(settings)
    .with_dotnet_help(dotnet);

println!("Capturing...");
let exporter = universal.parse_for_duration("perf_export", duration)
    .expect("Check permissions.");

let mut exporter = exporter.borrow_mut();

exporter.capture_and_resolve_symbols();
```

#### Helpers System (`helpers` module)

Helpers are the way to layer non-platform-level functionality on top of platform functionality.

##### Callstack Helper (`helpers::callstack`)
Stack unwinding integration:
- Integrates with `ruwind` library
- Manages unwinding context and state
- Call stack symbolization happens in ExportMachine/Universal

##### .NET Helper (`helpers::dotnet`)
The dotnet helper:
- Enables jitted code symbol capture
- Enables .NET event capture control (enable/disable)

##### Scripting Integration (`helpers::scripting`)

The scripting engine integrates at the universal layer, allowing runtime customization of event capture and data processing. It hooks into the `ExportMachine` before and after all data has been aggregated:

#### Utility Modules

##### Interning (`intern` module)
Memory-efficient string and data management through deduplication:

**Code Reference**: [`one_collect/src/intern.rs`](one_collect/src/intern.rs)

###### String Interning
```rust
use one_collect::intern::InternedStrings;

// Create an interned strings container
let mut strings = InternedStrings::new(32);

// Store strings with deduplication
let id1 = strings.to_id("kernel32.dll");
let id2 = strings.to_id("kernel32.dll"); // Same string, same ID
let id3 = strings.to_id("ntdll.dll");    // Different string, different ID

assert_eq!(id1, id2); // Same ID for identical strings

// Retrieve strings by ID
let name = strings.from_id(id1).unwrap();
println!("Module: {}", name); // "kernel32.dll"
```

###### Callstack Interning
```rust
use one_collect::intern::InternedCallstacks;

// Create an interned callstacks container
let mut callstacks = InternedCallstacks::new(64);

// Store callstacks with deduplication
let frames1 = vec![0x401000, 0x402000, 0x403000];
let frames2 = vec![0x401000, 0x402000, 0x403000]; // Same frames
let frames3 = vec![0x501000, 0x502000];           // Different frames

let id1 = callstacks.to_id(&frames1);
let id2 = callstacks.to_id(&frames2); // Same ID for identical stacks
let id3 = callstacks.to_id(&frames3); // Different ID

assert_eq!(id1, id2); // Same ID for identical callstacks

// Retrieve callstacks by ID
let mut retrieved_frames = Vec::new();
callstacks.from_id(id1, &mut retrieved_frames).unwrap();
println!("Callstack frames: {:?}", retrieved_frames);
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
4. **Symbol Resolution** (optional): Only when necessary based on the pipeline
5. **Serialization**: Final data serialized to output format
6. **Output Generation**: Files/streams written with exported data

## Key Design Patterns

### Closure-Based Event Handling
Events are processed through closures registered for specific event types:
```rust
event.add_callback(|event_data: &EventData| -> anyhow::Result<()> {
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
This example describes the pattern that we use to write platform-neutral code that calls into platform-specific code.  This is not a real example in the codebase.

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
