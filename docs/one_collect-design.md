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

##### `EventData`
Wrapper around raw event data providing:
- Access to full event payload
- Event-specific data extraction
- Format-aware data interpretation

##### `EventFormat`
Describes the structure and meaning of event data:
- Field definitions and types
- Parsing rules and constraints
- Platform-specific format variations

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

#### Helpers System (`helpers` module)

##### Exporting Pipeline (`helpers::exporting`)
Comprehensive data export framework:
- **ExportMachine**: Central state management for export operations
- **ExportSettings**: Configuration for export behavior
- **Record Types**: Structured data format definitions
- **Universal Exporters**: Cross-platform export implementations
- **Format Plugins**: Extensible output format support

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

#### Platform-Specific Modules

##### Linux Support
- **perf_event**: Linux perf events integration
- **procfs**: `/proc` filesystem access utilities
- **tracefs**: Linux trace filesystem support
- **user_events**: User-defined event support

##### Windows Support
- **etw**: ETW (Event Tracing for Windows) integration
- Windows-specific event processing
- ETW session management

#### Utility Modules

##### Interning (`intern` module)
Memory-efficient string and data management:
- `InternedStrings`: Deduplicated string storage
- `InternedCallstacks`: Efficient callstack representation
- Hash-based deduplication for memory efficiency

##### Scripting (`scripting` module - optional)
Runtime customization support:
- Dynamic event handler creation
- Script-based data processing
- Rhai scripting language integration

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
Platform-specific code isolated behind common interfaces:
- Conditional compilation for platform features
- Consistent APIs across platforms
- Platform-specific optimizations

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