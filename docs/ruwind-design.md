# ruwind - Stack Unwinding Library Design Document

## Overview

The `ruwind` crate is a specialized stack unwinding library designed for x64 Linux systems that provides DWARF-based call stack unwinding with support for anonymous code sections (such as JIT-compiled code from languages like C# and Java).

## Purpose and Responsibilities

- **Stack Unwinding**: Traverse call stacks to reconstruct execution context
- **DWARF Support**: Parse and interpret DWARF debugging information for native binaries
- **Anonymous Code Handling**: Unwind through JIT-compiled code sections using x64 calling convention scanning
- **Module Management**: Track and manage loaded modules (shared libraries, executables)
- **Cross-Language Support**: Enable profiling across native and managed code boundaries

## Architecture Overview

### Core Traits

The library is built around several key traits that define the unwinding interface:

#### `Unwindable`
```rust
pub trait Unwindable {
    fn find<'a>(&'a self, ip: u64) -> Option<&'a dyn CodeSection>;
}
```
Represents a collection of code sections that can be searched by instruction pointer.

#### `CodeSection`
```rust
pub trait CodeSection {
    fn anon(&self) -> bool;
    fn unwind_type(&self) -> UnwindType;
    fn rva(&self, ip: u64) -> u64;
    fn key(&self) -> ModuleKey;
}
```
Represents a loadable code section with unwinding metadata.

#### `MachineUnwinder`
```rust
pub trait MachineUnwinder {
    fn reset(&mut self, rip: u64, rbp: u64, rsp: u64);
    fn unwind(&mut self, process: &dyn Unwindable, accessor: &dyn ModuleAccessor, 
              stack_data: &[u8], stack_frames: &mut Vec<u64>, result: &mut UnwindResult);
}
```
The core unwinding algorithm interface.

#### `ModuleAccessor`
```rust
pub trait ModuleAccessor {
    fn open(&self, key: &ModuleKey) -> Option<File>;
}
```
Provides access to module files for reading debug information.

### Key Data Structures

#### `Module`
Represents a loaded module (executable or shared library) with:
- Memory address range (`start`, `end`)
- File offset mapping (`offset`)
- Unique identifier (`ModuleKey` with device/inode)
- Unwinding type (DWARF or Prolog scanning)
- Anonymous flag for JIT code

#### `Process`
Container for all modules within a process address space:
- Vector of modules sorted by start address
- Efficient binary search for IP-to-module resolution

#### `Machine`
Top-level container managing multiple processes:
- HashMap of processes indexed by PID
- Cross-process unwinding support

#### `UnwindResult`
Captures unwinding operation results:
- Number of frames successfully unwound
- Error conditions and diagnostics

### Unwinding Strategies

The library supports two primary unwinding strategies:

#### 1. DWARF Unwinding (`UnwindType::DWARF`)
- Parses `.eh_frame` and `.debug_frame` sections
- Follows DWARF CFI (Call Frame Information) rules
- Handles complex prologue/epilogue scenarios
- Most accurate for native code with debug information

#### 2. Prolog Scanning (`UnwindType::Prolog`)
- Scans stack memory for x64 calling convention patterns
- Used for anonymous/JIT code sections
- Fallback when DWARF information is unavailable
- Less accurate but enables cross-language unwinding

## Module Organization

### `lib.rs`
- Public API definitions
- Core trait declarations
- Type aliases and common structures

### `module.rs`
- `Module` and `ModuleKey` implementations
- Address range management
- Module comparison and sorting logic

### `process.rs`
- `Process` implementation
- Module collection management
- Binary search optimization for IP lookup

### `machine.rs`
- `Machine` implementation
- Multi-process unwinding coordination
- Process lifecycle management

### `dwarf.rs`
- DWARF parsing and interpretation
- CFI (Call Frame Information) processing
- Register rule evaluation
- Frame unwinding state machine

### `elf.rs`
- ELF file format parsing
- Section header processing
- Symbol table access
- Debug information extraction

### `x64unwinder.rs`
- x64-specific unwinding implementation
- Register context management
- Stack scanning algorithms
- Integration between DWARF and prolog strategies

## Design Patterns and Principles

### Trait-Based Architecture
The library uses traits extensively to enable:
- **Modularity**: Different unwinding strategies can be plugged in
- **Testability**: Mock implementations for unit testing
- **Extensibility**: New unwinding algorithms can be added

### Zero-Copy Design
- Minimal data copying during unwinding operations
- References and slices used extensively
- Memory-efficient for high-frequency profiling

### Lazy Loading
- Module debug information loaded on-demand
- File handles managed through `ModuleAccessor` trait
- Memory usage scales with active unwinding, not total modules

### Error Resilience
- Graceful degradation when debug information is missing
- Fallback strategies for corrupted or incomplete data
- Partial unwinding results rather than complete failure

## Platform Considerations

### Linux-Specific Features
- ELF binary format parsing
- `/proc/maps` integration for module discovery
- Linux calling conventions and ABI compliance

### x64 Architecture
- 64-bit address space handling
- x64 register set and calling conventions
- Stack layout assumptions for prolog scanning

## Integration Points

### With one_collect
- Provides unwinding services for profiling pipelines
- Integrates with Linux perf event processing
- Supports real-time unwinding during trace collection

### File System Integration
- Reads ELF binaries and debug symbols
- Handles missing or moved files gracefully
- Supports debug symbol search paths

## Performance Considerations

### Caching Strategy
- Module information cached after first access
- DWARF parsing results retained in memory
- Binary search optimization for module lookup

### Memory Management
- Minimal allocations during unwinding
- Reusable data structures to avoid GC pressure
- Stack frame vector reuse across unwind operations

### Algorithmic Complexity
- O(log n) module lookup via binary search
- Linear stack scanning with early termination
- Bounded unwinding depth to prevent infinite loops

## Extension Points

### Custom Unwinding Strategies
New unwinding algorithms can be added by:
1. Implementing `MachineUnwinder` trait
2. Defining appropriate `UnwindType` variants
3. Integrating with module detection logic

### Debug Information Formats
Support for additional debug formats via:
1. New section parsers in ELF processing
2. Extended CFI rule interpretation
3. Format-specific unwinding state machines

### Architecture Support
Porting to new architectures requires:
1. Architecture-specific register definitions
2. Calling convention adaptations
3. Stack layout modifications

## Testing Strategy

### Unit Tests
- Mock implementations of core traits
- Isolated testing of unwinding algorithms
- DWARF parsing validation

### Integration Tests
- Real binary unwinding scenarios
- Cross-language unwinding validation
- Performance regression testing

### Test Assets
- Sample binaries with known call stacks
- DWARF information test cases
- Anonymous code section examples