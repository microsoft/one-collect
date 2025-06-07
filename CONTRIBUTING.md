# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Development Setup

### Prerequisites

To build and test this repository, you need:

- [Rust](https://rustup.rs/) (latest stable version recommended)
- A Linux or Windows development environment
- On Linux: Development packages for your distribution (typically build-essential on Ubuntu/Debian)

### Building the Project

This repository contains multiple Rust crates:

- `one_collect/` - Main library for event and profiling data collection
- `record-trace/` - Command-line tool built on top of one_collect
- `ruwind/` - Unwinding library for callstack analysis

To build the main library:

```bash
cd one_collect
cargo build
```

To build the command-line tool:

```bash
cd record-trace
cargo build
```

To build the unwinding library:

```bash
cd ruwind
cargo build
```

### Running Tests

To run tests for the main library:

```bash
cd one_collect
cargo test
```

To run tests for the command-line tool:

```bash
cd record-trace
cargo test
```

To run tests for the unwinding library:

```bash
cd ruwind
cargo test
```

Note: Some tests may be ignored on certain platforms or require specific permissions (especially tests that interact with perf events on Linux). These tests can be run locally with appropriate permissions (e.g. sudo).

### Platform-Specific Notes

#### Linux Development

On Linux, this framework primarily uses the perf events facility. When running one-collect to capture traces and resolve symbols, some functionality may require:

- Root privileges for certain perf events
- Kernel headers installed
- Debug symbols for better stack unwinding

#### Windows Development

On Windows, this framework uses ETW (Event Tracing for Windows). Running one-collect will require elevated privileges on Windows.

### Contributing Code

#### Adding New File Formats

If you want to contribute a new export file format:

1. Add a new file under `one_collect/src/helpers/exporting/formats/`
2. If the format works per-process, add a trait extending `ExportGraph` with a method named `to_<format_name>()`
3. If the format works with many processes, also extend `ExportMachine` with the same method name
4. See `perf_view.rs` and `pprof.rs` as examples

#### Pull Request Guidelines

- Ensure your code builds on both Linux and Windows when applicable
- Run tests before submitting your PR
- For large changes, consider opening an issue first to discuss the approach
- Include tests for new functionality
- Follow existing code style and conventions

#### Reporting Issues

When reporting bugs or issues:

- Include enough details to reproduce the issue
- Specify your operating system
- Include relevant error messages or logs
- If possible, provide a minimal reproduction case

### Architecture Overview

This framework is highly composable and built around event pipelines:

- Events contain format details for decoding data
- When data arrives, registered closures are executed
- Base pipelines expose key events for building additional functionality
- The exporting pipeline is built on top of these base events

The framework supports callstack unwinding using live DWARF decoding on x64 Linux, with support for anonymous code sections from JIT compilers like C# and Java. On Windows, the framework uses the built-in Windows unwind functions for x64.