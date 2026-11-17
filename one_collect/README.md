# one_collect

An extremely fast, composable Rust framework for collecting event and profiling
data on Linux and Windows.

`one_collect` makes collecting, analyzing, and exporting events and profiles easy
and efficient. It is highly composable, allowing you to tweak all aspects of how
events and profiles are collected and processed.

- On **Linux**, the main source of events and profiling is the perf events
  facility.
- On **Windows**, the main source of events is the ETW facility.

Individual events can be hooked and processed as they arrive, or entire sessions
of events and profiling data can be managed for you. Regardless of the source,
data flows through a pipeline that invokes closures as it arrives. This allows
both pre-built scenarios and custom in-process scenarios to use the same
pipelines. Collected data can be exported to several pre-built or custom formats.

## Stack unwinding

On x64 Linux, the framework supports callstack unwinding using live DWARF
decoding. The unwinder also understands anonymous code sections, such as those
from C# and Java, and will unwind through them by scanning for x64 calling
conventions. This allows unwinding not only native ELF files, but also JIT'd code
without per-language support. The unwinding implementation lives in the internal
`ruwind` module; the types it surfaces in the public API are re-exported from
the `one_collect::unwind` module.

## Pre-release software

This project is currently in pre-release mode. It is expected that there may be
breaking API and behavioral changes. We expect this to stabilize before a
version 1.0 release.

## Features

- `scripting` *(default)* — enables the Rhai-based scripting support.

## License

Licensed under the [MIT](https://github.com/microsoft/one-collect/blob/main/LICENSE)
license.

## Contributing

See the repository's
[CONTRIBUTING](https://github.com/microsoft/one-collect/blob/main/CONTRIBUTING.md)
guide. This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
