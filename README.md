# An extremely fast Rust based framework for collecting event and profiling data

This repository contains Rust crates that make collecting, analyzing, and exporting events and profiles easy and efficient.
It is highly composable, which allows you to tweak all aspects of how events and profiles are collected and processed.

The main source of events and profiling on Linux is the perf events facility. Individual events can be hooked and processed
as they arrive, or entire sessions of events and profiling data can be managed for you. Regardless of the source of events
and profiling, the data is sent through a pipeline with closure invocations as data arrives. This allows pre-built scenarios
as well as custom in-proc scenarios to utilize the same pipelines. Data that has been collected can be exported to several
pre-built as well as custom formats.

The pipeline(s) are built from [events](EVENTS.md) that contain the necessary format details to decode the data. When data
is available for that event, any registered closure is run. The base pipelines expose their key events out, so that other
pipelines can be built on-top for when needed events fire. This is how the [exporting](one_collect/src/helpers/exporting)
pipeline is composed.

On X64, the framework supports callstack unwinding using live DWARF decoding. The unwinder also understands anonymous code
sections, such as those from C# and Java. It will unwind through them by scanning for X64 calling conventions. This allows
our framework to unwind not only native ELF files, but also through JIT'd code without the need for per-language support.
Custom unwinders, if required, can be built and utilized using the same pipeline hooks our pre-built DWARF unwinder does.

Our goal is to support others to consume, build, and contribute the latest file formats and technologies in a scalable
and composable way.

## Getting started

If you are simply interested in a common way to consume events and profiling via several different formats without major
tweaks please use the [CLI](cli) tool directly. It can start event and profiling based sessions and save them into several
different formats.

If you are planning to integrate event or profiling data into your agent or process, please look at our [examples](one_collect/examples).
You have a lot of options how you integrate this data, you can custom process data live via event closures. You can also
use the pre-built [exporting](one_collect/src/helpers/exporting) mechanisms, such as the ExportMachine and ExportGraph
to combine processes together, deduplicate the samples, and save into a known format with a few lines of Rust. Your
process chooses if local symbols should be included or not, or if any local symbolic resolution should occur before
the data is saved. The framework supports many options to suite your needs.

## Something is wrong

Bummer, please open an issue and we'll try to look at it quickly. Please include enough details so we can reproduce
the issue without your custom environment. If that is not possible, the more details the better.

## Something is missing

You have a few choices here, the framework is composable enough to allow you to extend it privately. However, it would
be even better if you contribute back. If you have requests and cannot contribute directly, please leave a feature
request by opening an issue.

If you do want to contribute (Thank you!) then please send a pull request with the addition. If the addition is quite
large or changes base pipeline or object functionality, then it might be better to first open an issue so we can discuss
the general direction.

If you want to contribute a file format to the known set (Awesome!) then please do so by adding a new file under [formats](one_collect/src/helpers/exporting/formats).
If the file format works on a per-process (or per-comm name) please add a trait that extends the ExportGraph struct.
The trait method should have the name of the format with to_ before it. For example, if the name was perf_view, you
would add a new trait that has a method name "to_perf_view()". Please see [perf_view](one_collect/src/helpers/exporting/formats/perf_view.rs)
and [pprof](one_collect/src/helpers/exporting/formats/pprof.rs) as examples of this. If the file format works with many processes,
also extend the ExportMachine struct with the same method name. If something isn't clear, feel free to open an issue and ask.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
