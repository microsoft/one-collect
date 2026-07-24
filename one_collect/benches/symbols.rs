// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use one_collect::helpers::exporting::symbols::{ElfSymbolReader, GoPclnTabSymbolReader};
use one_collect::helpers::exporting::{ExportMachine, ExportMapping, ExportSymbolReader};
use one_collect::intern::InternedStrings;
use one_collect::unwind::{ElfLoadHeader, UnwindType};

#[cfg(target_os = "linux")]
use one_collect::helpers::exporting::process::MetricValue;
#[cfg(target_os = "linux")]
use one_collect::helpers::exporting::{ExportProcessSample, ExportSettings};

const LOAD_VADDR: u64 = 0x400000;
const MAPPING_START: u64 = 0x10000000;
const MAPPING_LEN: u64 = 0x200000;

#[derive(Clone)]
struct Symbol {
    start: u64,
    end: u64,
    name: String,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../test/assets/go")
        .join(name)
}

fn load_header() -> ElfLoadHeader {
    ElfLoadHeader::new(0, LOAD_VADDR)
}

fn collect_symbols(reader: &mut impl ExportSymbolReader) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    reader.reset();
    while reader.next() {
        symbols.push(Symbol {
            start: reader.start(),
            end: reader.end(),
            name: reader.name().to_string(),
        });
    }
    symbols
}

fn elf_symbols(path: &Path, page_size: u64) -> Vec<Symbol> {
    let mut reader = ElfSymbolReader::new(
        File::open(path).expect("open ELF fixture"),
        load_header(),
        page_size,
    );
    collect_symbols(&mut reader)
}

fn go_symbols(path: &Path, page_size: u64) -> Vec<Symbol> {
    let mut reader = GoPclnTabSymbolReader::new(
        File::open(path).expect("open Go fixture"),
        load_header(),
        page_size,
    )
    .expect("parse Go fixture");
    collect_symbols(&mut reader)
}

fn shared_symbols(elf: &[Symbol], go: &[Symbol]) -> Vec<Symbol> {
    let elf_by_name: HashMap<&str, &Symbol> = elf
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol))
        .collect();
    let mut shared: Vec<Symbol> = go
        .iter()
        .filter(|symbol| {
            elf_by_name
                .get(symbol.name.as_str())
                .is_some_and(|elf_symbol| elf_symbol.start == symbol.start)
        })
        .cloned()
        .collect();
    shared.sort_by_key(|symbol| symbol.start);
    shared
}

fn new_mapping() -> ExportMapping {
    ExportMapping::new(
        0,
        0,
        MAPPING_START,
        MAPPING_START + MAPPING_LEN - 1,
        0,
        false,
        0,
        UnwindType::DWARF,
    )
}

fn sampled_ips(shared: &[Symbol]) -> Vec<u64> {
    shared
        .iter()
        .map(|symbol| MAPPING_START + symbol.start)
        .collect()
}

fn benchmark_readers(
    c: &mut Criterion,
    elf_path: &Path,
    go_path: &Path,
    page_size: u64,
    elf_count: usize,
    go_count: usize,
) {
    let mut setup = c.benchmark_group("symbol_readers/setup");
    setup.sample_size(20);

    setup.bench_function("elf", |b| {
        b.iter_batched(
            || File::open(elf_path).expect("open ELF fixture"),
            |file| {
                let mut reader = ElfSymbolReader::new(file, load_header(), page_size);
                reader.reset();
                black_box(reader);
            },
            BatchSize::SmallInput,
        )
    });

    setup.bench_function("go_pclntab", |b| {
        b.iter_batched(
            || File::open(go_path).expect("open Go fixture"),
            |file| {
                let mut reader = GoPclnTabSymbolReader::new(file, load_header(), page_size)
                    .expect("parse Go fixture");
                reader.reset();
                black_box(reader);
            },
            BatchSize::SmallInput,
        )
    });
    setup.finish();

    // This includes each reader's real initialization path as well as iteration.
    // The setup group above isolates initialization so its contribution remains visible.
    let mut scan = c.benchmark_group("symbol_readers/full_lifecycle");
    scan.sample_size(20);

    scan.throughput(Throughput::Elements(elf_count as u64));
    scan.bench_function(BenchmarkId::new("elf", elf_count), |b| {
        b.iter_batched(
            || File::open(elf_path).expect("open ELF fixture"),
            |file| {
                let mut reader = ElfSymbolReader::new(file, load_header(), page_size);
                reader.reset();
                while reader.next() {
                    black_box((reader.start(), reader.end(), reader.name()));
                }
            },
            BatchSize::SmallInput,
        )
    });

    scan.throughput(Throughput::Elements(go_count as u64));
    scan.bench_function(BenchmarkId::new("go_pclntab", go_count), |b| {
        b.iter_batched(
            || File::open(go_path).expect("open Go fixture"),
            |file| {
                let mut reader = GoPclnTabSymbolReader::new(file, load_header(), page_size)
                    .expect("parse Go fixture");
                reader.reset();
                while reader.next() {
                    black_box((reader.start(), reader.end(), reader.name()));
                }
            },
            BatchSize::SmallInput,
        )
    });
    scan.finish();
}

fn benchmark_mapping_resolution(
    c: &mut Criterion,
    elf_path: &Path,
    go_path: &Path,
    page_size: u64,
    ips: &[u64],
) {
    let mut group = c.benchmark_group("symbol_resolution/mapping");
    group.sample_size(20);
    group.throughput(Throughput::Elements(ips.len() as u64));

    group.bench_function("elf", |b| {
        b.iter_batched(
            || {
                (
                    File::open(elf_path).expect("open ELF fixture"),
                    new_mapping(),
                    InternedStrings::new(2048),
                    ips.to_vec(),
                )
            },
            |(file, mut mapping, mut strings, mut sampled_ips)| {
                let mut reader = ElfSymbolReader::new(file, load_header(), page_size);
                mapping.add_matching_symbols(&mut sampled_ips, &mut reader, &mut strings);
                black_box(mapping);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("go_pclntab", |b| {
        b.iter_batched(
            || {
                (
                    File::open(go_path).expect("open Go fixture"),
                    new_mapping(),
                    InternedStrings::new(2048),
                    ips.to_vec(),
                )
            },
            |(file, mut mapping, mut strings, mut sampled_ips)| {
                let mut reader = GoPclnTabSymbolReader::new(file, load_header(), page_size)
                    .expect("parse Go fixture");
                mapping.add_matching_symbols(&mut sampled_ips, &mut reader, &mut strings);
                black_box(mapping);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("elf_plus_go_union", |b| {
        b.iter_batched(
            || {
                (
                    File::open(elf_path).expect("open ELF fixture"),
                    new_mapping(),
                    InternedStrings::new(2048),
                    ips.to_vec(),
                )
            },
            |(file, mut mapping, mut strings, mut sampled_ips)| {
                let go_file = file.try_clone().expect("clone fixture");
                let mut elf_reader = ElfSymbolReader::new(file, load_header(), page_size);
                mapping.add_matching_symbols(&mut sampled_ips, &mut elf_reader, &mut strings);

                let mut go_reader = GoPclnTabSymbolReader::new(go_file, load_header(), page_size)
                    .expect("parse Go fixture");
                mapping.add_matching_symbols(&mut sampled_ips, &mut go_reader, &mut strings);
                black_box(mapping);
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

#[cfg(target_os = "linux")]
fn build_machine(path: &Path, symbol_vas: &[u64]) -> ExportMachine {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).expect("read fixture metadata");
    let pid = std::process::id();
    let mut machine = ExportMachine::new(ExportSettings::default());
    machine
        .add_comm_exec(pid, "symbol-benchmark", 0)
        .expect("add benchmark process");
    machine
        .add_mmap_exec(
            0,
            pid,
            LOAD_VADDR,
            MAPPING_LEN,
            0,
            libc::major(metadata.dev()) as u32,
            libc::minor(metadata.dev()) as u32,
            metadata.ino(),
            path.to_str().expect("UTF-8 fixture path"),
        )
        .expect("add fixture mapping");

    for (index, ip) in symbol_vas.iter().enumerate() {
        machine
            .add_process_sample(
                pid,
                ExportProcessSample::new(index as u64, MetricValue::Count(1), 0, 0, pid, *ip, 0),
            )
            .expect("add fixture sample");
    }
    machine
}

#[cfg(target_os = "linux")]
fn resolved_symbol_count(machine: &ExportMachine, ip: u64) -> usize {
    machine
        .find_process(std::process::id())
        .and_then(|process| process.find_mapping(ip, None))
        .map_or(0, |mapping| mapping.symbols().len())
}

#[cfg(target_os = "linux")]
fn benchmark_export_machine(
    c: &mut Criterion,
    elf_path: &Path,
    go_path: &Path,
    symbol_vas: &[u64],
) {
    for path in [elf_path, go_path] {
        let mut machine = build_machine(path, symbol_vas);
        machine.capture_file_symbol_metadata();
        machine.resolve_local_file_symbols();
        assert_eq!(
            resolved_symbol_count(&machine, symbol_vas[0]),
            symbol_vas.len()
        );
    }

    let mut group = c.benchmark_group("symbol_resolution/export_machine");
    group.sample_size(10);
    group.throughput(Throughput::Elements(symbol_vas.len() as u64));

    group.bench_function("unstripped_elf_plus_go", |b| {
        b.iter_batched(
            || build_machine(elf_path, symbol_vas),
            |mut machine| {
                machine.capture_file_symbol_metadata();
                machine.resolve_local_file_symbols();
                black_box(machine);
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("stripped_go", |b| {
        b.iter_batched(
            || build_machine(go_path, symbol_vas),
            |mut machine| {
                machine.capture_file_symbol_metadata();
                machine.resolve_local_file_symbols();
                black_box(machine);
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let elf_path = fixture("symbol_benchmark_elf");
    let go_path = fixture("symbol_benchmark_go");
    let page_size = ExportMachine::system_page_size();
    let elf = elf_symbols(&elf_path, page_size);
    let go = go_symbols(&go_path, page_size);
    let shared = shared_symbols(&elf, &go);

    assert!(elf.len() >= 1000, "expected at least 1000 ELF symbols");
    assert!(go.len() >= 1000, "expected at least 1000 Go symbols");
    assert!(
        shared.len() >= 1000,
        "expected at least 1000 shared symbols"
    );
    assert!(
        shared
            .iter()
            .any(|symbol| { symbol.name == "main.benchmarkTarget" && symbol.end >= symbol.start }),
        "benchmark target should be present"
    );

    let ips = sampled_ips(&shared);
    benchmark_readers(c, &elf_path, &go_path, page_size, elf.len(), go.len());
    benchmark_mapping_resolution(c, &elf_path, &go_path, page_size, &ips);

    #[cfg(target_os = "linux")]
    {
        let symbol_vas: Vec<u64> = shared
            .iter()
            .map(|symbol| LOAD_VADDR + symbol.start)
            .collect();
        benchmark_export_machine(c, &elf_path, &go_path, &symbol_vas);
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
