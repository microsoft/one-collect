// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use criterion::{criterion_group, criterion_main, Criterion};
use one_collect::helpers::exporting::*;
use one_collect::helpers::exporting::process::MetricValue;

const NUM_KALLSYMS_SYMBOLS: usize = 200_000;
const NUM_PROCESSES: u32 = 100;
const KERNEL_IPS_PER_PROCESS: usize = 500;

struct MockKallsymsReader {
    symbols: Vec<(u64, u64, String)>,
    current_idx: usize,
}

impl MockKallsymsReader {
    fn new(count: usize) -> Self {
        let mut symbols = Vec::with_capacity(count);
        for i in 0..count {
            let start = KERNEL_START + (i as u64) * 64;
            let end = start + 63;
            symbols.push((start, end, format!("kernel_func_{}", i)));
        }
        Self {
            symbols,
            current_idx: 0,
        }
    }
}

impl ExportSymbolReader for MockKallsymsReader {
    fn reset(&mut self) {
        self.current_idx = 0;
    }

    fn next(&mut self) -> bool {
        if self.current_idx < self.symbols.len() {
            self.current_idx += 1;
            true
        } else {
            false
        }
    }

    fn start(&self) -> u64 {
        if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
            self.symbols[self.current_idx - 1].0
        } else {
            0
        }
    }

    fn end(&self) -> u64 {
        if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
            self.symbols[self.current_idx - 1].1
        } else {
            0
        }
    }

    fn name(&self) -> &str {
        if self.current_idx > 0 && self.current_idx <= self.symbols.len() {
            &self.symbols[self.current_idx - 1].2
        } else {
            ""
        }
    }

    fn demangle(&mut self) -> Option<String> {
        None
    }
}

fn build_machine() -> ExportMachine {
    let mut machine = ExportMachine::new(ExportSettings::default());

    // Add processes with kernel IP samples. Each process gets a set of IPs
    // spread across the kallsyms symbol range, with overlap between processes.
    for pid in 0..NUM_PROCESSES {
        for i in 0..KERNEL_IPS_PER_PROCESS {
            // Spread IPs across the symbol range with some per-process offset
            // so processes share some symbols but not all.
            let symbol_idx = ((pid as usize * 37 + i * 397) % NUM_KALLSYMS_SYMBOLS) as u64;
            let ip = KERNEL_START + symbol_idx * 64 + 16;

            let sample = ExportProcessSample::new(
                i as u64,
                MetricValue::Count(1),
                0,
                0,
                pid,
                ip,
                0,
            );

            machine.add_process_sample(pid, sample).unwrap();
        }
    }

    machine
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("kallsyms");

    // Use fewer iterations since each run is expensive.
    group.sample_size(10);

    group.bench_function(
        &format!("resolve {}p x {}sym", NUM_PROCESSES, NUM_KALLSYMS_SYMBOLS),
        |b| {
            b.iter_with_setup(
                || {
                    let machine = build_machine();
                    let reader = MockKallsymsReader::new(NUM_KALLSYMS_SYMBOLS);
                    (machine, reader)
                },
                |(mut machine, mut reader)| {
                    machine.add_kernel_mappings_with(&mut reader);
                },
            )
        },
    );

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
