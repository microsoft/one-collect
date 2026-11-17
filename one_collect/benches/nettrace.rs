// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use one_collect::event::{EventField, EventFormat, LocationType};
use one_collect::helpers::exporting::formats::nettrace::NetTraceFormat;
use one_collect::helpers::exporting::process::MetricValue;
use one_collect::helpers::exporting::record::ExportRecordType;
use one_collect::helpers::exporting::*;

const SAMPLE_COUNT: u64 = 100_000;

fn record_machine(fields: &[(&str, usize, usize)]) -> ExportMachine {
    let mut machine = ExportMachine::new(ExportSettings::default());
    machine.mark_start();
    let start = machine.start_qpc().unwrap();
    let kind = machine.sample_kind("benchmark/record");
    let mut format = EventFormat::new();
    let mut data = Vec::new();
    for (index, &(type_name, offset, size)) in fields.iter().enumerate() {
        format.add_field(EventField::new(
            format!("field_{index}"), type_name.into(), LocationType::Static, offset, size));
        data.resize(offset + size, 0xA5);
        data[offset..offset + size].fill(index as u8);
    }
    let mut record = ExportRecordType::new(kind, 1, "benchmark/record".into(), format);
    record.set_original_data_flag();
    let record_id = machine.record_type(record);
    for index in 0..SAMPLE_COUNT {
        machine.add_sample_with_record(
            start + index, MetricValue::Count(1), 42, 42, 0, kind, record_id, &data, &[]).unwrap();
    }
    machine.mark_end();
    machine
}

fn benchmark(c: &mut Criterion) {
    let path = std::env::temp_dir().join(format!(
        "one-collect-nettrace-bench-{}.nettrace", std::process::id()));
    let mut group = c.benchmark_group("nettrace_export");
    group.throughput(Throughput::Elements(SAMPLE_COUNT));

    // Export real files because the writer seeks to patch block headers.
    // Record construction is excluded; serialization and buffered file I/O are timed.
    for (name, ret_offset) in [("sys_exit_packed", 12), ("sys_exit_padded", 16)] {
        let mut machine = record_machine(&[
            ("unsigned short", 0, 2),
            ("unsigned char", 2, 1),
            ("unsigned char", 3, 1),
            ("int", 4, 4),
            ("int", 8, 4),
            ("long", ret_offset, 8),
        ]);
        group.bench_function(name, |b| b.iter(|| {
            black_box(&mut machine).to_net_trace(|_| true, path.to_str().unwrap()).unwrap();
        }));
    }

    for (name, stride) in [("wide_packed", 12), ("wide_padded", 16)] {
        let mut fields = Vec::new();
        for index in 0..16 {
            fields.push(("u32", index * stride, 4));
            fields.push(("u64", index * stride + stride - 8, 8));
        }
        let mut machine = record_machine(&fields);
        group.bench_function(name, |b| b.iter(|| {
            black_box(&mut machine).to_net_trace(|_| true, path.to_str().unwrap()).unwrap();
        }));
    }
    group.finish();
    std::fs::remove_file(path).unwrap();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
