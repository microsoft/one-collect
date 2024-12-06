use criterion::{criterion_group, criterion_main, Criterion};
use one_collect::helpers::exporting::*;
use crate::mappings::ExportMappingLookup;

fn new_map(
    time: u64,
    start: u64,
    end: u64,
    id: usize) -> ExportMapping {
    ExportMapping::new(time, 0, start, end, 0, false, id, ruwind::UnwindType::DWARF)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut lookup = ExportMappingLookup::default();

    for i in 0..16 {
        let start = i * 1024;
        let end = start + 1023;

        lookup.mappings_mut().push(new_map(0, start, end, i as usize));
    }

    lookup.set_lookup_min_size(usize::MAX);

    c.bench_function("small (linear)", |b| b.iter(|| {
        lookup.find(0, None).unwrap();
    }));

    lookup.set_lookup_min_size(0);

    c.bench_function("small (logarithmic)", |b| b.iter(|| {
        lookup.find(0, None).unwrap();
    }));

    lookup.mappings_mut().clear();

    for i in 0..128 {
        let start = i * 1024;
        let end = start + 1023;

        lookup.mappings_mut().push(new_map(0, start, end, i as usize));
    }

    lookup.set_lookup_min_size(usize::MAX);

    c.bench_function("large (linear)", |b| b.iter(|| {
        lookup.find(0, None).unwrap();
    }));

    lookup.set_lookup_min_size(0);

    c.bench_function("large (logarithmic)", |b| b.iter(|| {
        lookup.find(0, None).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
