use criterion::{criterion_group, criterion_main, Criterion};
use one_collect::intern::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut strings = InternedStrings::new(8);

    strings.to_id("Test");

    c.bench_function("string: All Hits", |b| b.iter(|| {
        strings.to_id("Test");
    }));

    let mut lookup: Vec<String> = Vec::new();

    for i in 0..1024 {
        lookup.push(format!("Test {}", i));
    }

    let mut strings = InternedStrings::new(32);
    let mut i: usize = 0;

    c.bench_function("string: All New (1024)", |b| b.iter(|| {
        strings.to_id(&lookup[i]);
        i += 1;

        /* Reset */
        if i >= 1024 {
            strings = InternedStrings::new(256);
            i = 0;
        }
    }));

    let mut stacks = InternedCallstacks::new(8);
    let frames = &[0, 1, 2, 3, 4];

    stacks.to_id(frames);

    c.bench_function("callstacks: All Hits", |b| b.iter(|| {
        stacks.to_id(frames);
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
