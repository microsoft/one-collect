use criterion::{criterion_group, criterion_main, Criterion};
use one_collect::event::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut e = Event::new(1, "test".into());
    let format = e.format_mut();

    format.add_field(EventField::new("1".into(), FieldType::Static, 0, 1));
    format.add_field(EventField::new("2".into(), FieldType::Static, 1, 1));
    format.add_field(EventField::new("3".into(), FieldType::Static, 2, 1));

    let first = format.get_field_ref("1").unwrap();
    let second = format.get_field_ref("2").unwrap();
    let third = format.get_field_ref("3").unwrap();

    e.set_callback(move |format, data| {
        let a = format.get_data(first, data);
        let b = format.get_data(second, data);
        let c = format.get_data(third, data);

        assert!(a[0] == 1u8);
        assert!(b[0] == 2u8);
        assert!(c[0] == 3u8);
    });

    let mut data: Vec<u8> = Vec::new();
    data.push(1u8);
    data.push(2u8);
    data.push(3u8);

    let slice = data.as_slice();

    c.bench_function("min_parse", |b| b.iter(|| e.process(slice)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
