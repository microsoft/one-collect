static EMPTY: &[u8] = &[];

type BoxedCallback = Box<dyn FnMut(&EventFormat, &[u8])>;

pub enum FieldType {
    Static,
    RelativeLocation,
}

pub struct EventField {
    pub name: String,
    pub ftype: FieldType,
    pub offset: usize,
    pub size: usize,
}

impl EventField {
    pub fn new(
        name: String,
        ftype: FieldType,
        offset: usize,
        size: usize) -> Self {
        Self {
            name,
            ftype,
            offset,
            size,
        }
    }
}

pub struct EventFormat {
    fields: Vec<EventField>,
}

impl Default for EventFormat {
    fn default() -> Self {
        EventFormat::new()
    }
}

impl EventFormat {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
        }
    }

    pub fn add_field(
        &mut self,
        field: EventField) {
        self.fields.push(field);
    }

    pub fn get_field_ref(
        &self,
        name: &str) -> Option<usize> {
        for (i, field) in self.fields.iter().enumerate() {
            if field.name == name {
                return Some(i);
            }
        }

        None
    }

    pub fn get_data<'a>(
            &self,
            field_ref: usize,
            data: &'a [u8]) -> &'a [u8] {
        if field_ref >= self.fields.len() {
            return EMPTY;
        }

        let field = &self.fields[field_ref];

        match &field.ftype {
            FieldType::Static => {
                let end = field.offset + field.size;

                if end > data.len() {
                    return EMPTY;
                }

                &data[field.offset .. end]
            },

            FieldType::RelativeLocation => {
                todo!("Need to support relative location");
            }
        }
    }
}

pub struct Event {
    id: usize,
    name: String,
    callback: Option<BoxedCallback>,
    format: EventFormat,
}

impl Event {
    pub fn new(
        id: usize,
        name: String) -> Self {
        Self {
            id,
            name,
            callback: None,
            format: EventFormat::new(),
        }
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn format_mut(&mut self) -> &mut EventFormat {
        &mut self.format
    }

    pub fn format(&self) -> &EventFormat {
        &self.format
    }

    pub fn set_callback(
        &mut self,
        callback: impl FnMut(&EventFormat, &[u8]) + 'static) {
        self.callback = Some(Box::new(callback));
    }

    pub fn process(
        &mut self,
        data: &[u8]) {
        if let Some(callback) = &mut self.callback {
            (callback)(&self.format, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn create_abc() -> Event {
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(EventField::new("1".into(), FieldType::Static, 0, 1));
        format.add_field(EventField::new("2".into(), FieldType::Static, 1, 1));
        format.add_field(EventField::new("3".into(), FieldType::Static, 2, 1));

        e
    }

    fn setup_abc(e: &mut Event, count: Arc<AtomicUsize>) {
        let format = e.format();

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

            count.fetch_add(1, Ordering::Relaxed);
        });
    }

    #[test]
    fn it_works() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut e = create_abc();
        setup_abc(&mut e, Arc::clone(&count));

        let mut data: Vec<u8> = Vec::new();
        data.push(1u8);
        data.push(2u8);
        data.push(3u8);

        let slice = data.as_slice();

        assert_eq!(count.load(Ordering::Relaxed), 0);
        e.process(slice);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        e.process(slice);
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }
}
