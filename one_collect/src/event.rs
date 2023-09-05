use std::cell::Cell;
use std::rc::Rc;

static EMPTY: &[u8] = &[];

type BoxedCallback = Box<dyn FnMut(&[u8], &EventFormat, &[u8])>;

#[derive(Clone)]
pub struct DataFieldRef(Rc<Cell<DataField>>);

impl DataFieldRef {
    pub fn new() -> Self {
        DataFieldRef(Rc::new(Cell::new(DataField::default())))
    }

    pub fn get(&self) -> DataField {
        (*self.0).get()
    }

    pub fn get_data<'a>(
        &self,
        data: &'a [u8]) -> &'a [u8] {
        /* Get a copy of the field at this point in time */
        let field = self.get();

        /* Use it to slice the data */
        &data[field.start() .. field.end()]
    }

    pub fn try_get_u64(
        &self,
        data: &[u8]) -> Option<u64> {
        let slice = self.get_data(data);

        if slice.len() < 8 { return None; }

        match slice[0..8].try_into() {
            Ok(slice) => Some(u64::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }

    pub fn try_get_u32(
        &self,
        data: &[u8]) -> Option<u32> {
        let slice = self.get_data(data);

        if slice.len() < 4 { return None; }

        match slice[0..4].try_into() {
            Ok(slice) => Some(u32::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }

    pub fn try_get_u16(
        &self,
        data: &[u8]) -> Option<u16> {
        let slice = self.get_data(data);

        if slice.len() < 2 { return None; }

        match slice[0..2].try_into() {
            Ok(slice) => Some(u16::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }

    pub fn reset(&self) {
        self.update(0, 0);
    }

    pub fn update(
        &self,
        start: usize,
        len: usize) -> usize {
        let end = start + len;
        /* New copy of data for consumers to use */
        self.0.set(DataField::new(start as u32, end as u32));
        len
    }
}

impl Default for DataFieldRef {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
#[derive(Copy)]
#[derive(Default)]
pub struct DataField(u32, u32);

impl DataField {
    fn new(
        start: u32,
        end: u32) -> Self {
        Self(start, end)
    }

    fn start(&self) -> usize {
        self.0 as usize
    }

    fn end(&self) -> usize {
        self.1 as usize
    }
}

#[derive(Clone)]
#[derive(Copy)]
pub struct EventFieldRef(usize);

impl From<EventFieldRef> for usize {
    fn from(val: EventFieldRef) -> Self {
        val.0
    }
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum LocationType {
    Static,
    StaticString,
    DynRelative,
    DynAbsolute,
}

pub struct EventField {
    pub name: String,
    pub type_name: String,
    pub location: LocationType,
    pub offset: usize,
    pub size: usize,
}

impl EventField {
    pub fn new(
        name: String,
        type_name: String,
        location: LocationType,
        offset: usize,
        size: usize) -> Self {
        Self {
            name,
            type_name,
            location,
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

    pub fn fields(&self) -> &[EventField] {
        &self.fields
    }

    pub fn get_field_ref_unchecked(
        &self,
        name: &str) -> EventFieldRef {
        self.get_field_ref(name).unwrap()
    }

    pub fn get_field_ref(
        &self,
        name: &str) -> Option<EventFieldRef> {
        for (i, field) in self.fields.iter().enumerate() {
            if field.name == name {
                return Some(EventFieldRef(i));
            }
        }

        None
    }

    pub fn get_data<'a>(
            &self,
            field_ref: EventFieldRef,
            data: &'a [u8]) -> &'a [u8] {
        let index: usize = field_ref.into();

        if index >= self.fields.len() {
            return EMPTY;
        }

        let field = &self.fields[index];

        match &field.location {
            LocationType::Static => {
                let end = field.offset + field.size;

                if end > data.len() {
                    return EMPTY;
                }

                &data[field.offset .. end]
            },

            LocationType::StaticString => {
                let slice = &data[field.offset..];
                let mut len = 0usize;
                
                for b in slice {
                    if *b == 0 {
                        break;
                    }

                    len += 1;
                }

                &slice[0..len]
            },

            LocationType::DynRelative => {
                todo!("Need to support relative location");
            },

            LocationType::DynAbsolute => {
                todo!("Need to support absolute location");
            }
        }
    }

    pub fn try_get_u64(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Option<u64> {
        let slice = self.get_data(field_ref, data);

        if slice.len() < 8 { return None; }

        match slice[0..8].try_into() {
            Ok(slice) => Some(u64::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }

    pub fn try_get_u32(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Option<u32> {
        let slice = self.get_data(field_ref, data);

        if slice.len() < 4 { return None; }

        match slice[0..4].try_into() {
            Ok(slice) => Some(u32::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }

    pub fn try_get_u16(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Option<u16> {
        let slice = self.get_data(field_ref, data);

        if slice.len() < 2 { return None; }

        match slice[0..2].try_into() {
            Ok(slice) => Some(u16::from_ne_bytes(slice)),
            Err(_) => None,
        }
    }
}

pub struct Event {
    id: usize,
    name: String,
    callbacks: Vec<BoxedCallback>,
    format: EventFormat,
}

impl Event {
    pub fn new(
        id: usize,
        name: String) -> Self {
        Self {
            id,
            name,
            callbacks: Vec::new(),
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

    pub fn add_callback(
        &mut self,
        callback: impl FnMut(&[u8], &EventFormat, &[u8]) + 'static) {
        self.callbacks.push(Box::new(callback));
    }

    pub fn process(
        &mut self,
        full_data: &[u8],
        event_data: &[u8]) {
        for callback in &mut self.callbacks {
            (callback)(full_data, &self.format, event_data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn create_abc() -> Event {
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));
        format.add_field(
            EventField::new(
                "2".into(), "unsigned char".into(),
                LocationType::Static, 1, 1));
        format.add_field(
            EventField::new(
                "3".into(), "unsigned char".into(),
                LocationType::Static, 2, 1));

        e
    }

    fn setup_abc(e: &mut Event, count: Arc<AtomicUsize>) {
        let format = e.format();

        let first = format.get_field_ref("1").unwrap();
        let second = format.get_field_ref("2").unwrap();
        let third = format.get_field_ref("3").unwrap();

        e.add_callback(move |_full_data, format, event_data| {
            let a = format.get_data(first, event_data);
            let b = format.get_data(second, event_data);
            let c = format.get_data(third, event_data);

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
        e.process(slice, slice);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        e.process(slice, slice);
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn data_refs() {
        let field = DataFieldRef::new();
        let field2 = field.clone();
        let field3 = field2.clone();

        field.update(0, 1);

        let test = field.get();
        assert_eq!(0, test.start());
        assert_eq!(1, test.end());

        let test = field2.get();
        assert_eq!(0, test.start());
        assert_eq!(1, test.end());

        let test = field3.get();
        assert_eq!(0, test.start());
        assert_eq!(1, test.end());
    }

    #[test]
    fn shared_data() {
        /* Writable view */
        let owner: Writable<u64> = Writable::new(0u64);

        owner.write(|value| { *value = 321; });
        owner.read(|value| { assert_eq!(321, *value); });

        /* Simple set/value for Copy traits */
        owner.set(123);
        assert_eq!(123, owner.value());

        /* Read view */
        let reader: ReadOnly<u64> = owner.read_only();
        let mut copy: u64 = 0;

        reader.read(|value| { assert_eq!(123, *value); });

        /* Ensure read closure capture */
        reader.read(|value| { copy = *value; });

        /* Compare outside closure to ensure capture */
        assert_eq!(123, copy);

        /* Ensure simple read works */
        assert_eq!(123, reader.value());
    } 
}
