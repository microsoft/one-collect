// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::cell::Cell;
use std::rc::Rc;

pub mod os;

pub type EventExtension = os::EventExtension;

static EMPTY: &[u8] = &[];

pub struct EventData<'a> {
    full_data: &'a [u8],
    event_data: &'a [u8],
    format: &'a EventFormat,
}

impl<'a> EventData<'a> {
    /// Constructs a new EventData.
    ///
    /// # Arguments
    ///
    /// * `full_data` - The full data for the event.
    /// * `event_data` - The event specific payload data.
    /// * `format` - The format of the event describing the payload data.
    pub fn new(
        full_data: &'a [u8],
        event_data: &'a [u8],
        format: &'a EventFormat) -> Self {
        Self {
            full_data,
            event_data,
            format,
        }
    }

    /// Gets the full data for the event, including non-payload data.
    ///
    /// # Returns
    /// - A slice of the full data.
    pub fn full_data(&self) -> &[u8] { self.full_data }

    /// Gets the payload data for the event.
    ///
    /// # Returns
    /// - A slice of the event specific payload data.
    pub fn event_data(&self) -> &[u8] { self.event_data }

    /// Gets the format of the event.
    ///
    /// # Returns
    /// - A `EventFormat` reference of the event.
    pub fn format(&self) -> &EventFormat { self.format }
}

type BoxedCallback = Box<dyn FnMut(&EventData) -> anyhow::Result<()>>;

/// `DataFieldRef` is a wrapper for a `DataField` contained in a `Cell`, wrapped in a `Rc`.
/// This allows the `DataField` to be shared and updated across multiple consumers.
#[derive(Clone)]
pub struct DataFieldRef(Rc<Cell<DataField>>);

impl DataFieldRef {
    /// Creates a new reference to a `DataField`.
    ///
    /// # Returns
    /// - A new `DataFieldRef` instance.
    pub fn new() -> Self {
        DataFieldRef(Rc::new(Cell::new(DataField::default())))
    }

    /// Gets the data field that the reference is pointing to.
    ///
    /// # Returns
    /// - A `DataField`.
    pub fn get(&self) -> DataField {
        (*self.0).get()
    }

    /// Gets the data associated with the data field.
    ///
    /// # Parameters
    /// - `data`: The event data from which to retrieve the field data.
    ///
    /// # Returns
    /// - A slice of the data.
    pub fn get_data<'a>(
        &self,
        data: &'a [u8]) -> &'a [u8] {
        /* Get a copy of the field at this point in time */
        let field = self.get();

        /* Use it to slice the data */
        &data[field.start() .. field.end()]
    }

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u64.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - A `Result` that contains the u64 value if successful, or an error if not.
    pub fn get_u64(
        &self,
        data: &[u8]) -> Result<u64, anyhow::Error> {
        let slice = self.get_data(data);

        Ok(u64::from_ne_bytes(slice[0..8].try_into()?))
    }

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u64.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - An `Option` that contains the u64 value if successful, or `None` if not.
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

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u32.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - A `Result` that contains the u32 value if successful, or an error if not.
    pub fn get_u32(
        &self,
        data: &[u8]) -> Result<u32, anyhow::Error> {
        let slice = self.get_data(data);

        Ok(u32::from_ne_bytes(slice[0..4].try_into()?))
    }

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u32.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - An `Option` that contains the u32 value if successful, or `None` if not.
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

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u16.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - A `Result` that contains the u16 value if successful, or an error if not.
    pub fn get_u16(
        &self,
        data: &[u8]) -> Result<u16, anyhow::Error> {
        let slice = self.get_data(data);

        Ok(u16::from_ne_bytes(slice[0..2].try_into()?))
    }

    /// Tries to retrieve the data that the `DataFieldRef` points to as a u16.
    ///
    /// # Parameters
    /// - `data`: The data from which to retrieve the slice.
    ///
    /// # Returns
    /// - An `Option` that contains the u16 value if successful, or `None` if not.
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

    /// Resets the `DataField`'s start and end to 0.
    pub fn reset(&self) {
        self.update(0, 0);
    }

    /// Updates the `DataField` that the `DataFieldRef` points to with a new start and length.
    ///
    /// # Parameters
    /// - `start`: The start index of the new data field.
    /// - `len`: The length of the new data field.
    ///
    /// # Returns
    /// - The length of the new data field.
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
    /// Provides a default instance of `DataFieldRef`.
    /// The default instance is created with a new `DataFieldRef`.
    fn default() -> Self {
        Self::new()
    }
}

/// `DataField` represents a slice of data with a start and end index.
/// It is used to fetch specific portions of data.
#[derive(Clone)]
#[derive(Copy)]
#[derive(Default)]
pub struct DataField(u32, u32);

impl DataField {
    /// Constructs a new `DataField`.
    ///
    /// # Parameters
    /// - `start`: The start position of the data field.
    /// - `end`: The end position of the data field.
    ///
    /// # Returns
    /// - A new `DataField` instance.
    fn new(
        start: u32,
        end: u32) -> Self {
        Self(start, end)
    }

    /// Gets the start position of the data field.
    ///
    /// # Returns
    /// - The start position as usize.
    fn start(&self) -> usize {
        self.0 as usize
    }

    /// Gets the end position of the data field.
    ///
    /// # Returns
    /// - The end position as usize.
    fn end(&self) -> usize {
        self.1 as usize
    }
}

/// `EventFieldRef` is a reference to an `EventField` in an `EventFormat`.
/// It holds the index of the `EventField` in the `EventFormat`'s `fields` vector.
#[derive(Clone)]
#[derive(Copy)]
pub struct EventFieldRef(usize);

impl From<EventFieldRef> for usize {
    /// Allows an `EventFieldRef` to be converted into a `usize`.
    fn from(val: EventFieldRef) -> Self {
        val.0
    }
}

/// `LocationType` is used to classify the type of location of an `EventField`.
/// It describes if the location is static, dynamic, or a static string.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LocationType {
    /// Represents a static location that holds binary data.
    Static,
    /// Represents a static location that holds a UTF8 string.
    StaticString,
    /// Represents a dynamic location, with the position being relative to another field.
    DynRelative,
    /// Represents a dynamic location, with the position being an absolute index into the data.
    DynAbsolute,
    /// Represents a static location that holds a UTF16 string.
    StaticUTF16String,
}

/// `EventField` represents a field in an event.
/// It holds information about the field name, type, location, offset, and size.
#[derive(Clone, PartialEq)]
pub struct EventField {
    /// The name of the field.
    pub name: String,
    /// The type of the field.
    pub type_name: String,
    /// The location type of the field, which could be static, dynamic, or a static string.
    pub location: LocationType,
    /// The offset of the field in the event data.
    pub offset: usize,
    /// The size of the field in bytes.
    pub size: usize,
}

impl EventField {
    /// Constructs a new `EventField`.
    ///
    /// # Parameters
    /// - `name`: The name of the field.
    /// - `type_name`: The type of the field.
    /// - `location`: The location type of the field.
    /// - `offset`: The offset of the field in the event data.
    /// - `size`: The size of the field data.
    ///
    /// # Returns
    /// - A new `EventField` instance.
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

/// `EventFormat` represents the format of an event.
/// It holds a collection of `EventField`s which describe the fields within an event.
#[derive(Clone, PartialEq)]
pub struct EventFormat {
    fields: Vec<EventField>,
}

impl Default for EventFormat {
    /// Creates a new `EventFormat` instance with an empty `fields` vector.
    fn default() -> Self {
        EventFormat::new()
    }
}

impl EventFormat {
    /// Creates a new `EventFormat` instance with an empty `fields` vector.
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
        }
    }

    /// Adds a new `EventField` to the `fields` vector.
    ///
    /// # Parameters
    ///
    /// - `field`: The `EventField` to add.
    pub fn add_field(
        &mut self,
        field: EventField) {
        self.fields.push(field);
    }

    /// Returns a reference to the `fields` vector.
    ///
    /// # Returns
    ///
    /// A slice containing all the `EventField`s.
    pub fn fields(&self) -> &[EventField] {
        &self.fields
    }

    /// Returns a reference to an `EventField` based on the reference.
    ///
    /// # Returns
    ///
    /// An `EventField` if the field exists, panics otherwise.
    pub fn get_field_unchecked(
        &self,
        field: EventFieldRef) -> &EventField {
        &self.fields[usize::from(field)]
    }

    /// Returns a reference to an `EventField` in the `fields` vector based on its name, if it exists.
    /// This method does not perform any bounds checking.
    ///
    /// # Parameters
    ///
    /// - `name`: The name of the field.
    ///
    /// # Returns
    ///
    /// An `EventFieldRef` if a field with the given name exists, panics otherwise.
    pub fn get_field_ref_unchecked(
        &self,
        name: &str) -> EventFieldRef {
        self.get_field_ref(name).unwrap()
    }

    /// Returns a reference to an `EventField` in the `fields` vector based on its name, if it exists.
    ///
    /// # Parameters
    ///
    /// - `name`: The name of the field.
    ///
    /// # Returns
    ///
    /// An `EventFieldRef` if a field with the given name exists, `None` otherwise.
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

    fn get_data_with_offset_direct<'a>(
        size: usize,
        loc_type: LocationType,
        offset: usize,
        data: &'a [u8]) -> &'a [u8] {
        match loc_type {
            LocationType::Static => {
                let end = offset + size;

                if end > data.len() {
                    return EMPTY;
                }

                &data[offset .. end]
            },

            LocationType::StaticString => {
                if offset > data.len() {
                    return EMPTY;
                }

                let slice = &data[offset..];
                let mut len = 0usize;
                
                for b in slice {
                    if *b == 0 {
                        break;
                    }

                    len += 1;
                }

                &slice[0..len]
            },

            LocationType::StaticUTF16String => {
                if offset > data.len() {
                    return EMPTY;
                }

                let slice = &data[offset..];
                let chunks = slice.chunks_exact(2);
                let mut len = 0usize;

                for chunk in chunks {
                    if chunk[0] == 0 && chunk[1] == 0 {
                        break;
                    }

                    len += 2;
                }

                &slice[0..len]
            },

            LocationType::DynRelative => {
                todo!("Need to support relative location");
            },

            LocationType::DynAbsolute => {
                todo!("Need to support absolute location");
            },
        }
    }

    /// Retrieves the data associated with a given `EventFieldRef` within the provided data slice
    /// and offset.
    ///
    /// # Parameters
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The data slice from which to retrieve the field data.
    /// - `offset`: The offset to use in addition to a static offset.
    ///
    /// # Returns
    /// - A slice of the provided data that corresponds to the requested `EventFieldRef`.
    pub fn get_data_with_offset<'a>(
            &self,
            field_ref: EventFieldRef,
            data: &'a [u8],
            offset: usize) -> &'a [u8] {
        let index: usize = field_ref.into();

        if index >= self.fields.len() {
            return EMPTY;
        }

        let field = &self.fields[index];
        let offset = field.offset + offset;

        Self::get_data_with_offset_direct(
            field.size,
            field.location,
            offset,
            data)
    }

    /// Retrieves the data associated with a given `EventFieldRef` within the provided data slice.
    ///
    /// # Parameters
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The data slice from which to retrieve the field data.
    ///
    /// # Returns
    /// - A slice of the provided data that corresponds to the requested `EventFieldRef`.
    pub fn get_data<'a>(
            &self,
            field_ref: EventFieldRef,
            data: &'a [u8]) -> &'a [u8] {
        self.get_data_with_offset(field_ref, data, 0)
    }

    /// Retrieves the range of the data within the relative dynamic data field.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - A `Result` which is:
    ///     - `Ok` variant containing the range of the field if it exists;
    ///     - `Err` variant containing an error if the field does not exist or cannot be read.
    pub fn get_rel_loc(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Result<std::ops::Range<usize>, anyhow::Error> {
        let index: usize = field_ref.into();

        if index >= self.fields.len() {
            anyhow::bail!("Invalid field ref");
        }

        let field = &self.fields[index];

        if field.size != 4 {
            anyhow::bail!("Field size must be 4");
        }

        let rel_loc = u32::from_ne_bytes(data[field.offset..field.offset+4].try_into()?);

        let mut offset = field.offset;
        offset += 4;
        offset += (rel_loc & 0xFFFF) as usize;

        let length = (rel_loc >> 16) as usize;

        Ok(offset .. offset + length)
    }

    /// Retrieves the value of a specified field from the event data as a 64-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - A `Result` which is:
    ///     - `Ok` variant containing the value of the field if it exists and can be read as a 64-bit unsigned integer;
    ///     - `Err` variant containing an error if the field does not exist or cannot be read as a 64-bit unsigned integer.
    pub fn get_u64(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Result<u64, anyhow::Error> {
        let slice = self.get_data(field_ref, data);

        Ok(u64::from_ne_bytes(slice[0..8].try_into()?))
    }

    /// Tries to retrieve the value of a specified field from the event data as a 64-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - An `Option` which is:
    ///     - `Some` variant containing the value of the field if it exists and can be read as a 64-bit unsigned integer;
    ///     - `None` if the field does not exist or cannot be read as a 64-bit unsigned integer.
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

    /// Retrieves the value of a specified field from the event data as a 32-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - A `Result` which is:
    ///     - `Ok` variant containing the value of the field if it exists and can be read as a 32-bit unsigned integer;
    ///     - `Err` variant containing an error if the field does not exist or cannot be read as a 32-bit unsigned integer.
    pub fn get_u32(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Result<u32, anyhow::Error> {
        let slice = self.get_data(field_ref, data);

        Ok(u32::from_ne_bytes(slice[0..4].try_into()?))
    }

    /// Tries to retrieve the value of a specified field from the event data as a 32-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - An `Option` which is:
    ///     - `Some` variant containing the value of the field if it exists and can be read as a 32-bit unsigned integer;
    ///     - `None` if the field does not exist or cannot be read as a 32-bit unsigned integer.
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

    /// Retrieves the value of a specified field from the event data as a 16-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - A `Result` which is:
    ///     - `Ok` variant containing the value of the field if it exists and can be read as a 16-bit unsigned integer;
    ///     - `Err` variant containing an error if the field does not exist or cannot be read as a 16-bit unsigned integer.
    pub fn get_u16(
        &self,
        field_ref: EventFieldRef,
        data: &[u8]) -> Result<u16, anyhow::Error> {
        let slice = self.get_data(field_ref, data);

        Ok(u16::from_ne_bytes(slice[0..2].try_into()?))
    }

    /// Tries to retrieve the value of a specified field from the event data as a 16-bit unsigned integer.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - An `Option` which is:
    ///     - `Some` variant containing the value of the field if it exists and can be read as a 16-bit unsigned integer;
    ///     - `None` if the field does not exist or cannot be read as a 16-bit unsigned integer.
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

    /// Retrieves the value of a specified field from the event data as a string.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - A `Result` which is:
    ///     - `Ok` variant containing the value of the field if it exists and can be read as a string;
    ///     - `Err` variant containing an error if the field does not exist or cannot be read as a string.
    pub fn get_str<'a>(
        &self,
        field_ref: EventFieldRef,
        data: &'a [u8]) -> Result<&'a str, anyhow::Error> {
        let slice = self.get_data(field_ref, data);
        if slice.is_empty() { return Ok(""); }

        Ok(std::str::from_utf8(slice)?)
    }

    /// Tries to retrieve the value of a specified field from the event data as a string.
    ///
    /// # Parameters
    ///
    /// - `field_ref`: A reference to the `EventField` for which to retrieve the data.
    /// - `data`: The event data from which to retrieve the field value.
    ///
    /// # Returns
    ///
    /// - An `Option` which is:
    ///     - `Some` variant containing the value of the field if it exists and can be read as a string;
    ///     - `None` if the field does not exist or cannot be read as a string.
    pub fn try_get_str<'a>(
        &self,
        field_ref: EventFieldRef,
        data: &'a [u8]) -> Option<&'a str> {
        let slice = self.get_data(field_ref, data);

        if slice.is_empty() { return Some(""); }

        match std::str::from_utf8(slice) {
            Ok(str) => Some(str),
            Err(_) => None,
        }
    }
}

const EVENT_FLAG_NO_CALLSTACK:u64 = 1u64 << 0;
const EVENT_FLAG_PROXY:u64 = 1u64 << 1;

struct FieldSkip {
    loc_type: LocationType,
    offset: usize,
}

/// `Event` represents a system event in the context of event collection and profiling.
pub struct Event {
    id: usize,
    name: String,
    flags: u64,
    callbacks: Vec<BoxedCallback>,
    format: EventFormat,
    extension: EventExtension,
}

impl Event {
    /// Constructs a new Event.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the event.
    /// * `name` - The name of the event.
    pub fn new(
        id: usize,
        name: String) -> Self {
        Self {
            id,
            name,
            flags: 0,
            callbacks: Vec::new(),
            format: EventFormat::new(),
            extension: EventExtension::default(),
        }
    }

    fn get_field_data_closure<'a>(
        offset: usize,
        size: usize,
        loc_type: LocationType,
        skips: &Vec<FieldSkip>,
        data: &'a [u8]) -> &'a [u8] {
        let mut skip_offset = 0;

        for skip in skips {
            match skip.loc_type {
                LocationType::StaticString => {
                    for b in &data[skip_offset+skip.offset..] {
                        skip_offset += 1;

                        if *b == 0 {
                            break;
                        }
                    }
                },

                LocationType::StaticUTF16String => {
                    let slice = &data[skip_offset+skip.offset..];
                    let chunks = slice.chunks_exact(2);

                    for chunk in chunks {
                        skip_offset += 2;

                        if chunk[0] == 0 && chunk[1] == 0 {
                            break;
                        }
                    }
                },

                _ => {
                    /* Unexpected */
                    return EMPTY;
                },
            }
        }

        EventFormat::get_data_with_offset_direct(
            size,
            loc_type,
            offset + skip_offset,
            data)
    }

    /// Tries to return a closure capable of getting the field data
    /// dynamically.
    ///
    /// # Arguments
    ///
    /// * `field_name` - The name of the field to get.
    pub fn try_get_field_data_closure(
        &self,
        field_name: &str) -> Option<Box<dyn FnMut(&[u8]) -> &[u8]>> {
        let mut offset = 0;

        let mut skips = Vec::new();

        for field in &self.format().fields {
            if field.name == field_name {
                let size = field.size;
                let location = field.location;

                if skips.is_empty() {
                    /* Use direct field offset to allow for gaps */
                    offset = field.offset;

                    /* Direct access closure */
                    return Some(Box::new(move |data| -> &[u8] {
                        EventFormat::get_data_with_offset_direct(
                            size,
                            location,
                            offset,
                            data)
                    }));
                } else {
                    /* Complicated access closure */
                    return Some(Box::new(move |data| -> &[u8] {
                        Self::get_field_data_closure(
                            offset,
                            size,
                            location,
                            &skips,
                            data)
                    }));
                }
            }

            /* Check for dynamic data */
            if field.size == 0 {
                match field.location {
                    LocationType::StaticString |
                    LocationType::StaticUTF16String => {
                        /* Known skippable types */
                        skips.push(FieldSkip {
                            loc_type: field.location,
                            offset
                        });
                    },

                    _ => {
                        /* Cannot read field data via closure */
                        return None;
                    },
                }
            }

            offset += field.size;
        }

        None
    }

    /// Returns the ID of the event.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns the name of the event.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the no_callstack flag for the event. Use this when events are expected
    /// to have high volumes and callstacks should not be collected for performance
    /// reasons.
    pub fn set_no_callstack_flag(&mut self) {
        self.flags |= EVENT_FLAG_NO_CALLSTACK;
    }

    /// Checks if the no_callstack flag is set for the event.
    pub fn has_no_callstack_flag(&self) -> bool {
        self.flags & EVENT_FLAG_NO_CALLSTACK != 0
    }

    /// Sets the proxy flag for the event. Use this when events are used for proxy
    /// scenarios. The underlying session will not actually enable / add these events.
    pub fn set_proxy_flag(&mut self) {
        self.flags |= EVENT_FLAG_PROXY;
    }

    /// Checks if the proxy flag is set for the event.
    pub fn has_proxy_flag(&self) -> bool {
        self.flags & EVENT_FLAG_PROXY != 0
    }

    /// Returns a mutable reference to the event format.
    pub fn format_mut(&mut self) -> &mut EventFormat {
        &mut self.format
    }

    /// Returns a reference to the event format.
    pub fn format(&self) -> &EventFormat {
        &self.format
    }

    /// Returns a reference to the event OS extension.
    pub fn extension(&self) -> &EventExtension {
        &self.extension
    }

    /// Returns a mutable reference to the event OS extension.
    pub fn extension_mut(&mut self) -> &mut EventExtension {
        &mut self.extension
    }

    /// Adds a callback function to the event that runs each time the event is processed.
    ///
    /// # Arguments
    ///
    /// * `callback` - A callback function that returns a Result.
    pub fn add_callback(
        &mut self,
        callback: impl FnMut(&EventData) -> anyhow::Result<()> + 'static) {
        self.callbacks.push(Box::new(callback));
    }

    /// Processes the event by running all callbacks with the supplied data.
    ///
    /// # Arguments
    ///
    /// * `full_data` - The full data related to the event.
    /// * `event_data` - The event-related data.
    /// * `errors` - A vector to store any errors that occur during the process.
    pub fn process(
        &mut self,
        full_data: &[u8],
        event_data: &[u8],
        errors: &mut Vec<anyhow::Error>) {
        let data = EventData::new(
            full_data,
            event_data,
            &self.format);

        for callback in &mut self.callbacks {
            if let Err(e) = (callback)(&data) {
                errors.push(e);
            }
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

        e.add_callback(move |data| {
            let format = data.format();
            let event_data = data.event_data();

            let a = format.get_data(first, event_data);
            let b = format.get_data(second, event_data);
            let c = format.get_data(third, event_data);

            assert!(a[0] == 1u8);
            assert!(b[0] == 2u8);
            assert!(c[0] == 3u8);

            count.fetch_add(1, Ordering::Relaxed);

            Ok(())
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

        let mut errors: Vec<anyhow::Error> = Vec::new();

        let slice = data.as_slice();

        assert_eq!(count.load(Ordering::Relaxed), 0);
        e.process(slice, slice, &mut errors);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(errors.is_empty());
        e.process(slice, slice, &mut errors);
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert!(errors.is_empty());
    }

    #[test]
    fn flags() {
        let mut e = Event::new(0, "Flags".to_owned());

        /* No Callstacks */
        assert!(!e.has_no_callstack_flag());
        e.set_no_callstack_flag();
        assert!(e.has_no_callstack_flag());
    }

    #[test]
    fn error_reporting() {
        let mut e = create_abc();
        e.add_callback(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Oops").into())
        });

        let mut data: Vec<u8> = Vec::new();
        data.push(1u8);
        data.push(2u8);
        data.push(3u8);

        let mut errors: Vec<anyhow::Error> = Vec::new();

        let slice = data.as_slice();
        e.process(slice, slice, &mut errors);
        assert_eq!(1, errors.len());
        e.process(slice, slice, &mut errors);
        assert_eq!(2, errors.len());
        e.process(slice, slice, &mut errors);
        assert_eq!(3, errors.len());
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

    #[test]
    fn field_data_closure() {
        /* Static */
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "unsigned char".into(),
                LocationType::Static, 0, 1));
        format.add_field(
            EventField::new(
                "2".into(), "u32".into(),
                LocationType::Static, 1, 4));
        format.add_field(
            EventField::new(
                "3".into(), "u64".into(),
                LocationType::Static, 5, 8));

        let mut data = Vec::new();

        data.push(b'1');
        data.extend_from_slice(&2u32.to_ne_bytes());
        data.extend_from_slice(&3u64.to_ne_bytes());

        let first = e.try_get_field_data_closure("1");
        assert!(first.is_some());
        assert_eq!(&data[0..1], first.unwrap()(&data));

        let second = e.try_get_field_data_closure("2");
        assert!(second.is_some());
        assert_eq!(&data[1..5], second.unwrap()(&data));

        let third = e.try_get_field_data_closure("3");
        assert!(third.is_some());
        assert_eq!(&data[5..13], third.unwrap()(&data));

        /* Dynamic */
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "string".into(),
                LocationType::StaticString, 0, 0));
        format.add_field(
            EventField::new(
                "2".into(), "wide_string".into(),
                LocationType::StaticUTF16String, 0, 0));
        format.add_field(
            EventField::new(
                "3".into(), "u64".into(),
                LocationType::Static, 0, 8));

        let mut data = Vec::new();

        data.extend_from_slice(b"test\0");
        data.extend_from_slice(b"t\0e\0s\0t\0\0\0");
        data.extend_from_slice(&123456789u64.to_ne_bytes());

        let first = e.try_get_field_data_closure("1");
        assert!(first.is_some());
        assert_eq!(&data[0..4], first.unwrap()(&data));

        let second = e.try_get_field_data_closure("2");
        assert!(second.is_some());
        assert_eq!(&data[5..13], second.unwrap()(&data));

        let third = e.try_get_field_data_closure("3");
        assert!(third.is_some());
        assert_eq!(&data[15..23], third.unwrap()(&data));

        /* Mixed Middle */
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "string".into(),
                LocationType::StaticString, 0, 0));
        format.add_field(
            EventField::new(
                "2".into(), "u64".into(),
                LocationType::Static, 0, 8));
        format.add_field(
            EventField::new(
                "3".into(), "wide_string".into(),
                LocationType::StaticUTF16String, 0, 0));

        let mut data = Vec::new();

        data.extend_from_slice(b"test\0");
        data.extend_from_slice(&123456789u64.to_ne_bytes());
        data.extend_from_slice(b"t\0e\0s\0t\0\0\0");

        let first = e.try_get_field_data_closure("1");
        assert!(first.is_some());
        assert_eq!(&data[0..4], first.unwrap()(&data));

        let second = e.try_get_field_data_closure("2");
        assert!(second.is_some());
        assert_eq!(&data[5..13], second.unwrap()(&data));

        let third = e.try_get_field_data_closure("3");
        assert!(third.is_some());
        assert_eq!(&data[13..21], third.unwrap()(&data));

        /* Mixed Start */
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "1".into(), "u64".into(),
                LocationType::Static, 0, 8));
        format.add_field(
            EventField::new(
                "2".into(), "string".into(),
                LocationType::StaticString, 8, 0));
        format.add_field(
            EventField::new(
                "3".into(), "wide_string".into(),
                LocationType::StaticUTF16String, 8, 0));

        let mut data = Vec::new();

        data.extend_from_slice(&123456789u64.to_ne_bytes());
        data.extend_from_slice(b"test\0");
        data.extend_from_slice(b"t\0e\0s\0t\0\0\0");

        let first = e.try_get_field_data_closure("1");
        assert!(first.is_some());
        assert_eq!(&data[0..8], first.unwrap()(&data));

        let second = e.try_get_field_data_closure("2");
        assert!(second.is_some());
        assert_eq!(&data[8..12], second.unwrap()(&data));

        let third = e.try_get_field_data_closure("3");
        assert!(third.is_some());
        assert_eq!(&data[13..21], third.unwrap()(&data));
    }

    #[test]
    fn get_rel_loc() {
        let mut e = Event::new(1, "test".into());
        let format = e.format_mut();

        format.add_field(
            EventField::new(
                "data".into(), "__rel_loc u8[]".into(),
                LocationType::DynRelative, 0, 4));

        let rel_data = format.get_field_ref_unchecked("data");

        /* 0 offset case */
        let mut data = Vec::new();

        let rel_loc = 4u32 << 16 | 0u32;
        let actual = 123456789u32;

        data.extend_from_slice(&rel_loc.to_ne_bytes());
        data.extend_from_slice(&actual.to_ne_bytes());

        let range = format.get_rel_loc(rel_data, &data).unwrap();
        assert_eq!(data[4..8], data[range]);

        /* Non-0 offset case */
        let mut data = Vec::new();

        let rel_loc = 4u32 << 16 | 4u32;
        let pad = 987654321u32;
        let actual = 123456789u32;

        data.extend_from_slice(&rel_loc.to_ne_bytes());
        data.extend_from_slice(&pad.to_ne_bytes());
        data.extend_from_slice(&actual.to_ne_bytes());

        let range = format.get_rel_loc(rel_data, &data).unwrap();
        assert_eq!(data[8..12], data[range]);
    }
}
