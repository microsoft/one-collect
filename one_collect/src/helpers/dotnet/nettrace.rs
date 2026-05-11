// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* Some methods are used in tests only */
#![allow(unused)]

const EMPTY: &[u8] = &[];

pub const LABEL_META: u8 = 1;
pub const LABEL_ACTIVITY: u8 = 2;
pub const LABEL_RELATED_ACTIVITY: u8 = 3;

const U32_LEN: usize = 4;
const U64_LEN: usize = 8;
const GUID_LEN: usize = 16;

use crate::event::{LocationType, EventFormat, EventField};

pub fn parse_event_extension_v1(
    data: &[u8],
    mut output: impl FnMut(u8, &[u8])) {
    let mut extension = data;
    let mut count = 0;

    /*
     * We only support 3 label types right now. This data comes
     * from untrusted sources. Ensure data won't panic (getting
     * a slice by invalid/out-of-range index will panic) and
     * also ensure we don't get more labels than we support.
     * This ensures we cannot be DOS'd, etc. by rogue processes
     */
    while extension.len() > 1 && count < 3 {
        let label = extension[0];
        extension = &extension[1..];

        match label {
            LABEL_META => {
                /* Event Metadata */

                /* Enough space for u32 */
                if extension.len() < U32_LEN { break; }

                let len = u32::from_le_bytes(
                    extension[0..U32_LEN].try_into().unwrap()) as usize;

                /* Advance past u32 */
                extension = &extension[U32_LEN..];

                /* Ensure read length is valid */
                if extension.len() < len { break; }

                /* Output */
                output(LABEL_META, &extension[0..len]);

                /* Advance past metadata */
                extension = &extension[len..];
            },

            LABEL_ACTIVITY => {
                /* Activity Id */

                /* Enough space for Guid */
                if extension.len() < GUID_LEN { break; }

                /* Output */
                output(LABEL_ACTIVITY, &extension[0..GUID_LEN]);

                /* Advance past Guid */
                extension = &extension[GUID_LEN..];
            },

            LABEL_RELATED_ACTIVITY => {
                /* Related Activity Id */

                /* Enough space for Guid */
                if extension.len() < GUID_LEN { break; }

                /* Output */
                output(LABEL_RELATED_ACTIVITY, &extension[0..GUID_LEN]);

                /* Advance past Guid */
                extension = &extension[GUID_LEN..];
            },

            _ => {
                /* Unknown */
                break;
            },
        }

        count += 1;
    }
}

pub struct FieldsParserV5 {
}

struct FieldType {
    type_name: &'static str,
    size: usize,
}

impl FieldsParserV5 {
    const TYPE_OBJECT:u32 = 1u32;
    const TYPE_BOOL:u32 = 3u32;
    const TYPE_UTF16_CODE_UNIT:u32 = 4u32;
    const TYPE_SBYTE:u32 = 5u32;
    const TYPE_BYTE:u32 = 6u32;
    const TYPE_INT16:u32 = 7u32;
    const TYPE_UINT16:u32 = 8u32;
    const TYPE_INT32:u32 = 9u32;
    const TYPE_UINT32:u32 = 10u32;
    const TYPE_INT64:u32 = 11u32;
    const TYPE_UINT64:u32 = 12u32;
    const TYPE_SINGLE:u32 = 13u32;
    const TYPE_DOUBLE:u32 = 14u32;
    const TYPE_DATE_TIME:u32 = 16u32;
    const TYPE_GUID:u32 = 17u32;
    const TYPE_UTF16_STRING:u32 = 18u32;
    const TYPE_ARRAY:u32 = 19u32;

    fn read_int(data: &[u8]) -> Option<u32> {
        if data.len() < U32_LEN {
            None
        } else {
            Some(u32::from_le_bytes(data[0..U32_LEN].try_into().unwrap()))
        }
    }

    fn skip_string<'a>(data: &'a [u8]) -> &'a [u8] {
        let mut offset = 0;
        for c in data.chunks_exact(2) {
            let c = u16::from_le_bytes(c.try_into().unwrap());

            offset += 2;

            if c == 0 { break; }
        }

        &data[offset..]
    }

    fn read_string<'a>(
        data: &'a [u8],
        output: &mut String) -> &'a [u8] {
        output.clear();

        let mut offset = 0;
        for c in data.chunks_exact(2) {
            let c = u16::from_le_bytes(c.try_into().unwrap());

            offset += 2;

            if c == 0 { break; }

            match char::from_u32(c as u32) {
                Some(c) => { output.push(c); },
                None => { output.push('?'); },
            }
        }

        &data[offset..]
    }

    fn append_field(
        format: &mut EventFormat,
        field_name: String,
        field_type: &str,
        size: usize) {
        let mut offset = 0;

        if let Some(field) = format.fields().last() {
            offset = field.offset + field.size;
        }

        let location = match field_type {
            "string" => LocationType::StaticUTF16String,
            _ => {
                if field_type.starts_with("__dyn_array") {
                    LocationType::StaticLenPrefixArray
                } else {
                    LocationType::Static
                }
            },
        };

        format.add_field(EventField::new(
            field_name,
            field_type.to_owned(),
            location,
            offset,
            size));
    }

    fn parse_type<'a>(fields: &'a [u8]) -> Option<FieldType> {
        let ftype = match Self::read_int(fields) {
            Some(value) => { value },
            None => { return None; },
        };

        match ftype {
            Self::TYPE_OBJECT => {
                Some(FieldType {
                    type_name: "object",
                    size: 0,
                })
            },

            Self::TYPE_BOOL => {
                Some(FieldType {
                    type_name: "u32",
                    size: 4,
                })
            },

            Self::TYPE_UTF16_CODE_UNIT => {
                Some(FieldType {
                    type_name: "u16",
                    size: 2,
                })
            },

            Self::TYPE_SBYTE => {
                Some(FieldType {
                    type_name: "s8",
                    size: 1,
                })
            },

            Self::TYPE_BYTE => {
                Some(FieldType {
                    type_name: "u8",
                    size: 1,
                })
            },

            Self::TYPE_INT16 => {
                Some(FieldType {
                    type_name: "s16",
                    size: 2,
                })
            },

            Self::TYPE_UINT16 => {
                Some(FieldType {
                    type_name: "u16",
                    size: 2,
                })
            },

            Self::TYPE_INT32 => {
                Some(FieldType {
                    type_name: "s32",
                    size: 4,
                })
            },

            Self::TYPE_UINT32 => {
                Some(FieldType {
                    type_name: "u32",
                    size: 4,
                })
            },

            Self::TYPE_INT64 => {
                Some(FieldType {
                    type_name: "s64",
                    size: 8,
                })
            },

            Self::TYPE_UINT64 => {
                Some(FieldType {
                    type_name: "u64",
                    size: 8,
                })
            },

            Self::TYPE_SINGLE => {
                Some(FieldType {
                    type_name: "float",
                    size: 4,
                })
            },

            Self::TYPE_DOUBLE => {
                Some(FieldType {
                    type_name: "double",
                    size: 8,
                })
            },

            Self::TYPE_DATE_TIME => {
                Some(FieldType {
                    type_name: "u8",
                    size: 16,
                })
            },

            Self::TYPE_GUID => {
                Some(FieldType {
                    type_name: "u8",
                    size: 16,
                })
            },

            Self::TYPE_UTF16_STRING => {
                Some(FieldType {
                    type_name: "string",
                    size: 0,
                })
            },

            Self::TYPE_ARRAY => {
                Some(FieldType {
                    type_name: "array",
                    size: 0,
                })
            },

            _ => { None }
        }
    }

    fn parse_object<'a>(
        mut fields: &'a [u8],
        format: &mut EventFormat,
        depth: usize) -> &'a [u8] {
        if depth > 32 {
            return &[];
        }

        let mut v2 = false;

        if let Some(mut count) = Self::read_int(fields) {
            fields = &fields[4..];

            if count == 0 {
                /* Handle V2Params, if any */
                if let Some(bytes) = Self::read_int(fields) {
                    fields = &fields[4..];

                    if bytes == 0 || fields.len() == 0 {
                        /* Not enough bytes */
                        return &[];
                    }

                    let tag = fields[0];
                    fields = &fields[1..];

                    if tag != 2 {
                        /* Not V2Params, unknown. */
                        return &[];
                    }

                    /* Update count */
                    if let Some(new_count) = Self::read_int(fields) {
                        fields = &fields[4..];
                        count = new_count;

                        v2 = true;
                    }
                }
            }

            while count > 0 {
                let mut name = String::new();
                let mut next = None;

                if v2 {
                    if fields.len() < 4 {
                        break;
                    }

                    if let Some(size) = Self::read_int(fields) {
                        let size = size as usize;

                        if size > fields.len() {
                            break;
                        }

                        next = Some(&fields[size..]);
                        fields = &fields[4..];

                        fields = Self::read_string(fields, &mut name);
                    } else {
                        break;
                    }
                }

                if let Some(field_type) = Self::parse_type(fields) {
                    fields = &fields[4..];

                    match field_type.type_name {
                        "object" => {
                            fields = Self::parse_object(fields, format, depth+1);

                            if !v2 {
                                fields = Self::read_string(fields, &mut name);
                            }
                        },

                        "array" => {
                            if let Some(array_type) = Self::parse_type(fields) {
                                fields = &fields[4..];

                                match array_type.type_name {
                                    "object" | "array" => {
                                        /*
                                         * Currently don't support complex array types:
                                         * Allowing a field to have its own format would
                                         * allow for this. We would then parse a new
                                         * format via parse_object and add it to the field.
                                         */
                                        return &[];
                                    },
                                    _ => {
                                        let type_name = format!("__dyn_array {}", array_type.type_name);

                                        Self::append_field(format, name, &type_name, 0);
                                    },
                                }
                            } else {
                                break;
                            }
                        },

                        _ => {
                            if !v2 {
                                fields = Self::read_string(fields, &mut name);
                            }

                            Self::append_field(format, name, field_type.type_name, field_type.size);
                        },
                    }

                    if let Some(next) = next {
                        fields = next;
                    }
                } else {
                    break;
                }

                count -= 1;
            }
        } else {
            /* No more, not enough data. */
            fields = &[];
        }

        fields
    }

    pub fn parse(mut fields: &[u8]) -> EventFormat {
        let mut format = EventFormat::default();

        Self::parse_object(fields, &mut format, 1);

        format
    }
}

pub struct MetaParserV5<'a> {
    provider_name: &'a [u8],
    event_id: &'a [u8],
    event_name: &'a [u8],
    keywords: &'a [u8],
    version: &'a [u8],
    level: &'a [u8],
    fields: &'a [u8],
}

impl<'a> MetaParserV5<'a> {
    pub fn event_id(&self) -> Option<u32> {
        Self::read_int(self.event_id)
    }

    pub fn provider_name(
        &self,
        output: &mut String) {
        output.clear();

        Self::push_unicode_string(
            self.provider_name,
            output);
    }

    pub fn event_name(
        &self,
        output: &mut String) {
        output.clear();

        Self::push_unicode_string(
            self.event_name,
            output);
    }

    pub fn keywords(&self) -> Option<u64> {
        Self::read_long(self.keywords)
    }

    pub fn version(&self) -> Option<u32> {
        Self::read_int(self.version)
    }

    pub fn level(&self) -> Option<u32> {
        Self::read_int(self.level)
    }

    pub fn fields(&self) -> &'a [u8] { self.fields }

    fn push_unicode_string(
        data: &[u8],
        output: &mut String) {
        for c in data.chunks_exact(2) {
            let c = u16::from_le_bytes(c.try_into().unwrap());

            if c == 0 { break; }

            match char::from_u32(c as u32) {
                Some(c) => { output.push(c); },
                None => { output.push('?'); },
            }
        }
    }

    fn read_int(data: &[u8]) -> Option<u32> {
        if data.len() < U32_LEN {
            None
        } else {
            Some(u32::from_le_bytes(data[0..U32_LEN].try_into().unwrap()))
        }
    }

    fn read_long(data: &[u8]) -> Option<u64> {
        if data.len() < U64_LEN {
            None
        } else {
            Some(u64::from_le_bytes(data[0..U64_LEN].try_into().unwrap()))
        }
    }

    fn read_string_len(data: &[u8]) -> usize {
        let mut len = 0;
        let chunks = data.chunks_exact(2);

        for chunk in chunks {
            len += 2;

            if chunk[0] == 0 && chunk[1] == 0 {
                break;
            }
        }

        len
    }

    fn advance(data: &'a [u8], len: usize) -> (&'a [u8], &'a [u8]) {
        if data.len() < len {
            (EMPTY, EMPTY)
        } else {
            (&data[0..len], &data[len..])
        }
    }

    pub fn parse(data: &'a [u8]) -> Self {
        let mut buffer = data;

        /* ProviderName */
        let len = Self::read_string_len(buffer);
        let (provider_name, buffer) = Self::advance(buffer, len);

        /* EventId */
        let (event_id, buffer) = Self::advance(buffer, U32_LEN);

        /* EventName */
        let len = Self::read_string_len(buffer);
        let (event_name, buffer) = Self::advance(buffer, len);

        /* Keywords */
        let (keywords, buffer) = Self::advance(buffer, U64_LEN);

        /* Version */
        let (version, buffer) = Self::advance(buffer, U32_LEN);

        /* Level */
        let (level, fields) = Self::advance(buffer, U32_LEN);

        Self {
            provider_name,
            event_id,
            event_name,
            keywords,
            version,
            level,
            fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_parser() {
        let mut count = 0;

        /* Shouldn't get anything on empty data */
        parse_event_extension_v1(
            EMPTY,
            |_,_| { count += 1; });

        assert_eq!(0, count);

        let data = [
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
        ];

        /* Shouldn't get anything on invalid data */
        parse_event_extension_v1(
            &data,
            |_,_| { count += 1; });

        assert_eq!(0, count);

        /* Should get valid metadata */
        let data = [
            0x01,
            0x1C,0x00,0x00,0x00,
            0x00,0x00,0x2f,0x01,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x08,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x04,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00];

        parse_event_extension_v1(
            &data,
            |label,data| {
                count += 1;

                assert_eq!(1, label);

                let parser = MetaParserV5::parse(data);

                assert_eq!(Some(303), parser.event_id());
                assert_eq!(Some(0x80000000000), parser.keywords());
                assert_eq!(Some(0), parser.version());
                assert_eq!(Some(4), parser.level());
                assert_eq!(4, parser.fields().len());
            });

        assert_eq!(1, count);
        count = 0;

        /* Guid at start should work */
        let data = [
            0x2,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x3,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x01,
            0x1C,0x00,0x00,0x00,
            0x00,0x00,0x2f,0x01,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x08,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x04,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00];

        parse_event_extension_v1(
            &data,
            |label,data| {
                if label == 2 {
                    assert_eq!(0, count);
                    assert_eq!(16, data.len());
                    assert_eq!(0x01, data[0]);
                    assert_eq!(0x10, data[15]);
                    count += 1;
                } else if label == 3 {
                    assert_eq!(1, count);
                    assert_eq!(16, data.len());
                    assert_eq!(0x01, data[0]);
                    assert_eq!(0x10, data[15]);
                    count += 1;
                } else if label == 1 {
                    assert_eq!(2, count);
                    count += 1;
                    let parser = MetaParserV5::parse(data);

                    assert_eq!(Some(303), parser.event_id());
                    assert_eq!(Some(0x80000000000), parser.keywords());
                    assert_eq!(Some(0), parser.version());
                    assert_eq!(Some(4), parser.level());
                    assert_eq!(4, parser.fields().len());
                }
            });

        assert_eq!(3, count);
        count = 0;

        /* Partial data should stop */
        let data = [
            0x1,
            0x01,0x02,0x03,0x04];

        parse_event_extension_v1(
            &data,
            |_,_| { count += 1; });

        assert_eq!(0, count);

        let data = [
            0x2,
            0x01,0x02,0x03,0x04];

        parse_event_extension_v1(
            &data,
            |_,_| { count += 1; });

        assert_eq!(0, count);

        let data = [
            0x3,
            0x01,0x02,0x03,0x04];

        parse_event_extension_v1(
            &data,
            |_,_| { count += 1; });

        assert_eq!(0, count);

        /* Zero length extension */
        let data = [
            0x1,
            0x00,0x00,0x00,0x00];

        parse_event_extension_v1(
            &data,
            |label,data| {
                assert_eq!(0, count);
                assert_eq!(1, label);
                assert!(data.is_empty());

                count += 1;
            });

        assert_eq!(1, count);
        count = 0;

        /* Limit count to 3 for DOS */
        let data = [
            0x2,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x3,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x2,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x3,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x2,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10,
            0x3,
            0x01,0x02,0x03,0x04,
            0x05,0x06,0x07,0x08,
            0x09,0x0a,0x0b,0x0c,
            0x0d,0x0e,0x0f,0x10];

        parse_event_extension_v1(
            &data,
            |_,_| { count += 1 });

        assert_eq!(3, count);
    }

    #[test]
    fn no_meta_parser_panics() {
        /* Parser should be very safe to use without panics */
        let parser = MetaParserV5::parse(EMPTY);
        let mut name = String::new();

        /* Shouldn't have anything */
        assert!(parser.event_id().is_none());
        assert!(parser.keywords().is_none());
        assert!(parser.version().is_none());
        assert!(parser.level().is_none());
        assert!(parser.fields().is_empty());

        parser.event_name(&mut name);
        assert!(name.is_empty());

        parser.provider_name(&mut name);
        assert!(name.is_empty());
    }

    #[test]
    fn meta_parser_works() {
        let mut name = String::new();

        let data = [
            0x00,0x00,0x2f,0x01,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x08,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x04,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00];

        let parser = MetaParserV5::parse(&data);

        assert_eq!(Some(303), parser.event_id());
        assert_eq!(Some(0x80000000000), parser.keywords());
        assert_eq!(Some(0), parser.version());
        assert_eq!(Some(4), parser.level());
        assert_eq!(4, parser.fields().len());

        parser.event_name(&mut name);
        assert!(name.is_empty());

        parser.provider_name(&mut name);
        assert!(name.is_empty());

        let data = [
            0x00,0x00,0x50,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x80,0x00,0x00,
            0x02,0x00,0x00,0x00,
            0x01,0x00,0x00,0x00,
            0x02,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00];

        let parser = MetaParserV5::parse(&data);

        assert_eq!(Some(80), parser.event_id());
        assert_eq!(Some(0x200008000), parser.keywords());
        assert_eq!(Some(1), parser.version());
        assert_eq!(Some(2), parser.level());
        assert_eq!(4, parser.fields().len());

        parser.event_name(&mut name);
        assert!(name.is_empty());

        parser.provider_name(&mut name);
        assert!(name.is_empty());
    }
}
