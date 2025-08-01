// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* Some methods are used in tests only */
#![allow(unused)]

const EMPTY: &[u8] = &[];

pub const LABEL_META: u8 = 1;
pub const LABEL_ACTIVITY: u8 = 2;
pub const LABEL_RELATED_ACTIVITY: u8 = 3;

pub fn parse_event_extension_v1(
    data: &[u8],
    mut output: impl FnMut(u8, &[u8])) {
    let mut extension = data;
    let mut count = 0;

    while extension.len() > 1 && count < 3 {
        let label = extension[0];
        extension = &extension[1..];

        match label {
            LABEL_META => {
                /* Event Metadata */
                if extension.len() < 4 { break; }

                let len = u32::from_le_bytes(
                    extension[0..4].try_into().unwrap()) as usize;

                extension = &extension[4..];

                if extension.len() < len { break; }

                output(1, &extension[0..len]);

                extension = &extension[len..];
            },

            LABEL_ACTIVITY => {
                /* Activity Id */
                if extension.len() < 16 { break; }

                output(2, &extension[0..16]);

                extension = &extension[16..];
            },

            LABEL_RELATED_ACTIVITY => {
                /* Related Activity Id */
                if extension.len() < 16 { break; }

                output(3, &extension[0..16]);

                extension = &extension[16..];
            },

            _ => {
                /* Unknown */
                break;
            },
        }

        count += 1;
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
        if data.len() < 4 {
            None
        } else {
            Some(u32::from_le_bytes(data[0..4].try_into().unwrap()))
        }
    }

    fn read_long(data: &[u8]) -> Option<u64> {
        if data.len() < 8 {
            None
        } else {
            Some(u64::from_le_bytes(data[0..8].try_into().unwrap()))
        }
    }

    fn read_string(data: &[u8]) -> usize {
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
        let len = Self::read_string(buffer);
        let (provider_name, buffer) = Self::advance(buffer, len);

        /* EventId */
        let (event_id, buffer) = Self::advance(buffer, 4);

        /* EventName */
        let len = Self::read_string(buffer);
        let (event_name, buffer) = Self::advance(buffer, len);

        /* Keywords */
        let (keywords, buffer) = Self::advance(buffer, 8);

        /* Version */
        let (version, buffer) = Self::advance(buffer, 4);

        /* Level */
        let (level, fields) = Self::advance(buffer, 4);

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
