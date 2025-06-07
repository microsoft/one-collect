// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{EventField, Event, LocationType};

pub fn lost() -> Event {
    let mut event = Event::new(0, "__lost".into());
    let mut offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "id".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "lost".into(), "u64".into(),
        LocationType::Static, offset, len));

    event
}

pub fn comm() -> Event {
    let mut event = Event::new(0, "__comm".into());
    let mut offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "pid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "tid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "comm[]".into(), "char".into(),
        LocationType::StaticString, offset, 0));

    event
}

pub fn exit() -> Event {
    let mut event = Event::new(0, "__exit".into());
    let mut offset: usize = 0;
    let mut len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "pid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ppid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "tid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ptid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 8;
    format.add_field(EventField::new(
        "time".into(), "u64".into(),
        LocationType::Static, offset, len));

    event
}

pub fn fork() -> Event {
    let mut event = Event::new(0, "__fork".into());
    let mut offset: usize = 0;
    let mut len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "pid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ppid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "tid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ptid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 8;
    format.add_field(EventField::new(
        "time".into(), "u64".into(),
        LocationType::Static, offset, len));

    event
}

pub fn mmap() -> Event {
    let mut event = Event::new(0, "__mmap".into());
    let mut offset: usize = 0;
    let mut len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "pid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "tid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 8;
    format.add_field(EventField::new(
        "addr".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "len".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "pgoffset".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "maj".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "min".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 8;
    format.add_field(EventField::new(
        "ino".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ino_generation".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "prot".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "flags".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "filename[]".into(), "char".into(),
        LocationType::StaticString, offset, 0));

    event
}

pub fn lost_samples() -> Event {
    let mut event = Event::new(0, "__lost_samples".into());
    let offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "lost".into(), "u64".into(),
        LocationType::Static, offset, len));

    event
}

pub fn cswitch() -> Event {
    let mut event = Event::new(0, "__cswitch".into());
    let mut offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "next_prev_pid".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "next_prev_tid".into(), "u32".into(),
        LocationType::Static, offset, len));

    event
}
