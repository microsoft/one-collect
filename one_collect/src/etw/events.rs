use super::{EventField, Event, LocationType};

pub fn comm(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "UniqueProcessKey".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ProcessId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ParentId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "SessionId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ExitStatus".into(), "s32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "DirectoryTableBase".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "UserSID".into(), "object".into(),
        LocationType::Static, offset, 0));

    format.add_field(EventField::new(
        "ImageFileName".into(), "string".into(),
        LocationType::StaticUTF16String, offset, 0));

    format.add_field(EventField::new(
        "CommandLine".into(), "string".into(),
        LocationType::StaticUTF16String, offset, 0));

    event.set_no_callstack_flag();

    event
}

pub fn mmap(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let len: usize;
    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "ImageBase".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ImageSize".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ProcessId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ImageCheckSum".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "TimeDateStamp".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    /* Reserved0 */
    offset += len;

    format.add_field(EventField::new(
        "DefaultBase".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    /* Reserved1 */
    offset += len;

    /* Reserved2 */
    offset += len;

    /* Reserved3 */
    offset += len;

    /* Reserved4 */
    offset += len;

    format.add_field(EventField::new(
        "FileName".into(), "string".into(),
        LocationType::StaticUTF16String, offset, 0));

    event.set_no_callstack_flag();

    event
}
