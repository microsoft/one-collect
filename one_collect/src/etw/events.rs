use super::*;

fn register_soft_pid(
    event: &mut Event,
    pid_field: &str) {
    /*
     * Legacy kernel events do not always have process IDs.
     * We register a hook to provide this from the data for
     * other consumers.
     */
    if let Some(pid) = event.format().get_field_ref(pid_field) {
        event.register_soft_pid(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let pid = fmt.get_u32(pid, data)?;

            Ok(pid as i32)
        });
    }
}

pub fn comm(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_PROCESS_PROVIDER;

    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "UniqueProcessKey".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
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

    len = 8;
    format.add_field(EventField::new(
        "DirectoryTableBase".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "Flags".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    /* Dynamically sized after this */
    len = 0;
    format.add_field(EventField::new(
        "UserSID".into(), "object".into(),
        LocationType::Static, offset, len));

    /* Only first dynamic data will have offset */
    let offset = 0;
    format.add_field(EventField::new(
        "ImageFileName".into(), "string".into(),
        LocationType::StaticString, offset, len));

    format.add_field(EventField::new(
        "CommandLine".into(), "string".into(),
        LocationType::StaticUTF16String, offset, len));

    event.set_no_callstack_flag();

    register_soft_pid(&mut event, "ProcessId");

    event
}

pub fn mmap(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_IMAGE_PROVIDER;

    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "ImageBase".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "ImageSize".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
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

    len = 8;
    format.add_field(EventField::new(
        "DefaultBase".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;

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

    register_soft_pid(&mut event, "ProcessId");

    event
}

pub fn sample_profile(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_PROFILE_PROVIDER;

    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "InstructionPointer".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "ThreadId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "Count".into(), "u32".into(),
        LocationType::Static, offset, len));

    event.set_no_callstack_flag();

    event
}

pub fn dpc(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_INTERRUPT_PROVIDER;

    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "InitialTime".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "Routine".into(), "u64".into(),
        LocationType::Static, offset, len));

    event.set_no_callstack_flag();

    event
}

pub fn callstack(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_CALLSTACK_PROVIDER;

    let format = event.format_mut();

    len = 8;
    format.add_field(EventField::new(
        "EventTimeStamp".into(), "u64".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "StackProcess".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "StackThread".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 0;
    format.add_field(EventField::new(
        "StackFrames".into(), "u64".into(),
        LocationType::Static, offset, len));

    event.set_no_callstack_flag();

    register_soft_pid(&mut event, "StackProcess");

    event
}

pub fn ready_thread(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_THREAD_PROVIDER;

    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "TThreadId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 1;
    format.add_field(EventField::new(
        "AdjustReason".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "AdjustIncrement".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "Flag".into(), "s8".into(),
        LocationType::Static, offset, len));

    event.set_no_callstack_flag();

    event
}

pub fn cswitch(
    id: usize,
    name: &str) -> Event {
    let mut event = Event::new(id, name.into());
    let mut offset: usize = 0;
    let mut len: usize;

    *event.extension_mut().provider_mut() = REAL_SYSTEM_THREAD_PROVIDER;

    let format = event.format_mut();

    len = 4;
    format.add_field(EventField::new(
        "NewThreadId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadId".into(), "u32".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 1;
    format.add_field(EventField::new(
        "NewThreadPriority".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadPriority".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "PreviousCState".into(), "u8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "SpareByte".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadWaitReason".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadWaitMode".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadState".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    format.add_field(EventField::new(
        "OldThreadWaitIdealProcessor".into(), "s8".into(),
        LocationType::Static, offset, len));
    offset += len;

    len = 4;
    format.add_field(EventField::new(
        "NewThreadWaitTime".into(), "u32".into(),
        LocationType::Static, offset, len));

    event.set_no_callstack_flag();

    event
}
