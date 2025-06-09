// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;
use std::collections::hash_map::Drain;
use std::collections::hash_map::Entry::{Vacant, Occupied};

use super::*;
use crate::{Writable, ReadOnly};
use crate::etw::*;

struct PartialThreadCallstacks {
    partials: HashMap<u64, PartialCallstack>,
}

impl PartialThreadCallstacks {
    fn new() -> Self {
        Self {
            partials: HashMap::default(),
        }
    }

    fn flush(&mut self) -> Drain<u64, PartialCallstack> {
        self.partials.drain()
    }

    fn add_frames<'a>(
        &'a mut self,
        time: u64,
        frames: &'a [u64],
        buffer: &'a mut Vec<u64>) -> Option<&'a [u64]> {
        let user_stack = PartialCallstack::frames_end_in_userspace(frames);

        match self.partials.entry(time) {
            Vacant(entry) => {
                if user_stack {
                    /* Return immediately, since user mode only stack */
                    return Some(frames);
                }

                /* Kernel stack, save for userspace */
                let mut partial = PartialCallstack::default();

                partial.add_frames(frames);

                entry.insert(partial);

                None
            },
            Occupied(mut entry) => {
                if user_stack {
                    let partial = entry.remove();

                    buffer.clear();
                    buffer.extend_from_slice(partial.frames());
                    buffer.extend_from_slice(frames);

                    Some(&buffer[..])
                } else {
                    entry.get_mut().add_frames(frames);

                    None
                }
            }
        }
    }
}

pub struct CompletedCallstack<'a> {
    time: u64,
    pid: u32,
    tid: u32,
    frames: &'a [u64],
}

impl<'a> CompletedCallstack<'a> {
    fn new(
        time: u64,
        pid: u32,
        tid: u32,
        frames: &'a [u64]) -> Self {
        Self {
            time,
            pid,
            tid,
            frames,
        }
    }

    pub fn time(&self) -> u64 { self.time }

    pub fn pid(&self) -> u32 { self.pid }

    pub fn tid(&self) -> u32 { self.tid }

    pub fn frames(&'a self) -> &'a [u64] { self.frames }

    fn notify(
        &self,
        callbacks: &mut Vec<Box<dyn FnMut(&CompletedCallstack)>>) {
        for callback in callbacks {
            callback(self);
        }
    }
}

#[derive(Default)]
struct PartialCallstackLookup {
    stacks: HashMap<u64, PartialThreadCallstacks>,
    buffer: Vec<u64>,
    flushed_callbacks: Vec<Box<dyn FnMut()>>,
    frames_callbacks: Vec<Box<dyn FnMut(&CompletedCallstack)>>,
}

impl PartialCallstackLookup {
    fn add_flushed_callback(
        &mut self,
        callback: impl FnMut() + 'static) {
        self.flushed_callbacks.push(Box::new(callback));
    }

    fn add_frames_callback(
        &mut self,
        callback: impl FnMut(&CompletedCallstack) + 'static) {
        self.frames_callbacks.push(Box::new(callback));
    }

    fn flush(&mut self) {
        for (key, mut stacks) in self.stacks.drain() {
            let pid = (key >> 32 & 0xFFFF) as u32;
            let tid = (key & 0xFFFF) as u32;

            for (time, stack) in stacks.flush() {
                let full = CompletedCallstack::new(
                    time,
                    pid,
                    tid,
                    stack.frames());

                full.notify(&mut self.frames_callbacks);
            }
        }

        for callback in &mut self.flushed_callbacks {
            callback();
        }
    }

    fn add_frames(
        &mut self,
        time: u64,
        pid: u32,
        tid: u32,
        frames: &[u64]) {
        if frames.is_empty() {
            return;
        }

        let key = (pid as u64) << 32 | tid as u64;

        let stacks = self.stacks
            .entry(key)
            .or_insert_with(|| PartialThreadCallstacks::new());

        if let Some(frames) = stacks.add_frames(
            time,
            frames,
            &mut self.buffer) {
            let full = CompletedCallstack::new(
                time,
                pid,
                tid,
                frames);

            full.notify(&mut self.frames_callbacks);
        }
    }
}

pub struct CallstackReader {
    ancillary: ReadOnly<AncillaryData>,
    lookup: Writable<PartialCallstackLookup>,
    match_id: Writable<u64>,
}

impl Clone for CallstackReader {
    fn clone(&self) -> Self {
        Self {
            ancillary: self.ancillary.clone(),
            lookup: self.lookup.clone(),
            match_id: Writable::new(0),
        }
    }
}

impl CallstackReader {
    pub fn match_id(&self) -> u64 { *self.match_id.borrow() }

    pub fn add_flushed_callback(
        &self,
        callback: impl FnMut() + 'static) {
        self.lookup.borrow_mut().add_flushed_callback(callback);
    }

    pub fn add_async_frames_callback(
        &self,
        callback: impl FnMut(&CompletedCallstack) + 'static) {
        self.lookup.borrow_mut().add_frames_callback(callback);
    }

    pub fn read_frames(
        &self,
        _full_data: &[u8],
        frames: &mut Vec<u64>) {
        self.ancillary.borrow().callstack(
            frames,
            &mut self.match_id.borrow_mut());
    }
}

pub struct CallstackHelper {
    ancillary: Writable<ReadOnly<AncillaryData>>,
    lookup: Writable<PartialCallstackLookup>,
}

impl CallstackHelper {
    pub fn new() -> Self {
        /* Start with an empty ancillary data */
        let empty = Writable::new(AncillaryData::default());

        Self {
            ancillary: Writable::new(empty.read_only()),
            lookup: Writable::new(PartialCallstackLookup::default()),
        }
    }

    pub fn with_external_lookup(self) -> Self {
        /* NOP on Windows */
        self
    }

    pub fn has_unwinder(&self) -> bool { false }

    pub fn to_reader(self) -> CallstackReader {
        CallstackReader {
            ancillary: self.ancillary.borrow().clone(),
            lookup: self.lookup.clone(),
            match_id: Writable::new(0),
        }
    }
}

impl CallstackHelp for EtwSession {
    fn with_callstack_help(
        mut self,
        helper: &CallstackHelper) -> Self {
        let ancillary = self.ancillary_data();

        /* Set the ancillary data from the target session */
        *helper.ancillary.borrow_mut() = ancillary.clone();

        let helper_lookup = helper.lookup.clone();

        self.add_built_callback(move |session| {
            /*
             * Session is about to be parsed, check if
             * we should be handling kernel stacks.
             */
            if !session.needs_kernel_callstacks() {
                return Ok(());
            }

            /* Hookup async callstack event */
            let callstack = session.callstack_event();
            let fmt = callstack.format();
            let time = fmt.get_field_ref_unchecked("EventTimeStamp");
            let pid = fmt.get_field_ref_unchecked("StackProcess");
            let tid = fmt.get_field_ref_unchecked("StackThread");
            let frames = fmt.get_field_ref_unchecked("StackFrames");
            let frame_offset = fmt.get_field_unchecked(frames).offset;

            let lookup = helper_lookup.clone();
            let mut frame_buffer = Vec::new();

            /* Callstacks just add to our lookup as they arrive */
            callstack.add_callback(move |data| {
                let fmt = data.format();
                let data = data.event_data();

                let time = fmt.get_u64(time, data)?;
                let pid = fmt.get_u32(pid, data)?;
                let tid = fmt.get_u32(tid, data)?;

                /* Read frames from remaining data */
                let frame_data = &data[frame_offset..];

                frame_buffer.clear();

                for frame in frame_data.chunks_exact(8) {
                    let frame = unsafe { *(frame.as_ptr() as *const u64) };

                    frame_buffer.push(frame);
                }

                /* Add frames to lookup */
                lookup.borrow_mut().add_frames(
                    time,
                    pid,
                    tid,
                    &frame_buffer);

                Ok(())
            });

            /* Ensure we flush stacks upon being stopped */
            let lookup = helper_lookup.clone();

            session.add_stopped_callback(
                move |_context| {
                    lookup.borrow_mut().flush();
                });

            Ok(())
        });

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn build_partial_lookup(
        time: u64,
        pid: u32,
        tid: u32,
        frames: Vec<u64>,
        outcome: Writable<bool>) -> PartialCallstackLookup {
        let mut stacks = PartialCallstackLookup::default();

        stacks.add_frames_callback(move |completed| {
            *outcome.borrow_mut() =
                completed.time != time ||
                completed.pid != pid ||
                completed.pid != tid ||
                completed.frames != &frames;
        });

        stacks
    }

    #[test]
    fn partial_callstacks() {
        let outcome = Writable::new(false);

        let mut stacks = build_partial_lookup(
            0xf00d,
            0,
            1,
            vec!(KERNEL_START, 0x1, 0x2, 0x3, 0x4),
            outcome.clone());

        /* Frames ending in userspace should give full callstack */
        stacks.add_frames(
            0xf00d,
            0,
            1,
            &vec!(KERNEL_START, 0x1, 0x2, 0x3, 0x4));

        assert_eq!(true, *outcome.borrow());
        *outcome.borrow_mut() = false;

        /* Partial frames should only complete on user */
        stacks.add_frames(
            0xf00d,
            0,
            1,
            &vec!(KERNEL_START));
        assert_eq!(false, *outcome.borrow());

        stacks.add_frames(
            0xf00d,
            0,
            1,
            &vec!(0x1, 0x2, 0x3, 0x4));
        assert_eq!(true, *outcome.borrow());
        *outcome.borrow_mut() = false;

        /* Flush should work for kernel only stacks */
        let mut stacks = build_partial_lookup(
            0xf00d,
            0,
            1,
            vec!(KERNEL_START),
            outcome.clone());

        stacks.add_frames(
            0xf00d,
            0,
            1,
            &vec!(KERNEL_START));
        assert_eq!(false, *outcome.borrow());

        stacks.flush();

        assert_eq!(true, *outcome.borrow());
    }

    #[test]
    #[ignore]
    fn it_works() {
        let helper = CallstackHelper::new();

        let mut session = EtwSession::new()
            .with_callstack_help(&helper);

        let ancillary = session.ancillary_data();

        let profile_count = Writable::new(0);
        let count = profile_count.clone();
        let event = session.profile_cpu_event(Some(PROPERTY_STACK_TRACE));
        let profile_times = Writable::new(HashSet::new());
        let times = profile_times.clone();

        event.add_callback(
            move |data| {
                times.borrow_mut().insert(ancillary.borrow().time());
                *count.borrow_mut() += 1;
                Ok(())
            });

        let stack_reader = helper.to_reader();

        let stack_count = Writable::new(0);
        let count = stack_count.clone();
        let stack_times = Writable::new(HashSet::new());
        let times = stack_times.clone();

        stack_reader.add_async_frames_callback(
            move |stack| {
                times.borrow_mut().insert(stack.time());
                *count.borrow_mut() += 1;
            });

        let flushed_count = Writable::new(0);
        let count = flushed_count.clone();

        stack_reader.add_flushed_callback(
            move || {
                *count.borrow_mut() += 1;
            });

        let duration = std::time::Duration::from_secs(1);

        session.parse_for_duration(
            "one_collect_callstacks_test",
            duration).unwrap();

        let flushed_count = *flushed_count.borrow();
        let profile_count = *profile_count.borrow();
        let stack_count = *stack_count.borrow();

        println!("Counts:");
        println!("Profile: {}", profile_count);
        println!("Stacks: {}", stack_count);

        let mut first = u64::MAX;
        let mut last = u64::MIN;

        for time in profile_times.borrow().iter() {
            let time = *time;

            if time < first {
                first = time;
            }

            if time > last {
                last = time;
            }
        }

        for time in profile_times.borrow().iter() {
            if !stack_times.borrow().contains(time) {
                println!("Missed {}", time);
            }
        }

        println!("Range: {} - {}", first, last);

        assert!(flushed_count != 0);
        assert!(profile_count != 0);
        assert!(stack_count != 0);
    }
}
