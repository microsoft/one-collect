#[cfg_attr(target_os = "linux", path = "os/linux.rs")]
#[cfg_attr(target_os = "windows", path = "os/windows.rs")]
pub mod os;

pub type CallstackReader = os::CallstackReader;
pub type CallstackHelper = os::CallstackHelper;

use crate::helpers::exporting::KERNEL_START;

pub trait CallstackHelp {
    fn with_callstack_help(
        self,
        helper: &CallstackHelper) -> Self;
}

#[derive(Default)]
pub struct PartialCallstack {
    frames: Vec<u64>
}

impl PartialCallstack {
    pub fn frames(&self) -> &[u64] { &self.frames }

    pub fn is_empty(&self) -> bool { self.frames.is_empty() }

    pub fn frames_end_in_userspace(
        frames: &[u64]) -> bool {
        let len = frames.len();

        len > 0 && frames[len-1] < KERNEL_START
    }

    pub fn ends_in_userspace(&self) -> bool {
        Self::frames_end_in_userspace(self.frames())
    }

    pub fn add_frames(
        &mut self,
        frames: &[u64]) {
        self.frames.extend_from_slice(frames);
    }

    pub fn clear(&mut self) { self.frames.clear(); }
}
