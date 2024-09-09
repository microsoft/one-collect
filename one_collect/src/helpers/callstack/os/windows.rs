use super::*;
use crate::{Writable, ReadOnly};
use crate::etw::*;

pub struct CallstackReader {
    ancillary: ReadOnly<AncillaryData>,
    match_id: Writable<u64>,
}

impl Clone for CallstackReader {
    fn clone(&self) -> Self {
        Self {
            ancillary: self.ancillary.clone(),
            match_id: Writable::new(0),
        }
    }
}

impl CallstackReader {
    pub fn match_id(&self) -> u64 { *self.match_id.borrow() }

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
}

impl CallstackHelper {
    pub fn new() -> Self {
        /* Start with an empty ancillary data */
        let empty = Writable::new(AncillaryData::default());

        Self {
            ancillary: Writable::new(empty.read_only()),
        }
    }

    pub fn with_external_lookup(self) -> Self {
        /* NOP on Windows */
        self
    }

    pub fn to_reader(self) -> CallstackReader {
        CallstackReader {
            ancillary: self.ancillary.borrow().clone(),
            match_id: Writable::new(0),
        }
    }
}

impl CallstackHelp for EtwSession {
    fn with_callstack_help(
        self,
        helper: &CallstackHelper) -> Self {
        /* Set the ancillary data from the target session */
        *helper.ancillary.borrow_mut() = self.ancillary_data();

        self
    }
}
