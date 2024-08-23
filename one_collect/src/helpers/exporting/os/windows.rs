use super::*;
use crate::Writable;

/* OS Specific Session Type */
pub type Session = EtwSession;

pub(crate) struct OSExportSettings {
    /* Placeholder */
}

impl OSExportSettings {
    pub fn new() -> Self {
        Self {
        }
    }
}

pub struct EtwSession {
    /* Placeholder for now */
}

pub struct ExportSampler {
    /* Common */
    pub(crate) exporter: Writable<ExportMachine>,
    pub(crate) frames: Vec<u64>,

    /* OS Specific */
}

impl ExportSampler {
    pub(crate) fn new(
        exporter: &Writable<ExportMachine>,
        _session: &EtwSession) -> Self {
        Self {
            exporter: exporter.clone(),
            frames: Vec::new(),
        }
    }

    pub(crate) fn time(
        &self,
        _data: &EventData) -> anyhow::Result<u64> {
        todo!()
    }

    pub(crate) fn pid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        todo!()
    }

    pub(crate) fn tid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        todo!()
    }

    pub(crate) fn cpu(&self) -> u16 {
        todo!()
    }

    pub(crate) fn callstack(
        &self,
        _data: &EventData) -> anyhow::Result<()> {
        todo!()
    }
}

pub(crate) struct OSExportMachine {
    
}

impl OSExportMachine {
    pub fn new() -> Self {
        Self {
        }
    }
}

impl ExportMachine {
    pub(crate) fn os_add_mmap_exec(
        &mut self,
        _pid: u32,
        _mapping: &mut ExportMapping,
        _filename: &str) -> anyhow::Result<()> {
        Ok(())
    }

    pub(crate) fn os_add_comm_exec(
        &mut self,
        _pid: u32,
        _comm: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
