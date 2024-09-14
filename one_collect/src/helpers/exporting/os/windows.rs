use super::*;
use crate::{ReadOnly, Writable};
use crate::etw::*;

/* OS Specific Session Type */
pub type Session = EtwSession;

trait PushWide {
    fn push_wide_str(
        &mut self,
        data: &[u8]);
}

impl PushWide for String {
    fn push_wide_str(
        &mut self,
        data: &[u8]) {
        for chunk in data.chunks_exact(2) {
            let val = u16::from_ne_bytes(
                chunk[..2].try_into().unwrap());

            if let Some(c) = char::from_u32(val as u32) {
                self.push(c);
            } else {
                self.push('?');
            }
        }
    }
}

pub(crate) struct OSExportSettings {
    /* Placeholder */
}

impl OSExportSettings {
    pub fn new() -> Self {
        Self {
        }
    }
}

pub struct ExportSampler {
    /* Common */
    pub(crate) exporter: Writable<ExportMachine>,
    pub(crate) frames: Vec<u64>,

    /* OS Specific */
    ancillary: ReadOnly<AncillaryData>,
}

impl ExportSampler {
    pub(crate) fn new(
        exporter: &Writable<ExportMachine>,
        session: &EtwSession) -> Self {
        Self {
            exporter: exporter.clone(),
            ancillary: session.ancillary_data(),
            frames: Vec::new(),
        }
    }

    pub(crate) fn time(
        &self,
        _data: &EventData) -> anyhow::Result<u64> {
        Ok(self.ancillary.borrow().time())
    }

    pub(crate) fn pid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        Ok(self.ancillary.borrow().pid())
    }

    pub(crate) fn tid(
        &self,
        _data: &EventData) -> anyhow::Result<u32> {
        Ok(self.ancillary.borrow().tid())
    }

    pub(crate) fn cpu(&self) -> u16 {
        self.ancillary.borrow().cpu() as u16
    }

    pub(crate) fn callstack(
        &mut self,
        _data: &EventData) -> anyhow::Result<()> {
        let mut _match_id = 0u64;

        self.ancillary.borrow().callstack(
            &mut self.frames,
            &mut _match_id);

        Ok(())
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

    fn sid_length(data: &[u8]) -> anyhow::Result<usize> {
        const ptr_size: usize = std::mem::size_of::<usize>();
        let mut sid_size: usize = ptr_size;

        if data.len() < 8 {
            anyhow::bail!("Invalid SID length");
        }

        let sid = u64::from_ne_bytes(data[..8].try_into()?);

        if sid != 0 {
            let offset = ptr_size * 2;
            let start = offset + 1;

            if data.len() < start {
                anyhow::bail!("Invalid SID length");
            }

            let auth_count = data[start..][0] as usize;
            sid_size = offset + 8 + (auth_count * 4);
        }

        Ok(sid_size)
    }

    fn hook_mmap_event(
        event: &mut Event,
        event_machine: Writable<ExportMachine>) {
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("ProcessId");
        let addr = fmt.get_field_ref_unchecked("ImageBase");
        let len = fmt.get_field_ref_unchecked("ImageSize");
        let filename = fmt.get_field_ref_unchecked("FileName");

        let mut path_buf = String::new();

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();

            let mut event_machine = event_machine.borrow_mut();

            /*
             * Paths are logged in the global root namespace.
             * So we must use a path that can be used via
             * CreateFile vs NtOpenFile. Insert the GlobalRoot
             * in front of the path to ensure this can happen.
             * This way std::fs::File::open() will work.
             */
            path_buf.clear();
            path_buf.push_str("\\\\?\\GlobalRoot");
            path_buf.push_wide_str(fmt.get_data(filename, data));

            /* Use the interned ID as the inode for uniqueness */
            let inode = event_machine.intern(&path_buf);

            event_machine.add_mmap_exec(
                fmt.get_u32(pid, data)?,
                fmt.get_u64(addr, data)?,
                fmt.get_u64(len, data)?,
                0, /* Pgoffset */
                0, /* Device Maj */
                0, /* Device Min */
                inode as u64,
                &path_buf)
        });
    }

    fn hook_comm_event(
        ancillary: ReadOnly<AncillaryData>,
        event: &mut Event,
        event_machine: Writable<ExportMachine>) {
        let fmt = event.format();
        let pid = fmt.get_field_ref_unchecked("ProcessId");
        let sid = fmt.get_field_ref_unchecked("UserSID");
        let comm = fmt.get_field_ref_unchecked("ImageFileName");

        event.add_callback(move |data| {
            let fmt = data.format();
            let data = data.event_data();
            let sid = fmt.get_field_unchecked(sid);

            let pid = fmt.get_u32(pid, data)?;

            let dynamic = &data[sid.offset..];
            let sid_length = Self::sid_length(dynamic)?;
            let dynamic = &dynamic[sid_length..];

            event_machine.borrow_mut().add_comm_exec(
                pid,
                fmt.get_str(comm, dynamic)?)
        });
    }

    pub fn hook_to_session(
        mut self,
        session: &mut EtwSession) -> anyhow::Result<Writable<ExportMachine>> {
        let cpu_profiling = self.settings.cpu_profiling;
        let cswitches = self.settings.cswitches;
        let events = self.settings.events.take();

        let callstack_reader = match self.settings.callstack_helper.take() {
            Some(callstack_helper) => { callstack_helper.to_reader() },
            None => { anyhow::bail!("No callstack reader specified."); }
        };

        let machine = Writable::new(self);

        if let Some(events) = events {
            let shared_sampler = Writable::new(
                ExportSampler::new(
                    &machine,
                    session));

            for mut callback in events {
                if callback.event.is_none() {
                    continue;
                }

                let mut event = callback.event.take().unwrap();
                let mut event_machine = machine.borrow_mut();

                let mut builder = ExportBuiltContext::new(
                    &mut event_machine,
                    session);

                /* Invoke built callback for setup, etc */
                (callback.built)(&mut builder)?;

                let sample_kind = match builder.take_sample_kind() {
                    /* If the builder has a sample kind pre-defined, use that */
                    Some(kind) => { kind },
                    /* Otherwise, use the event name */
                    None => { event_machine.sample_kind(event.name()) }
                };

                /* Re-use sampler for all events */
                let event_sampler = shared_sampler.clone();

                /* Trampoline between event callback and exporter callback */
                event.add_callback(move |data| {
                    (callback.trace)(
                        &mut ExportTraceContext::new(
                            &mut event_sampler.borrow_mut(),
                            sample_kind,
                            data))
                });

                let options = match event.has_no_callstack_flag() {
                    true => {
                        /* No callstack flag is enabled */
                        None
                    },
                    false => {
                        /* Event requires callstacks */
                        Some(PROPERTY_STACK_TRACE)
                    },
                };

                /* Add event to session */
                session.add_event(event, options);
            }
        }

        if cpu_profiling {
            /* TODO */
        }

        if cswitches {
            /* TODO */
        }

        /* Hook mmap records */
        Self::hook_mmap_event(
            session.mmap_load_event(),
            machine.clone());

        Self::hook_mmap_event(
            session.mmap_load_capture_start_event(),
            machine.clone());

        /* Hook comm records */
        Self::hook_comm_event(
            session.ancillary_data(),
            session.comm_start_event(),
            machine.clone());

        Self::hook_comm_event(
            session.ancillary_data(),
            session.comm_start_capture_event(),
            machine.clone());

        Ok(machine)
    }
}

impl ExportSessionHelp for EtwSession {
    fn build_exporter(
        &mut self,
        settings: ExportSettings) -> anyhow::Result<Writable<ExportMachine>> {
        let exporter = ExportMachine::new(settings);

        exporter.hook_to_session(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn it_works() {

        let helper = CallstackHelper::new();

        let settings = ExportSettings::new(helper);

        let mut session = EtwSession::new();

        let exporter = session.build_exporter(settings).unwrap();

        let duration = std::time::Duration::from_secs(1);

        session.parse_for_duration(
            "one_collect_export_self_test",
            duration).unwrap();

        let exporter = exporter.borrow();

        let strings = exporter.strings();

        for process in exporter.processes() {
            let mut comm = "Unknown";

            if let Some(comm_id) = process.comm_id() {
                if let Ok(value) = strings.from_id(comm_id) {
                    comm = value;
                }
            }

            println!("{} ({}):", process.pid(), comm);

            for mapping in process.mappings() {
                let filename = match strings.from_id(mapping.filename_id()) {
                    Ok(name) => { name },
                    Err(_) => { "Unknown" },
                };

                println!(
                    "0x{:x} - 0x{:x}: {}",
                    mapping.start(),
                    mapping.end(),
                    filename);
            }
        }
    }
}
