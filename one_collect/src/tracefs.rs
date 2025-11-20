// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Result, Error, BufRead, BufReader, ErrorKind, Write};
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use tracing::{warn, info};

use crate::event::*;
use crate::user_events::UserEventsFactory;

/// Struct representing the trace file system.
pub struct TraceFS {
    root: String
}

impl TraceFS {
    /// Opens the first found trace file system and returns a `TraceFS` instance.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the tracefs is successfully opened, and `Err` otherwise.
    pub fn open() -> Result<TraceFS> {
        let mounts = File::open("/proc/mounts")?;
        let reader = BufReader::new(mounts);

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let mut parts = line.split_whitespace();

                    /* Format: fsspec path vfstype */
                    if let Some(path) = parts.nth(1) {
                        if let Some(fstype) = parts.next() {
                            if fstype == "tracefs" {
                                info!("TraceFS found and opened: path={}", path);
                                return Self::open_at(path);
                            }
                        }
                    }
                },
                Err(_) => { break; },
            }
        }

        warn!("TraceFS not mounted");
        Err(
            Error::new(
                ErrorKind::Other,
                concat!(
                    "It appears tracefs is not mounted. ",
                    "You can mount it by running ",
                    "mount -t tracefs nodev /sys/kernel/tracing.")))
    }

    /// Opens the trace file system at the given path and returns a `TraceFS` instance.
    ///
    /// # Parameters
    ///
    /// * `path`: The path where the tracefs is located.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the tracefs is successfully opened, and `Err` otherwise.
    pub fn open_at(path: &str) -> Result<TraceFS> {
        /* Ensure we have access */
        let _ = std::fs::metadata(format!("{}/README", path))?;

        let tracefs = Self {
            root: path.into()
        };

        info!("TraceFS opened at path: path={}", path);
        Ok(tracefs)
    }

    /// Parses a line from the tracefs and returns an `EventField`.
    ///
    /// # Parameters
    ///
    /// * `line`: The line to be parsed.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the line is successfully parsed, and `Err` otherwise.
    fn field_from_line(
        line: &str) -> Result<EventField> {
        /* Split upon ';' */
        let parts = line.split(';');

        /* Parse field */
        let mut fname: Option<String> = None;
        let mut ftype: Option<String> = None;
        let mut floc = LocationType::Static;
        let mut foffset: Option<usize> = None;
        let mut fsize: Option<usize> = None;

        for (i, part) in parts.enumerate() {
            let part = part.trim();

            match i {
                0 => {
                    /* <Type ...> <Name> */
                    if let Some(name_index) = part.rfind(' ') {
                        let parts = part.split_at(name_index);
                        let mut type_part = parts.0;
                        let mut name_part = parts.1.trim();

                        /* Types can start with special markers */
                        if type_part.starts_with("__rel_loc ") {
                            /* Relative dynamic data size */
                            floc = LocationType::DynRelative;
                            type_part = type_part.split_at(10).1;
                        } else if type_part.starts_with("__dyn_loc ") {
                            /* Absolute dynamic data size */
                            floc = LocationType::DynAbsolute;
                            type_part = type_part.split_at(10).1;
                        }

                        /*
                         * Remove [] from name as sometimes it encodes the 
                         * data size, which could change from version to
                         * version.
                         */
                        if let Some(bracket_index) = name_part.find('[') {
                            name_part = name_part.split_at(bracket_index).0;
                        }

                        fname = Some(name_part.into());
                        ftype = Some(type_part.into());
                    } else {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "Field name has no type."));
                    }
                },

                1 => {
                    /* offset:<Offset> */
                    let offset = part.split_at(7).1;
                    foffset = offset.parse::<usize>().ok();
                },

                2 => {
                    /* size:<Size> */
                    let size = part.split_at(5).1;
                    fsize = size.parse::<usize>().ok();
                },

                _ => {
                    /* Don't need any more, stop */
                    break;
                }
            }
        }

        /* Odd/incomplete field */
        if fname.is_none() || ftype.is_none() ||
           foffset.is_none() || fsize.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "Field is missing one of: type, name, offset, size."));
        }

        Ok(EventField::new(
            fname.unwrap(),
            ftype.unwrap(),
            floc,
            foffset.unwrap(),
            fsize.unwrap()))
    }

    /// Parses the format of an event from the tracefs and returns an `Event`.
    ///
    /// # Parameters
    ///
    /// * `system`: The system of the event.
    /// * `name`: The name of the event.
    /// * `reader`: A mutable reference to a `BufRead` instance.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the event format is successfully parsed, and `Err` otherwise.
    #[allow(clippy::while_let_on_iterator)]
    fn event_from_format(
        system: &str,
        name: &str,
        reader: &mut impl BufRead) -> Result<Event> {
        let mut lines = reader.lines();
        let mut id: Option<usize> = None;
        let mut read_format = false;

        /* Read in pre-format lines */
        while let Some(line) = lines.next() {
            if let Ok(line) = line {
                if line.starts_with("ID: ") {
                    /* Read the ID and bail if it's not in the right format */
                    if let Ok(read_id) = line.split_at(4).1.parse::<usize>() {
                        id = Some(read_id);
                    } else {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "ID was not an integer."));
                    }
                } else if line.starts_with("format:") {
                    /* The rest of the lines are format lines */
                    read_format = true;
                    break;
                }
            }
        }

        /* Ensure we read ID and format */
        if id.is_none() || !read_format {
            return Err(Error::new(
                ErrorKind::Other,
                "Format is missing ID or format prefix."));
        }

        let mut event = Event::new(
            id.unwrap(),
            format!("{}/{}", system, name));

        let format = event.format_mut();

        /* Read in format lines */
        while let Some(line) = lines.next() {
            if let Ok(line) = line {
                /* Skip non-field lines */
                if !line.starts_with("\tfield:") {
                    continue;
                }

                /* Remove "field:" */
                let line = line.split_at(7).1;

                /* Parse and add */
                let field = Self::field_from_line(line)?;

                format.add_field(field);
            }
        }

        Ok(event)
    }

    /// Finds an event in the trace filesystem.
    ///
    /// # Arguments
    ///
    /// * `system` - A string slice that holds the name of the system.
    /// * `name` - A string slice that holds the name of the event.
    ///
    /// # Returns
    ///
    /// * `Event` - An `Event` instance that has been found. Returns a `Result` which is an `Ok` if the event is found, `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(target_os = "linux")]
    /// use one_collect::tracefs::TraceFS;
    ///
    /// # #[cfg(target_os = "linux")]
    /// if let Ok(tracefs) = TraceFS::open() {
    ///     let event = tracefs.find_event("sched", "sched_waking");
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the event is not found or the file cannot be opened.
    pub fn find_event(
        &self,
        system: &str,
        name: &str) -> Result<Event> {
        let mut path_buf = PathBuf::new();

        path_buf.push(&self.root);
        path_buf.push("events");
        path_buf.push(system);
        path_buf.push(name);
        path_buf.push("format");

        let format = File::open(&path_buf);
        
        match format {
            Ok(file) => {
                let mut reader = BufReader::new(file);
                let event = Self::event_from_format(
                    system,
                    name,
                    &mut reader)?;
                
                info!("Event found: system={}, name={}", system, name);
                Ok(event)
            },
            Err(e) => {
                warn!("Event not found: system={}, name={}, error={}", system, name, e);
                Err(e)
            }
        }
    }

    /// Runs a command on the dynamic_events tracefs file.
    ///
    /// # Arguments
    ///
    /// * `command` - A string containing the command to run.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` if the command is successfully parsed, and `Err` otherwise.
    pub fn dynamic_event_command(
        &self,
        command: &str) -> Result<()> {
        let mut path_buf = PathBuf::new();

        path_buf.push(&self.root);
        path_buf.push("dynamic_events");

        let mut file = File::options()
            .append(true)
            .open(path_buf)?;

        file.write_all(command.as_bytes())?;

        Ok(())
    }

    fn register_uprobe_full(
        &self,
        probe_type: &str,
        system: &str,
        name: &str,
        file_path: &str,
        address: usize,
        fetch_args: &str) -> Result<Event> {
        let mut path_buf = PathBuf::new();

        path_buf.push(&self.root);
        path_buf.push("uprobe_events");

        let mut file = File::options()
            .append(true)
            .open(path_buf)?;

        let command = format!(
            "{}:{}/{} {}:0x{:x} {}",
            probe_type,
            system,
            name,
            file_path,
            address,
            fetch_args);

        file.write_all(command.as_bytes())?;

        self.find_event(system, name)
    }

    /// Unregisters a uprobe from the trace filesystem.
    ///
    /// # Arguments
    ///
    /// * `system` - A string slice that holds the name of the system.
    /// * `name` - A string slice that holds the name of the uprobe.
    ///
    /// # Returns
    ///
    /// * `()` - Returns a `Result` which is an `Ok` if the uprobe is unregistered, `Err` otherwise.
    pub fn unregister_uprobe(
        &self,
        system: &str,
        name: &str) -> Result<()> {
        let mut path_buf = PathBuf::new();

        path_buf.push(&self.root);
        path_buf.push("uprobe_events");

        let mut file = File::options()
            .append(true)
            .open(path_buf)?;

        let command = format!(
            "-:{}/{}",
            system,
            name);

        file.write_all(command.as_bytes())?;

        info!("Uprobe unregistered: system={}, name={}", system, name);
        Ok(())
    }

    /// Registers a uprobe in the trace filesystem.
    ///
    /// # Arguments
    ///
    /// * `system` - A string slice that holds the name of the system.
    /// * `name` - A string slice that holds the name of the uprobe.
    /// * `file` - A string slice that indicates the file associated with the uprobe.
    /// * `address` - The address where the uprobe is placed.
    /// * `fetch_args` - The arguments to fetch when the uprobe is hit.
    ///
    /// # Returns
    ///
    /// * `Event` - An `Event` instance that has been registered. Returns a `Result` which is an `Ok` if the uprobe is registered, `Err` otherwise.
    ///
    pub fn register_uprobe(
        &self,
        system: &str,
        name: &str,
        file: &str,
        address: usize,
        fetch_args: &str) -> Result<Event> {
        self.register_uprobe_full(
            "p",
            system,
            name,
            file,
            address,
            fetch_args)
    }

    /// Registers a return uprobe in the trace filesystem.
    ///
    /// # Arguments
    ///
    /// * `system` - A string slice that holds the name of the system.
    /// * `name` - A string slice that holds the name of the uprobe.
    /// * `file` - A string slice that indicates the file associated with the uprobe.
    /// * `address` - The address where the uprobe is placed.
    /// * `fetch_args` - The arguments to fetch when the uprobe is hit.
    ///
    /// # Returns
    ///
    /// * `Event` - An `Event` instance that has been registered. Returns a `Result` which is an `Ok` if the uprobe is registered, `Err` otherwise.
    ///
    pub fn register_uretprobe(
        &self,
        system: &str,
        name: &str,
        file: &str,
        address: usize,
        fetch_args: &str) -> Result<Event> {
        self.register_uprobe_full(
            "r",
            system,
            name,
            file,
            address,
            fetch_args)
    }

    pub fn user_events_factory(&self) -> Result<UserEventsFactory> {
        let mut path_buf = PathBuf::new();

        path_buf.push(&self.root);
        path_buf.push("user_events_data");

        let file = OpenOptions::new()
            .write(true)
            .open(path_buf)?;

        Ok(UserEventsFactory::new(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Write, BufWriter};
    use std::path::Path;

    #[test]
    fn it_works() {
        let mut data = Vec::new();
        let mut buffer = BufWriter::new(&mut data);

        write!(buffer, "ID: {}\n", 123).unwrap();
        write!(buffer, "format:\n").unwrap();
        write!(buffer, "\tfield:unsigned char a;\toffset:0;\tsize:1;\tsigned:0;\n").unwrap();
        write!(buffer, "\tfield:unsigned char b;\toffset:1;\tsize:1;\tsigned:0;\n").unwrap();
        write!(buffer, "\tfield:unsigned char c;\toffset:2;\tsize:1;\tsigned:0;\n").unwrap();
        write!(buffer, "\tfield:__dyn_loc char dyn_c[];\toffset:3;\tsize:4;\tsigned:0;\n").unwrap();
        write!(buffer, "\tfield:__rel_loc char rel_c[];\toffset:7;\tsize:4;\tsigned:0;\n").unwrap();
        buffer.flush().unwrap();
        drop(buffer);

        let data = data;
        let mut reader = BufReader::new(data.as_slice());
        let event = TraceFS::event_from_format("unit_test", "test", &mut reader).unwrap();

        assert_eq!("unit_test/test", event.name());
        assert_eq!(123, event.id());

        let format = event.format();
        let fields = format.fields();
        assert_eq!(5, fields.len());

        let a: usize = format.get_field_ref("a").unwrap().into();
        assert_eq!("a", fields[a].name);
        assert_eq!("unsigned char", fields[a].type_name);
        assert!(LocationType::Static == fields[a].location);
        assert_eq!(0, fields[a].offset);
        assert_eq!(1, fields[a].size);

        let b: usize = format.get_field_ref("b").unwrap().into();
        assert_eq!("b", fields[b].name);
        assert_eq!("unsigned char", fields[b].type_name);
        assert!(LocationType::Static == fields[b].location);
        assert_eq!(1, fields[b].offset);
        assert_eq!(1, fields[b].size);

        let c: usize = format.get_field_ref("c").unwrap().into();
        assert_eq!("c", fields[c].name);
        assert_eq!("unsigned char", fields[c].type_name);
        assert!(LocationType::Static == fields[c].location);
        assert_eq!(2, fields[c].offset);
        assert_eq!(1, fields[c].size);

        let dyn_c: usize = format.get_field_ref("dyn_c").unwrap().into();
        assert_eq!("dyn_c", fields[dyn_c].name);
        assert_eq!("char", fields[dyn_c].type_name);
        assert_eq!(LocationType::DynAbsolute, fields[dyn_c].location);
        assert_eq!(3, fields[dyn_c].offset);
        assert_eq!(4, fields[dyn_c].size);

        let rel_c: usize = format.get_field_ref("rel_c").unwrap().into();
        assert_eq!("rel_c", fields[rel_c].name);
        assert_eq!("char", fields[rel_c].type_name);
        assert_eq!(LocationType::DynRelative, fields[rel_c].location);
        assert_eq!(7, fields[rel_c].offset);
        assert_eq!(4, fields[rel_c].size);
    }

    #[test]
    #[ignore]
    fn tracefs_open_find() {
        println!("NOTE: Requires sudo/SYS_CAP_ADMIN/tracefs access.");
        let tracefs = TraceFS::open().unwrap();

        let sched = tracefs.find_event("sched", "sched_waking").unwrap();
        assert_eq!("sched/sched_waking", sched.name());

        let format = sched.format();
        let fields = format.fields();

        /* This field always exists on sched_waking */
        let comm_ref: usize = format.get_field_ref("comm").unwrap().into();
        let comm = &fields[comm_ref];
        assert_eq!("comm", comm.name);
        assert_eq!("char", comm.type_name);
        assert_eq!(16, comm.size);
    }

    #[test]
    #[ignore]
    fn tracefs_uprobe() {
        println!("NOTE: Requires sudo/SYS_CAP_ADMIN/tracefs access.");
        let tracefs = TraceFS::open().unwrap();

        let _ = tracefs.unregister_uprobe(
            "unit_test",
            "malloc");

        #[cfg(all(target_arch = "x86_64"))]
        let possible_paths = [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        #[cfg(all(target_arch = "aarch64"))]
        let possible_paths = [
            "/usr/lib/aarch64-linux-gnu/libc.so.6",
            "/usr/lib/libc.so.6"
        ];

        let libc_path = possible_paths
            .iter()
            .find(|&p| Path::new(p).exists())
            .expect("Could not find libc.so.6 in any expected location");

        #[cfg(all(target_arch = "x86_64"))]
        let event = tracefs.register_uprobe(
            "unit_test",
            "malloc",
            libc_path,
            0x0,
            "size=%di:u64").unwrap();

        #[cfg(all(target_arch = "aarch64"))]
        let event = tracefs.register_uprobe(
            "unit_test",
            "malloc",
            libc_path,
            0x0,
            "size=%x0:u64").unwrap();

        assert!(event.format().get_field_ref("size").is_some());

        tracefs.unregister_uprobe(
            "unit_test",
            "malloc").unwrap();
    }
}
