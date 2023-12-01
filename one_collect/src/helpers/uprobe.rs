use ruwind::elf::{self};
use std::fs::File;
use anyhow::Result;

use crate::procfs::*;

pub struct UProbe<'a> {
    probe_type: &'a str,
    name: &'a str,
    address: u64,
}

impl<'a> UProbe<'a> {
    fn new(
        probe_type: &'a str,
        name: &'a str,
        address: u64) -> Self {
        Self {
            probe_type,
            name,
            address,
        }
    }

    pub fn probe_type(&self) -> &str { self.probe_type }

    pub fn name(&self) -> &str { self.name }
    
    pub fn address(&self) -> u64 { self.address }
}

pub fn enum_uprobes(
    file_name: &str,
    mut callback: impl FnMut(&UProbe)) -> Result<()> {
    let mut file = File::open(file_name)?;
    let mut sections = Vec::new();

    /* Get symbol sections */
    elf::get_section_metadata(&mut file, None, 0x2, &mut sections)?;
    elf::get_section_metadata(&mut file, None, 0xb, &mut sections)?;

    /* Get symbols from those sections and pass to caller */
    elf::get_symbols(&mut file, &sections, move |symbol| {
        let probe = UProbe::new(
            "Func",
            symbol.name,
            symbol.start);

        callback(&probe);
    })?;

    Ok(())
}

pub fn enum_uprobe_procs(
    mut callback: impl FnMut(u32, &str)) {
    iter_processes(|pid,path| {
        if let Some(name) = get_comm(path) {
            callback(pid, &name);
        }
    });
}

pub fn enum_uprobe_modules(
    pid: u32,
    mut callback: impl FnMut(&str)) {
    iter_proc_modules(pid, |module| {
        if let Some(path) = module.path {
            if !path.starts_with("[") {
                callback(path);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_uprobes_helper() {
        #[cfg(target_arch = "x86_64")]
        let path = "/usr/lib/x86_64-linux-gnu/libc.so.6";

        #[cfg(target_arch = "aarch64")]
        let path = "/usr/lib/aarch64-linux-gnu/libc.so.6";

        let mut found = false;

        enum_uprobes(path, |probe| {
            if probe.name == "malloc" {
                found = true;
            }
        }).unwrap();

        assert!(found);
    }

    #[test]
    fn enum_uprobe_procs_helper() {
        let mut count = 0u64;

        enum_uprobe_procs(|pid,name| {
            println!("{}: {}", pid, name);
            count += 1;
        });

        assert!(count != 0);
    }
    
    #[test]
    fn enum_uprobe_modules_helper() {
        let mut count = 0u64;

        enum_uprobe_modules(0, |path| {
            println!("{}", path);
            count += 1;
        });

        assert!(count != 0);
    }
}
