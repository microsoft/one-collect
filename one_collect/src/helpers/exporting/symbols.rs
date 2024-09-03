use std::{fs::File, io::{BufRead, BufReader, Seek, SeekFrom}};
use ruwind::elf::{ElfSymbol, ElfSymbolIterator};

#[derive(Clone)]
pub struct ExportSymbol {
    name_id: usize,
    start: u64,
    end: u64,
}

impl ExportSymbol {
    pub fn new(
        name_id: usize,
        start: u64,
        end: u64) -> Self {
        Self {
            name_id,
            start,
            end,
        }
    }

    pub fn name_id(&self) -> usize { self.name_id }

    pub fn start(&self) -> u64 { self.start }

    pub fn end(&self) -> u64 { self.end }
}

pub trait ExportSymbolReader {
    fn reset(&mut self);

    fn next(&mut self) -> bool;

    fn start(&self) -> u64;

    fn end(&self) -> u64;

    fn name(&self) -> &str;
}

pub struct KernelSymbolReader {
    reader: Option<BufReader<File>>,
    buffer: String,
    current_ip: u64,
    current_end: Option<u64>,
    current_name: String,
    next_ip: Option<u64>,
    next_name: String,
    done: bool,
}

impl KernelSymbolReader {
    pub fn new() -> Self {
        Self {
            reader: None,
            buffer: String::with_capacity(64),
            current_name: String::with_capacity(64),
            current_ip: 0,
            current_end: None,
            next_ip: None,
            next_name: String::with_capacity(64),
            done: true,
        }
    }

    pub fn set_file(
        &mut self,
        file: File) {
        self.reader = Some(BufReader::new(file));
        self.reset()
    }

    fn load_next(&mut self) {
        /* Swap next with current */
        if let Some(ip) = self.next_ip {
            self.current_ip = ip;
            self.current_end = None;
            self.current_name.clear();
            self.current_name.push_str(&self.next_name);

            self.next_ip = None;
            self.next_name.clear();
        }

        /* Load in new next */
        if let Some(reader) = &mut self.reader {
            loop {
                self.buffer.clear();

                if let Ok(len) = reader.read_line(&mut self.buffer) {
                    if len == 0 {
                        break;
                    }
                } else {
                    break;
                }

                let mut addr: u64 = 0;
                let mut symtype: &str = "";
                let mut method: &str = "";
                let mut module: Option<&str> = None;

                for (index, part) in self.buffer.split_whitespace().enumerate() {
                    match index {
                        0 => {
                            addr = u64::from_str_radix(part, 16).unwrap();
                        },
                        1 => {
                            symtype = part;
                        },
                        2 => {
                            method = part;
                        },
                        3 => {
                            module = Some(part);
                        },
                        _ => {},
                    }
                }

                if self.current_end.is_none() && self.current_ip != 0 {
                    self.current_end = Some(addr - 1);
                }

                /* Skip non-method symbols */
                if !symtype.starts_with('t') && !symtype.starts_with('T') {
                    continue;
                }

                self.next_ip = Some(addr);
                if let Some(module) = module {
                    self.next_name.push_str(module);
                    self.next_name.push_str(" ");
                }
                self.next_name.push_str(method);
                self.done = false;

                return;
            }
        }

        self.done = true;
    }
}

impl ExportSymbolReader for KernelSymbolReader {
    fn reset(&mut self) {
        self.current_ip = 0;
        self.current_end = None;
        self.next_ip = None;

        if let Some(reader) = &mut self.reader {
            if reader.seek(SeekFrom::Start(0)).is_ok() {
                self.done = false;
                self.load_next();
                return;
            }
        }

        if let Ok(file) = File::open("/proc/kallsyms") {
            self.reader = Some(BufReader::new(file));
            self.done = false;
            self.load_next();
        }
    }

    fn next(&mut self) -> bool {
        if self.done {
            return false;
        }

        self.load_next();

        true
    }

    fn start(&self) -> u64 {
        self.current_ip
    }

    fn end(&self) -> u64 {
        match self.current_end {
            Some(end) => { end },
            None => { 0xFFFFFFFFFFFFFFFF },
        }
    }

    fn name(&self) -> &str {
        &self.current_name
    }
}

pub struct ElfSymbolReader<'a> {
    iterator: ElfSymbolIterator<'a>,
    current_sym: ElfSymbol,
    current_sym_valid: bool,
}

impl<'a> ElfSymbolReader<'a> {
    pub fn new(file: File) -> Self {
        Self {
            iterator: ElfSymbolIterator::new(file),
            current_sym: ElfSymbol::new(),
            current_sym_valid: false,
        }
    }
}

impl<'a> ExportSymbolReader for ElfSymbolReader<'a> {
    fn reset(&mut self) {
        self.iterator.reset();
        self.current_sym_valid = false;
    }

    fn next(&mut self) -> bool {
        self.current_sym_valid = self.iterator.next(&mut self.current_sym);
        self.current_sym_valid
    }

    fn start(&self) -> u64 {
        let mut start = 0u64;
        if self.current_sym_valid {
            start = self.current_sym.start();
        }
        start
    }

    fn end(&self) -> u64 {
        let mut end = 0u64;
        if self.current_sym_valid {
            end = self.current_sym.end();
        }
        end
    }

    fn name(&self) -> &str {
        let mut name = "";
        if self.current_sym_valid {
            name = self.current_sym.name();
        }
        name
    }
}

pub struct PerfMapSymbolReader {
    reader: BufReader<File>,
    buffer: String,
    start_ip: u64,
    end_ip: u64,
    name: String,
    done: bool,
}

impl PerfMapSymbolReader {
    pub fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
            buffer: String::with_capacity(256),
            name: String::with_capacity(256),
            start_ip: 0,
            end_ip: 0,
            done: true,
        }
    }

    fn load_next(&mut self) {
        loop {
            self.buffer.clear();

            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();

            if let Ok(len) = self.reader.read_line(&mut self.buffer) {
                if len == 0 {
                    break;
                }
            } else {
                break;
            }

            for (index, part) in self.buffer.splitn(3, ' ').enumerate() {
                match index {
                    0 => {
                        if part.starts_with("0x") || part.starts_with("0X") {
                            self.start_ip = u64::from_str_radix(&part[2..], 16).unwrap();
                        }
                        else {
                            self.start_ip = u64::from_str_radix(part, 16).unwrap();
                        }
                    },
                    1 => {
                        let size = u64::from_str_radix(part, 16).unwrap();
                        self.end_ip = self.start_ip + size;
                    },
                    _ => {
                        /*
                         * Symbols sometimes have nulls in them. When we see
                         * this we'll just use up to the null as the name.
                         */
                        let part = part.split('\0').next().unwrap();

                        self.name.push_str(part);
                        if self.name.ends_with("\n") {
                            self.name.pop();
                        }
                    },
                }
            }

            self.done = false;

            return;
        }

        self.done = true;
    }
}

impl ExportSymbolReader for PerfMapSymbolReader {
    fn reset(&mut self) {
        if self.reader.seek(SeekFrom::Start(0)).is_ok() {
            self.done = false;
            return;
        }
        else {
            // If we fail to seek to the start of the file,
            // set the values to their defaults and set
            // done = true to prevent further reading.
            self.start_ip = 0;
            self.end_ip = 0;
            self.name.clear();
            self.done = true;
        }
    }

    fn next(&mut self) -> bool {
        if self.done {
            return false;
        }

        self.load_next();

        if self.done {
            return false;
        }

        true
    }

    fn start(&self) -> u64 {
        self.start_ip
    }

    fn end(&self) -> u64 {
        self.end_ip
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_symbol_reader() {
        let kern_syms_path = std::env::current_dir().unwrap().join(
            "../test/assets/kernel/symbols.map");

        let mut reader = KernelSymbolReader::new();

        reader.set_file(File::open(kern_syms_path).unwrap());

        for _ in 0..4 {
            /* method1 */
            assert!(reader.next());
            assert_eq!(0x0A, reader.start());
            assert_eq!(0xA9, reader.end());
            assert_eq!("method1", reader.name());

            /* method2 */
            assert!(reader.next());
            assert_eq!(0xAC, reader.start());
            assert_eq!(0xBA, reader.end());
            assert_eq!("[module] method2", reader.name());

            /* method3 */
            assert!(reader.next());
            assert_eq!(0xBB, reader.start());
            assert_eq!(0xFFFFFFFFFFFFFFFF, reader.end());
            assert_eq!("method3", reader.name());

            /* End */
            assert!(!reader.next());

            /* Reset */
            reader.reset();
        }
    }

    #[test]
    fn perf_map_symbol_reader() {
        let expected_count = 2435;
        let perf_map_path = std::env::current_dir().unwrap().join(
            "../test/assets/perfmap/dotnet-info.map");

        if let Ok(file) = File::open(perf_map_path.clone()) {
            let mut reader = PerfMapSymbolReader::new(file);
            reader.reset();

            let mut actual_count = 0;
            loop {
                if !reader.next() {
                    break;
                }

                actual_count+=1;
                assert!(reader.start() < reader.end(), "Start must be less than end - start: {}, end: {}", reader.start(), reader.end());
                assert!(reader.name().len() > 0);

                // Check for a few known symbols.
                match reader.start() {
                    0x00007F148458E6A0 => {
                        assert_eq!(0x00007F148458E6A0 + 0x1B0, reader.end());
                        assert_eq!(reader.name(), "int32 [System.Private.CoreLib] System.SpanHelpers::IndexOf(char&,char,int32)[OptimizedTier1]");
                    },
                    0x00007F1484597400 => {
                        assert_eq!(0x00007F1484597400 + 0x121, reader.end());
                        assert_eq!(reader.name(), "native uint [System.Private.CoreLib] System.Text.ASCIIUtility::NarrowUtf16ToAscii(char*,uint8*,native uint)[Optimized]");
                    },
                    0x00007F1484F65380 => {
                        assert_eq!(0x00007F1484F65380 + 0x17e, reader.end());
                        assert_eq!(reader.name(), "instance bool [System.Linq] System.Linq.Enumerable+SelectListIterator`2[Microsoft.Extensions.DependencyModel.DependencyContextJsonReader+TargetLibrary,System.__Canon]::MoveNext()[QuickJitted]")
                    },
                    _ => {},
                }
            }

            assert_eq!(actual_count, expected_count);
        }
        else {
            assert!(false, "Unable to open file {}", perf_map_path.display());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn elf_symbol_reader() {
        #[cfg(target_arch = "x86_64")]
        let path = "/usr/lib/x86_64-linux-gnu/libc.so.6";

        #[cfg(target_arch = "aarch64")]
        let path = "/usr/lib/aarch64-linux-gnu/libc.so.6";

        if let Ok(file) = File::open(path) {
            let mut reader = ElfSymbolReader::new(file);
            reader.reset();

            let mut actual_count = 0;
            loop {
                if !reader.next() {
                    break;
                }

                actual_count+=1;
                assert!(reader.start() <= reader.end(), "Start must be less than or equal to end - start: {}, end: {}", reader.start(), reader.end());
                assert!(reader.name().len() > 0);
            }

            assert!(actual_count > 0);
        }
        else {
            assert!(false, "Unable to open file {}", path);
        }
    }
}
