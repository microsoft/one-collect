use std::io::{BufRead, Seek, SeekFrom};

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
    reader: Option<std::io::BufReader<std::fs::File>>,
    buffer: String,
    current_ip: u64,
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
            next_ip: None,
            next_name: String::with_capacity(64),
            done: true,
        }
    }

    fn load_next(&mut self) {
        /* Swap next with current */
        if let Some(ip) = self.next_ip {
            self.current_ip = ip;
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
                let mut module: &str = "vmlinux";

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
                            module = part;
                        },
                        _ => {},
                    }
                }

                /* Skip non-method symbols */
                if !symtype.starts_with('t') && !symtype.starts_with('T') {
                    continue;
                }

                self.next_ip = Some(addr);
                self.next_name.push_str(module);
                self.next_name.push('!');
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
        if let Some(reader) = &mut self.reader {
            if reader.seek(SeekFrom::Start(0)).is_ok() {
                self.done = false;
                self.load_next();
                return;
            }
        }

        if let Ok(file) = std::fs::File::open("/proc/kallsyms") {
            self.reader = Some(std::io::BufReader::new(file));
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
        if let Some(next_ip) = self.next_ip {
            next_ip - 1
        } else {
            0xFFFFFFFFFFFFFFFF
        }
    }

    fn name(&self) -> &str {
        &self.current_name
    }
}
