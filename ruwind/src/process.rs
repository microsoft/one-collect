use super::*;

impl Unwindable for Process {
    fn find<'a>(
        &'a self,
        ip: u64) -> Option<&'a dyn CodeSection> {
        self.find(ip)
    }
}

impl Process {
    pub fn new() -> Self { Self::default() }

    pub fn add_module(
        &mut self,
        module: Module) {
        self.mods.push(module);
        self.sorted = false;
    }

    pub fn fork(&self) -> Self {
        let mut child = Self::new();

        for module in &self.mods {
            child.mods.push(*module);
        }

        child
    }

    pub fn sort(
        &mut self) {
        if !self.sorted {
            self.mods.sort();
            self.sorted = true;
        }
    }

    pub fn find(
        &self,
        ip: u64) -> Option<&dyn CodeSection> {
        if self.mods.is_empty() {
            return None;
        }

        let mut index = self.mods.partition_point(
            |module| module.start <= ip );

        index = index.saturating_sub(1);

        let module = &self.mods[index];

        if module.start <= ip &&
           module.end >= ip {
            return Some(module);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find() {
        let mut proc = Process::new();
        let first = Module::new(1, 1024, 0, 1, 0, UnwindType::DWARF);
        let second = Module::new(1025, 2048, 0, 2, 0, UnwindType::DWARF);
        let third = Module::new(2049, 3072, 0, 3, 0, UnwindType::DWARF);
        proc.add_module(first);
        proc.add_module(second);
        proc.add_module(third);
        proc.sort();

        /* Entirely out of bounds (Start) */
        match proc.find(0) {
            Some(_module) => {
                assert!(false, "Shouldn't have any");
            },
            None => { /* Expected */ },
        }

        /* First module case */
        let found = proc.find(1).unwrap();
        assert!(found.key().dev == 1);

        let found = proc.find(1024).unwrap();
        assert!(found.key().dev == 1);

        /* Second module case */
        let found = proc.find(1025).unwrap();
        assert!(found.key().dev == 2);

        let found = proc.find(2048).unwrap();
        assert!(found.key().dev == 2);

        /* Third module case */
        let found = proc.find(2049).unwrap();
        assert!(found.key().dev == 3);

        let found = proc.find(3072).unwrap();
        assert!(found.key().dev == 3);

        /* Entirely out of bounds (End) */
        match proc.find(3073) {
            Some(_module) => {
                assert!(false, "Shouldn't have any");
            },
            None => { /* Expected */ },
        }
    }
}
