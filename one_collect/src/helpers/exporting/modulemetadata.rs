use std::collections::HashMap;
use std::collections::hash_map::Entry;
use crate::helpers::exporting::ExportDevNode;
use super::InternedStrings;
use super::pe_file::PEModuleMetadata;

pub enum ModuleMetadata {
    Elf(ElfModuleMetadata),
    PE(PEModuleMetadata),
}

pub struct ElfModuleMetadata {
    build_id: Option<[u8; 20]>,
    debug_link_id: usize,
}

impl ElfModuleMetadata {
    pub fn new() -> Self {
        Self {
            build_id: None,
            debug_link_id: 0,
        }
    }

    pub fn build_id(&self) -> Option<&[u8; 20]> {
        self.build_id.as_ref()
    }

    pub fn set_build_id(
        &mut self,
        build_id: Option<&[u8; 20]>) {
        self.build_id = build_id.copied();
    }

    pub fn debug_link_id(&self) -> usize {
        self.debug_link_id
    }

    pub fn debug_link<'a>(&self, strings: &'a InternedStrings) -> Option<&'a str> {
        match strings.from_id(self.debug_link_id) {
            Ok(link) => Some(link),
            Err(_) => None,
        }
    }

    pub fn set_debug_link(
        &mut self,
        debug_link: Option<String>,
        strings: &mut InternedStrings) {
        match debug_link {
            Some(link) => { self.debug_link_id = strings.to_id(link.as_str()) },
            None => { self.debug_link_id = 0 }
        }
    }
}

pub struct ModuleMetadataLookup {
    metadata: HashMap<ExportDevNode, ModuleMetadata>
}

impl ModuleMetadataLookup {
    pub fn new() -> Self {
        Self {
            metadata: HashMap::new()
        }
    }

    pub fn contains(
        &self,
        key: &ExportDevNode) -> bool {
        self.metadata.contains_key(key)
    }

    pub fn entry(
        &mut self,
        key: ExportDevNode) -> Entry<'_, ExportDevNode, ModuleMetadata> {
        self.metadata.entry(key)
    }

    pub fn get(
        &self,
        key: &ExportDevNode) -> Option<&ModuleMetadata> {
        self.metadata.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn elf_module_metadata_lookup() {
        let mut strings = InternedStrings::new(8);
        let mut metadata_lookup = ModuleMetadataLookup::new();

        let dev_node_1 = ExportDevNode::new(1,2);
        assert!(!metadata_lookup.contains(&dev_node_1));
        let entry = metadata_lookup.entry(dev_node_1)
            .or_insert(ModuleMetadata::Elf(ElfModuleMetadata::new()));

        let symbol_file_path = "/path/to/symbol/file";
        if let ModuleMetadata::Elf(metadata) = entry {
            metadata.set_debug_link(Some(String::from_str(symbol_file_path).unwrap()), &mut strings);
        }

        assert!(metadata_lookup.contains(&dev_node_1));
        let result = metadata_lookup.get(&dev_node_1).unwrap();
        match result {
            ModuleMetadata::Elf(metadata) => {
                match metadata.debug_link(&strings) {
                    Some(path) => assert_eq!(path, symbol_file_path),
                    None => assert!(false)
                }
            }
            ModuleMetadata::PE(_) => {
                assert!(false)
            }
        }

        let dev_node_2 = ExportDevNode::new(2, 3);
        assert!(!metadata_lookup.contains(&dev_node_2));
        assert!(metadata_lookup.contains(&dev_node_1));
    }
}