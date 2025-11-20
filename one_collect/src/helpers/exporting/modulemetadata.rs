// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use crate::helpers::exporting::ExportDevNode;
use super::InternedStrings;
use super::pe_file::PEModuleMetadata;

pub enum ModuleMetadata {
    Elf(ElfModuleMetadata),
    PE(PEModuleMetadata),
}

impl ModuleMetadata {
    pub fn to_symbol_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        match self {
            ModuleMetadata::Elf(elf) => {
                elf.to_symbol_metadata(strings, out);
            },

            ModuleMetadata::PE(pe) => {
                pe.to_symbol_metadata(strings, out);
            }
        }
    }

    pub fn to_version_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        match self {
            ModuleMetadata::Elf(elf) => {
                elf.to_version_metadata(strings, out);
            },

            ModuleMetadata::PE(pe) => {
                pe.to_version_metadata(strings, out);
            }
        }
    }
}

pub struct ElfModuleMetadata {
    build_id: Option<[u8; 20]>,
    debug_link_id: usize,
    version_metadata_id: usize,
    p_vaddr: u64,
    p_offset: u64,
}

impl ElfModuleMetadata {
    pub fn new() -> Self {
        Self {
            build_id: None,
            debug_link_id: 0,
            version_metadata_id: 0,
            p_vaddr: 0,
            p_offset: 0,
        }
    }

    pub fn to_symbol_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        out.clear();
        out.push_str("{");
        out.push_str("\"type\": \"ELF\",");

        if let Ok(debug_link) = strings.from_id(self.debug_link_id) {
            out.push_str("\"debug_link\": \"");
            out.push_str(debug_link);
            out.push_str("\",");
        }

        if let Some(build_id) = self.build_id {
            out.push_str("\"build_id\": \"");
            for b in build_id {
                out.push_str(&format!("{:02x}", b));
            }
            out.push_str("\",");
        }

        out.push_str(&format!("\"p_vaddr\": \"0x{:x}\",", self.p_vaddr));
        out.push_str(&format!("\"p_offset\": \"0x{:x}\",", self.p_offset));

        /* Remove trailing comma if it exists */
        if out.ends_with(',') {
            out.pop();
        }

        out.push_str("}");
    }

    pub fn to_version_metadata(
        &self,
        strings: &InternedStrings,
        out: &mut String) {
        out.clear();

        if let Ok(version_metadata) = strings.from_id(self.version_metadata_id) {
            out.push_str(version_metadata);
        } else {
            out.push_str("{}");
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
            Some(link) => { 
                self.debug_link_id = strings.to_id(link.as_str());
            },
            None => { self.debug_link_id = 0 }
        }
    }

    pub fn version_metadata_id(&self) -> usize {
        self.version_metadata_id
    }

    pub fn set_version_metadata(
        &mut self,
        metadata: &str,
        strings: &mut InternedStrings) {
        self.version_metadata_id = strings.to_id(metadata);
    }

    pub fn p_vaddr(&self) -> u64 {
        self.p_vaddr
    }

    pub fn set_p_vaddr(&mut self, p_vaddr: u64) {
        self.p_vaddr = p_vaddr;
    }

    pub fn p_offset(&self) -> u64 {
        self.p_offset
    }

    pub fn set_p_offset(&mut self, p_offset: u64) {
        self.p_offset = p_offset;
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

    #[test]
    fn to_symbol_metadata() {
        let mut strings = InternedStrings::new(8);
        let mut m = ElfModuleMetadata::new();

        m.build_id = Some([1; 20]);
        m.debug_link_id = strings.to_id("debug_link");

        let mut out = String::new();

        m.to_symbol_metadata(&strings, &mut out);

        let mut expected = String::new();

        expected.push_str("{");
        expected.push_str("\"type\": \"ELF\",");
        expected.push_str("\"debug_link\": \"debug_link\",");
        expected.push_str("\"build_id\": \"0101010101010101010101010101010101010101\",");
        expected.push_str("\"p_vaddr\": \"0x0\",");
        expected.push_str("\"p_offset\": \"0x0\"");
        expected.push_str("}");

        assert_eq!(expected, out);
    }

    #[test]
    fn to_version_metadata() {
        let mut strings = InternedStrings::new(8);
        let mut m = ElfModuleMetadata::new();

        let version = "{\"version\": \"1\"}";

        m.version_metadata_id = strings.to_id(version);

        let mut out = String::new();

        m.to_version_metadata(&strings, &mut out);

        assert_eq!(version, out);
    }
}
