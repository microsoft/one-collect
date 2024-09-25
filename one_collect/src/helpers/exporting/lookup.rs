use std::collections::HashSet;

pub(crate) struct AddressLookupItem {
    address: u64,
    index: u32,
    valid: bool,
}

impl AddressLookupItem {
    pub fn new(
        address: u64,
        index: u32,
        valid: bool) -> Self {
        Self {
            address,
            index,
            valid,
        }
    }
}

#[derive(Default)]
pub(crate) struct AddressLookup {
    lookup: Vec<AddressLookupItem>,
    index: Vec<u32>,
}

impl AddressLookup {
    pub fn is_empty(&self) -> bool { self.lookup.is_empty() }

    pub fn clear(&mut self) { self.lookup.clear(); }

    pub fn find(
        &mut self,
        address: u64) -> &[u32] {
        let mut index = self.lookup.partition_point(
            |item| item.address <= address);

        index = index.saturating_sub(1);

        self.index.clear();
        self.index.push(self.lookup[index].index);

        let address = self.lookup[index].address;

        while index > 0 {
            index -= 1;

            if self.lookup[index].address == address {
                self.index.push(self.lookup[index].index);
            } else {
                break;
            }
        }

        &self.index
    }

    pub fn update(
        &mut self,
        items: &mut Vec<AddressLookupItem>) {
        let mut index_set = HashSet::new();

        self.lookup.clear();

        items.sort_by(|a,b| a.address.cmp(&b.address));

        for item in items {
            if item.valid {
                index_set.insert(item.index);
            } else {
                index_set.remove(&item.index);
            }

            for index in index_set.iter() {
                self.lookup.push(
                    AddressLookupItem::new(
                        item.address,
                        *index,
                        true));
            }
        }
    }
}
