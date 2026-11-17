// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Time-scoped tracking of kernel dynamic symbols.
//!
//! Kernel dynamic code (BPF JIT images, BPF trampolines and dispatchers)
//! can be registered and unregistered while a trace is being recorded.
//! `/proc/kallsyms` only describes what is loaded when it is read, which
//! for exports is after recording stops. Code that was unloaded before then
//! would otherwise be unknown, or worse, attributed to whichever symbol
//! happened to precede it in kallsyms at finalization time.
//!
//! [`KernelDynamicSymbols`] records each registration as a generation with
//! an exact extent and a `[load, unload)` lifetime so that samples can be
//! resolved against the code that was actually present when they were taken.

use std::collections::HashMap;

/// The kind of kernel dynamic code a symbol describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelDynamicSymbolKind {
    /// A JIT compiled BPF program (or subprogram).
    Bpf,
    /// Out-of-line kernel code such as BPF trampolines and dispatchers.
    OutOfLine,
    /// A kind this version does not understand.
    Other(u16),
}

impl KernelDynamicSymbolKind {
    /// Converts a `PERF_RECORD_KSYMBOL` `ksym_type` value.
    pub fn from_ksym_type(ksym_type: u16) -> Self {
        match ksym_type {
            1 => { Self::Bpf },
            2 => { Self::OutOfLine },
            other => { Self::Other(other) },
        }
    }
}

/// A single lifetime (generation) of a kernel dynamic symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelDynamicSymbol {
    start: u64,
    len: u64,
    name_id: usize,
    kind: KernelDynamicSymbolKind,
    load_time: u64,
    unload_time: Option<u64>,
    load_observed: bool,
}

impl KernelDynamicSymbol {
    /// First address of the symbol.
    pub fn start(&self) -> u64 { self.start }

    /// Length of the symbol in bytes.
    pub fn len(&self) -> u64 { self.len }

    /// Last address of the symbol (inclusive).
    pub fn end(&self) -> u64 { self.start + self.len - 1 }

    /// First address past the symbol (exclusive).
    pub fn end_exclusive(&self) -> u64 { self.start + self.len }

    pub fn name_id(&self) -> usize { self.name_id }

    pub fn kind(&self) -> KernelDynamicSymbolKind { self.kind }

    /// Time the symbol became valid. Symbols that were already loaded when
    /// tracking began (or whose registration was not observed) use the
    /// earliest time they are known to be valid, which is 0 when unknown.
    pub fn load_time(&self) -> u64 { self.load_time }

    /// Time the symbol stopped being valid (exclusive), if it was unloaded
    /// while being tracked.
    pub fn unload_time(&self) -> Option<u64> { self.unload_time }

    /// Whether the registration of this symbol was observed directly.
    pub fn load_observed(&self) -> bool { self.load_observed }

    pub fn contains(
        &self,
        address: u64) -> bool {
        address >= self.start && address < self.end_exclusive()
    }

    pub fn is_live_at(
        &self,
        time: u64) -> bool {
        time >= self.load_time &&
            self.unload_time.map_or(true, |unload| time < unload)
    }

    fn overlaps(
        &self,
        start: u64,
        end_exclusive: u64) -> bool {
        self.start < end_exclusive && start < self.end_exclusive()
    }
}

/// Diagnostic counters describing how kernel dynamic symbol records were
/// interpreted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelDynamicSymbolStats {
    /// Register records accepted.
    pub registers: u64,
    /// Unregister records that closed an observed registration.
    pub unregisters: u64,
    /// Unregister records without an observed registration. This is
    /// expected for code loaded before tracking began; the symbol is
    /// assumed valid from the latest point it could have been loaded.
    pub unmatched_unregisters: u64,
    /// Open generations closed because new code was registered over them,
    /// which implies their unregister record was lost.
    pub implicit_unloads: u64,
    /// Unregister records whose extent or name did not match the open
    /// generation they closed.
    pub mismatched_unregisters: u64,
    /// Duplicate records (e.g. the same record seen through multiple
    /// perf events), which are ignored.
    pub duplicates: u64,
    /// Records with an empty or overflowing extent, which are ignored so
    /// their addresses stay unknown.
    pub invalid: u64,
}

/// Time-scoped store of kernel dynamic symbols.
#[derive(Default)]
pub struct KernelDynamicSymbols {
    symbols: Vec<KernelDynamicSymbol>,
    open: HashMap<u64, usize>,
    stats: KernelDynamicSymbolStats,
}

impl KernelDynamicSymbols {
    pub fn new() -> Self { Self::default() }

    pub fn is_empty(&self) -> bool { self.symbols.is_empty() }

    /// All generations in the order they were recorded.
    pub fn symbols(&self) -> &[KernelDynamicSymbol] { &self.symbols }

    pub fn stats(&self) -> &KernelDynamicSymbolStats { &self.stats }

    fn valid_extent(
        address: u64,
        len: u64) -> bool {
        len != 0 && address.checked_add(len).is_some()
    }

    fn close(
        &mut self,
        index: usize,
        time: u64) {
        let symbol = &mut self.symbols[index];

        symbol.unload_time = Some(time.max(symbol.load_time));
    }

    /// Records that `name_id` was registered at `[address, address + len)`
    /// at `time`. Records must be supplied in time order.
    pub fn register(
        &mut self,
        time: u64,
        address: u64,
        len: u64,
        kind: KernelDynamicSymbolKind,
        name_id: usize) {
        if !Self::valid_extent(address, len) {
            self.stats.invalid += 1;
            return;
        }

        if let Some(index) = self.open.get(&address) {
            let existing = &self.symbols[*index];

            if existing.load_time == time &&
               existing.len == len &&
               existing.name_id == name_id {
                self.stats.duplicates += 1;
                return;
            }
        }

        /*
         * Any open generation overlapping the new code must have been
         * unloaded already; its unregister record was lost. Close it now so
         * it cannot be attributed beyond this point.
         */
        let end_exclusive = address + len;
        let mut stale = Vec::new();

        for (start, index) in &self.open {
            if self.symbols[*index].overlaps(address, end_exclusive) {
                stale.push((*start, *index));
            }
        }

        for (start, index) in stale {
            self.open.remove(&start);
            self.close(index, time);
            self.stats.implicit_unloads += 1;
        }

        self.open.insert(address, self.symbols.len());

        self.symbols.push(
            KernelDynamicSymbol {
                start: address,
                len,
                name_id,
                kind,
                load_time: time,
                unload_time: None,
                load_observed: true,
            });

        self.stats.registers += 1;
    }

    /// Records that the symbol at `[address, address + len)` was
    /// unregistered at `time`. Records must be supplied in time order.
    pub fn unregister(
        &mut self,
        time: u64,
        address: u64,
        len: u64,
        kind: KernelDynamicSymbolKind,
        name_id: usize) {
        if !Self::valid_extent(address, len) {
            self.stats.invalid += 1;
            return;
        }

        if let Some(index) = self.open.remove(&address) {
            let existing = &self.symbols[index];

            if existing.len != len || existing.name_id != name_id {
                self.stats.mismatched_unregisters += 1;
            }

            self.close(index, time);
            self.stats.unregisters += 1;
            return;
        }

        let end_exclusive = address + len;
        let mut load_time = 0;

        for symbol in &self.symbols {
            if !symbol.overlaps(address, end_exclusive) {
                continue;
            }

            if symbol.start == address &&
               symbol.unload_time == Some(time) &&
               symbol.len == len &&
               symbol.name_id == name_id {
                self.stats.duplicates += 1;
                return;
            }

            /*
             * Without a registration, the code can only have been loaded
             * after anything previously seen at these addresses went away.
             */
            if let Some(unload) = symbol.unload_time {
                if unload <= time {
                    load_time = load_time.max(unload);
                }
            }
        }

        self.symbols.push(
            KernelDynamicSymbol {
                start: address,
                len,
                name_id,
                kind,
                load_time,
                unload_time: Some(time),
                load_observed: false,
            });

        self.stats.unmatched_unregisters += 1;
    }

    /// Finds the generation containing `address` that was live at `time`.
    pub fn find(
        &self,
        address: u64,
        time: u64) -> Option<&KernelDynamicSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.contains(address) && symbol.is_live_at(time))
            .max_by_key(|symbol| symbol.load_time)
    }

    /// Whether `address` lies inside any recorded generation.
    pub fn any_contains(
        &self,
        address: u64) -> bool {
        self.symbols.iter().any(|symbol| symbol.contains(address))
    }

    /// Whether `address` lies inside a generation still loaded at the end
    /// of tracking.
    pub fn open_contains(
        &self,
        address: u64) -> bool {
        self.open
            .values()
            .any(|index| self.symbols[*index].contains(address))
    }

    /// Clips an inclusive `[start, end]` range so that it does not extend
    /// into any recorded generation that starts after `start`, nor past the
    /// end of a generation containing `start`.
    pub fn clip_end(
        &self,
        start: u64,
        end: u64) -> u64 {
        let mut end = end;

        for symbol in &self.symbols {
            if symbol.start > start {
                if symbol.start <= end {
                    end = symbol.start - 1;
                }
            } else if symbol.contains(start) {
                end = end.min(symbol.end());
            }
        }

        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: u64 = 0xffffffffc0000000;
    const SEC: u64 = 1_000_000_000;

    fn names(symbols: &KernelDynamicSymbols, address: u64, time: u64) -> Option<usize> {
        symbols.find(address, time).map(|symbol| symbol.name_id())
    }

    #[test]
    fn address_reuse_is_time_scoped() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.register(SEC, X, 256, bpf, 1);
        symbols.unregister(2 * SEC, X, 256, bpf, 1);
        symbols.register(3 * SEC, X, 128, bpf, 2);
        symbols.unregister(4 * SEC, X, 128, bpf, 2);

        let at = X + 64;
        assert_eq!(None, names(&symbols, at, SEC / 2));
        assert_eq!(Some(1), names(&symbols, at, SEC + SEC / 2));
        assert_eq!(None, names(&symbols, at, 2 * SEC));
        assert_eq!(None, names(&symbols, at, 2 * SEC + SEC / 2));
        assert_eq!(Some(2), names(&symbols, at, 3 * SEC + SEC / 2));
        assert_eq!(None, names(&symbols, at, 4 * SEC));

        /* Exclusive end of B, but still inside A's old extent */
        assert_eq!(None, names(&symbols, X + 128, 3 * SEC + SEC / 2));
        assert_eq!(Some(1), names(&symbols, X + 128, SEC + SEC / 2));
        assert_eq!(None, names(&symbols, X + 256, SEC + SEC / 2));
        assert_eq!(None, names(&symbols, X - 1, SEC + SEC / 2));

        assert_eq!(2, symbols.stats().registers);
        assert_eq!(2, symbols.stats().unregisters);
    }

    #[test]
    fn unload_without_register_is_valid_until_unload() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.unregister(5 * SEC, X, 64, bpf, 7);

        assert_eq!(Some(7), names(&symbols, X, 0));
        assert_eq!(Some(7), names(&symbols, X + 63, 5 * SEC - 1));
        assert_eq!(None, names(&symbols, X, 5 * SEC));
        assert!(!symbols.symbols()[0].load_observed());
        assert_eq!(1, symbols.stats().unmatched_unregisters);
    }

    #[test]
    fn unmatched_unregister_starts_after_prior_occupant() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.register(SEC, X, 256, bpf, 1);
        symbols.unregister(2 * SEC, X, 256, bpf, 1);
        /* Register of the second program was lost */
        symbols.unregister(4 * SEC, X + 16, 32, bpf, 2);

        assert_eq!(Some(1), names(&symbols, X + 20, SEC + 1));
        assert_eq!(Some(2), names(&symbols, X + 20, 3 * SEC));
        assert_eq!(2 * SEC, symbols.symbols()[1].load_time());
    }

    #[test]
    fn register_over_open_generation_closes_it() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.register(SEC, X, 256, bpf, 1);
        /* Unregister of the first program was lost */
        symbols.register(3 * SEC, X + 128, 64, bpf, 2);

        assert_eq!(Some(1), names(&symbols, X + 130, 2 * SEC));
        assert_eq!(Some(2), names(&symbols, X + 130, 3 * SEC));
        assert_eq!(None, names(&symbols, X, 3 * SEC));
        assert_eq!(1, symbols.stats().implicit_unloads);
        assert!(!symbols.open_contains(X));
        assert!(symbols.open_contains(X + 128));
    }

    #[test]
    fn duplicates_and_invalid_records_are_ignored() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.register(SEC, X, 64, bpf, 1);
        symbols.register(SEC, X, 64, bpf, 1);
        symbols.unregister(2 * SEC, X, 64, bpf, 1);
        symbols.unregister(2 * SEC, X, 64, bpf, 1);
        symbols.register(SEC, X, 0, bpf, 1);
        symbols.register(SEC, u64::MAX - 1, 16, bpf, 1);

        assert_eq!(1, symbols.symbols().len());
        assert_eq!(2, symbols.stats().duplicates);
        assert_eq!(2, symbols.stats().invalid);
        assert_eq!(Some(1), names(&symbols, X, SEC));
        assert_eq!(None, names(&symbols, X, 2 * SEC));
    }

    #[test]
    fn clip_end_stops_at_dynamic_code() {
        let bpf = KernelDynamicSymbolKind::Bpf;
        let mut symbols = KernelDynamicSymbols::new();

        symbols.register(SEC, X, 64, bpf, 1);
        symbols.unregister(2 * SEC, X, 64, bpf, 1);

        /* A preceding static symbol whose inferred extent covers X */
        assert_eq!(X - 1, symbols.clip_end(X - 0x100, X + 0x1000));
        /* A static symbol starting inside the extent is clipped to it */
        assert_eq!(X + 63, symbols.clip_end(X + 8, X + 0x1000));
        /* Unrelated symbols are untouched */
        assert_eq!(X + 0x2000, symbols.clip_end(X + 0x1000, X + 0x2000));
    }
}
