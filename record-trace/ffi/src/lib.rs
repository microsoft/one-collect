// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use tracing::{error, warn, info, debug};

use engine::commandline::RecordArgs;
use engine::recorder::Recorder;
use engine::EngineOutput;

const OUTPUT_NORMAL: i32 = 0;
const OUTPUT_LIVE: i32 = 1;
const OUTPUT_ERROR: i32 = 2;
const OUTPUT_PROGRESS: i32 = 3;
const OUTPUT_START: i32 = 4;
const OUTPUT_END: i32 = 5;

type COutputCallback = extern "C" fn(i32, *const u8, usize) -> i32;

#[no_mangle]
extern "C" fn RecordTrace(
    args: *const u8,
    args_len: usize,
    callback: Option<COutputCallback>) -> i32 {
    /* Safety checks */
    if args.is_null() || callback.is_none() {
        warn!("RecordTrace FFI call failed: null args pointer or missing callback");
        return 1;
    }

    info!("RecordTrace FFI call started: args_len={}", args_len);

    let args = unsafe { std::slice::from_raw_parts(args, args_len) };
    let callback = callback.unwrap();

    if let Ok(args) = std::str::from_utf8(args) {
        debug!("Arguments parsed successfully: args={}", args);
        let mut output = EngineOutput::default();

        output.with_normal(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_NORMAL, bytes.as_ptr(), bytes.len())
        });

        output.with_live(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_LIVE, bytes.as_ptr(), bytes.len())
        });

        output.with_error(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_ERROR, bytes.as_ptr(), bytes.len())
        });

        output.with_progress(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_PROGRESS, bytes.as_ptr(), bytes.len())
        });

        output.with_start(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_START, bytes.as_ptr(), bytes.len())
        });

        output.with_end(move |output| {
            let bytes = output.as_bytes();
            callback(OUTPUT_END, bytes.as_ptr(), bytes.len())
        });

        let parser = RecordArgsParser::new(
            "RecordTraceFFI",
            args);

        let mut recorder = Recorder::new(
            RecordArgs::parse(parser),
            output);

        let result = recorder.run();
        info!("RecordTrace FFI call completed: result={}", result);
        result
    } else {
        error!("RecordTrace FFI call failed: invalid UTF-8 in arguments");
        1
    }
}

pub struct RecordArgsParser<'a> {
    binary: &'a str,
    input: &'a str,
    pos: usize,
    first: bool,
}

impl<'a> RecordArgsParser<'a> {
    pub fn new(binary: &'a str, input: &'a str) -> Self {
        Self {
            binary,
            input,
            pos: 0,
            first: true,
        }
    }
}

impl<'a> Iterator for RecordArgsParser<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // First argument is always the "binary"
        if self.first {
            self.first = false;

            return Some(self.binary);
        }

        let bytes = self.input.as_bytes();
        let len = bytes.len();

        // Skip leading whitespace
        while self.pos < len && bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }

        if self.pos >= len {
            return None;
        }

        let start;
        let end;

        if bytes[self.pos] == b'"' {
            // Quoted string
            self.pos += 1; // skip opening quote
            start = self.pos;

            while self.pos < len && bytes[self.pos] != b'"' {
                self.pos += 1;
            }

            end = self.pos;
            self.pos += 1; // skip closing quote
        } else {
            // Unquoted string
            start = self.pos;
            while self.pos < len && !bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            end = self.pos;
        }

        Some(&self.input[start..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parser() {
        let mut parser = RecordArgsParser::new(
            "UnitTest",
            "1 2 3 \"4 5 6\" 7  8  9   \t   10");

        assert_eq!("UnitTest", parser.next().unwrap());
        assert_eq!("1", parser.next().unwrap());
        assert_eq!("2", parser.next().unwrap());
        assert_eq!("3", parser.next().unwrap());
        assert_eq!("4 5 6", parser.next().unwrap());
        assert_eq!("7", parser.next().unwrap());
        assert_eq!("8", parser.next().unwrap());
        assert_eq!("9", parser.next().unwrap());
        assert_eq!("10", parser.next().unwrap());
        assert!(parser.next().is_none());
    }
}
