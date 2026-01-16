// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod commandline;
pub mod recorder;
pub mod logger;
mod export;

pub type EngineOutputCallback = dyn Fn(&str) -> i32 + Send + Sync;

pub struct EngineOutput {
    on_live: Box<EngineOutputCallback>,
    on_normal: Box<EngineOutputCallback>,
    on_error: Box<EngineOutputCallback>,
    on_start: Box<EngineOutputCallback>,
    on_end: Box<EngineOutputCallback>,
    on_progress: Box<EngineOutputCallback>,
}

impl Default for EngineOutput {
    fn default() -> Self {
        EngineOutput {
            on_live: Box::new(Self::default_normal),
            on_normal: Box::new(Self::default_normal),
            on_error: Box::new(Self::default_error),
            on_start: Box::new(Self::default_normal),
            on_end: Box::new(Self::default_normal),
            on_progress: Box::new(|_| { 0 }),
        }
    }
}

impl EngineOutput {
    fn default_normal(output: &str) -> i32 {
        println!("{}", output);
        0
    }

    fn default_error(output: &str) -> i32 {
        eprintln!("{}", output);
        0
    }

    pub fn with_live(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_live = Box::new(callback);
    }

    pub fn with_normal(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_normal = Box::new(callback);
    }

    pub fn with_error(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_error = Box::new(callback);
    }

    pub fn with_progress(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_progress = Box::new(callback);
    }

    pub fn with_start(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_start = Box::new(callback);
    }

    pub fn with_end(
        &mut self,
        callback: impl Fn(&str) -> i32 + 'static + Send + Sync) {
        self.on_end = Box::new(callback);
    }

    fn live(&self, output: &str) -> i32 { (self.on_live)(output) }

    fn normal(&self, output: &str) -> i32 { (self.on_normal)(output) }

    fn error(&self, output: &str) -> i32 { (self.on_error)(output) }

    fn progress(&self, output: &str) -> i32 { (self.on_progress)(output) }

    fn start(&self, output: &str) -> i32 { (self.on_start)(output) }

    fn end(&self, output: &str) -> i32 { (self.on_end)(output) }
}
