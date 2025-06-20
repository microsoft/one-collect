use super::*;

#[derive(Default)]
pub struct ExportSpan {
    name_id: usize,
    start_time: u64,
    end_time: u64,
    children: Vec<ExportSpan>,
}

impl ExportSpan {
    pub fn start(
        name_id: usize,
        start_time: u64,
        capacity: usize) -> Self {
        Self {
            name_id,
            start_time,
            end_time: start_time,
            children: Vec::with_capacity(capacity),
        }
    }

    pub fn name<'a>(
        &self,
        strings: &'a InternedStrings) -> &'a str {
        strings.from_id(self.name_id).unwrap_or_default()
    }

    pub fn name_id(&self) -> usize { self.name_id }

    pub fn start_time(&self) -> u64 { self.start_time }

    pub fn start_time_mut(&mut self) -> &mut u64 { &mut self.start_time }

    pub fn end_time(&self) -> u64 { self.end_time }

    pub fn end_time_mut(&mut self) -> &mut u64 { &mut self.end_time }

    pub fn children(&self) -> &[ExportSpan] { &self.children }

    pub fn children_mut(&mut self) -> &mut [ExportSpan] { &mut self.children }

    pub fn qpc_duration(&self) -> u64 {
        self.end_time - self.start_time
    }

    pub fn mark_last_child_end(
        &mut self,
        end_time: u64) {
        if let Some(last) = self.children.last_mut() {
            last.mark_end(end_time);
        }
    }

    pub fn mark_end(
        &mut self,
        end_time: u64) {
        self.end_time = end_time;
        self.children.shrink_to_fit();
    }

    pub fn add_child(
        &mut self,
        span: ExportSpan) {
        self.children.push(span);
    }
}
