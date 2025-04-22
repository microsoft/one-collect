use std::collections::HashMap;

use super::*;
use crate::event::*;

impl DotNetScenario {
    pub fn build_runtime(builder: &mut TypeBuilder<Self>) {
        builder
            .with_fn("with_exceptions", Self::with_exceptions)
            .with_fn("with_gc_times", Self::with_gc_times)
            .with_fn("with_gc_stats", Self::with_gc_stats)
            .with_fn("with_gc_allocs", Self::with_gc_allocs)
            .with_fn("with_gc_segments", Self::with_gc_segments)
            .with_fn("with_gc_concurrent_threads", Self::with_gc_concurrent_threads)
            .with_fn("with_gc_finalizers", Self::with_gc_finalizers)
            .with_fn("with_gc_suspends", Self::with_gc_suspends)
            .with_fn("with_gc_restarts", Self::with_gc_restarts)
            .with_fn("with_contentions", Self::with_contentions);
    }

    pub fn runtime_samples(&self) -> HashMap<u16, DotNetSample> {
        let mut samples = HashMap::new();

        let record = self.record;

        for event in self.runtime.events() {
            let mut sample = match event.id {
                1 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCStart".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 4;
                    format.add_field(EventField::new(
                        "Count".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Depth".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Reason".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Type".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                2 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCEnd".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 4;
                    format.add_field(EventField::new(
                        "Count".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Depth".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                4 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCHeapStats".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 8;
                    format.add_field(EventField::new(
                        "GenerationSize0".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "TotalPromotedSize0".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "GenerationSize1".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "TotalPromotedSize1".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "GenerationSize2".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "TotalPromotedSize2".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "GenerationSize3".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "TotalPromotedSize3".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "FinalizationPromotedSize".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "FinalizationPromotedCount".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 4;
                    format.add_field(EventField::new(
                        "PinnedObjectCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "SinkBlockCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "GCHandleCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 8;
                    format.add_field(EventField::new(
                        "GenerationSize4".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "TotalPromotedSize4".into(), "u64".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                5 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCCreateSegment".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 8;
                    format.add_field(EventField::new(
                        "Address".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Size".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 4;
                    format.add_field(EventField::new(
                        "Type".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                6 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCFreeSegment".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 8;
                    format.add_field(EventField::new(
                        "Address".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                7 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCRestartEEBegin".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                3 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCRestartEEEnd".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                9 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCSuspendEE".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 2;
                    format.add_field(EventField::new(
                        "Reason".into(), "u16".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 4;
                    format.add_field(EventField::new(
                        "Count".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                8 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCSuspendEEEnd".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                10 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCAllocationTick".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 4;
                    format.add_field(EventField::new(
                        "AllocationAmount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "AllocationKind".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 8;
                    let sample_start = offset;
                    format.add_field(EventField::new(
                        "AllocationAmount64".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;
                    let sample_end = offset;

                    format.add_field(EventField::new(
                        "TypeId".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 0;
                    format.add_field(EventField::new(
                        "TypeName".into(), "wchar".into(),
                        LocationType::StaticUTF16String, offset, len));

                    len = 4;
                    format.add_field(EventField::new(
                        "HeapIndex".into(), "u32".into(),
                        LocationType::Static, offset, len));

                    len = 8;
                    format.add_field(EventField::new(
                        "Address".into(), "u64".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[sample_start..sample_end].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Bytes(value))
                        }),
                        record,
                    }
                },

                14 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCFinalizersBegin".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                13 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "GCFinalizersEnd".into());

                    let format = event.format_mut();
                    let mut len: usize;
                    let mut offset = 0;

                    len = 4;
                    format.add_field(EventField::new(
                        "Count".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                11 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCCreateConcurrentThread".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                12 => {
                    let event = Event::new(
                        event.id.into(),
                        "GCTerminateConcurrentThread".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                80 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "ExceptionThrown".into());

                    let format = event.format_mut();
                    let offset = 0;
                    let mut len = 0;

                    format.add_field(EventField::new(
                        "ExceptionType".into(), "wchar".into(),
                        LocationType::StaticUTF16String, offset, len));

                    format.add_field(EventField::new(
                        "ExceptionMessage".into(), "wchar".into(),
                        LocationType::StaticUTF16String, offset, len));

                    len = 8;
                    format.add_field(EventField::new(
                        "EIPCodeThrow".into(), "u64".into(),
                        LocationType::Static, offset, len));

                    len = 4;
                    format.add_field(EventField::new(
                        "ExceptionHR".into(), "u32".into(),
                        LocationType::Static, offset, len));

                    len = 2;
                    format.add_field(EventField::new(
                        "ExceptionFlags".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                81 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "ContentionStart".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 1;
                    format.add_field(EventField::new(
                        "Flags".into(), "u8".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                91 => {
                    let mut event = Event::new(
                        event.id.into(),
                        "ContentionStop".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 1;
                    format.add_field(EventField::new(
                        "Flags".into(), "u8".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                _ => { continue; },
            };

            if !self.callstacks {
                sample.event.set_no_callstack_flag();
            }

            samples.insert(event.id, sample);
        }

        samples
    }

    pub fn with_contentions(&mut self) {
        /* Start */
        self.runtime.add(
            DotNetEvent {
                id: 81,
                keywords: 0x4000,
                level: 4,
            });

        /* Stop */
        self.runtime.add(
            DotNetEvent {
                id: 91,
                keywords: 0x4000,
                level: 4,
            });
    }

    pub fn with_exceptions(&mut self) {
        self.runtime.add(
            DotNetEvent {
                id: 80,
                keywords: 0x8000,
                level: 2,
            });
    }

    pub fn with_gc_finalizers(&mut self) {
        /* Start */
        self.runtime.add(
            DotNetEvent {
                id: 14,
                keywords: 0x1,
                level: 4,
            });

        /* End */
        self.runtime.add(
            DotNetEvent {
                id: 13,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_suspends(&mut self) {
        /* Start */
        self.runtime.add(
            DotNetEvent {
                id: 9,
                keywords: 0x1,
                level: 4,
            });

        /* End */
        self.runtime.add(
            DotNetEvent {
                id: 8,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_restarts(&mut self) {
        /* Start */
        self.runtime.add(
            DotNetEvent {
                id: 7,
                keywords: 0x1,
                level: 4,
            });

        /* End */
        self.runtime.add(
            DotNetEvent {
                id: 3,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_concurrent_threads(&mut self) {
        /* Create */
        self.runtime.add(
            DotNetEvent {
                id: 11,
                keywords: 0x1,
                level: 4,
            });

        /* Terminate */
        self.runtime.add(
            DotNetEvent {
                id: 12,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_segments(&mut self) {
        /* Create */
        self.runtime.add(
            DotNetEvent {
                id: 5,
                keywords: 0x1,
                level: 4,
            });

        /* Free */
        self.runtime.add(
            DotNetEvent {
                id: 6,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_allocs(&mut self) {
        self.runtime.add(
            DotNetEvent {
                id: 10,
                keywords: 0x1,
                level: 5,
            });
    }

    pub fn with_gc_stats(&mut self) {
        self.runtime.add(
            DotNetEvent {
                id: 4,
                keywords: 0x1,
                level: 4,
            });
    }

    pub fn with_gc_times(&mut self) {
        self.runtime.add(
            DotNetEvent {
                id: 1,
                keywords: 0x1,
                level: 4,
            });

        self.runtime.add(
            DotNetEvent {
                id: 2,
                keywords: 0x1,
                level: 4,
            });
    }
}
