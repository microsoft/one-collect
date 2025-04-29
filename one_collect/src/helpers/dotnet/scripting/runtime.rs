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
            .with_fn("with_contentions", Self::with_contentions)
            .with_fn("with_tp_worker_threads", Self::with_tp_worker_threads)
            .with_fn("with_tp_worker_thread_adjustments", Self::with_tp_worker_thread_adjustments)
            .with_fn("with_tp_io_threads", Self::with_tp_io_threads)
            .with_fn("with_arm_threads", Self::with_arm_threads)
            .with_fn("with_arm_allocs", Self::with_arm_allocs);
    }

    pub fn add_runtime_samples(
        &self,
        factory: &mut OSDotNetEventFactory,
        mut add_sample: impl FnMut(DotNetSample)) {
        let record = self.record;

        let mut new_event = |id: usize, name: String| -> Event {
            factory.new_event(
                "Microsoft-Windows-DotNETRuntime",
                self.runtime.keyword(),
                self.runtime.level(),
                id.into(),
                name.into()).expect(
                    "Creating with known provider should always work.")
        };

        for event in self.runtime.events() {
            let mut sample = match event.id {
                1 => {
                    let mut event = new_event(
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
                    let mut event = new_event(
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
                    let mut event = new_event(
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
                    let mut event = new_event(
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
                    let mut event = new_event(
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
                    let event = new_event(
                        event.id.into(),
                        "GCRestartEEBegin".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                3 => {
                    let event = new_event(
                        event.id.into(),
                        "GCRestartEEEnd".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                9 => {
                    let mut event = new_event(
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
                    let event = new_event(
                        event.id.into(),
                        "GCSuspendEEEnd".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                10 => {
                    let mut event = new_event(
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
                    let event = new_event(
                        event.id.into(),
                        "GCFinalizersBegin".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                13 => {
                    let mut event = new_event(
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
                    let event = new_event(
                        event.id.into(),
                        "GCCreateConcurrentThread".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                12 => {
                    let event = new_event(
                        event.id.into(),
                        "GCTerminateConcurrentThread".into());

                    DotNetSample {
                        event,
                        sample_value: Box::new(|_| { Ok(MetricValue::Count(1)) }),
                        record,
                    }
                },

                80 => {
                    let mut event = new_event(
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

                50 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadStart".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 4;
                    format.add_field(EventField::new(
                        "ActiveWorkerThreadCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "RetiredWorkerThreadCount".into(), "u32".into(),
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

                51 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadStop".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 4;
                    format.add_field(EventField::new(
                        "ActiveWorkerThreadCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "RetiredWorkerThreadCount".into(), "u32".into(),
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

                52 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadRetirementStart".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 4;
                    format.add_field(EventField::new(
                        "ActiveWorkerThreadCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "RetiredWorkerThreadCount".into(), "u32".into(),
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

                53 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadRetirementStop".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 4;
                    format.add_field(EventField::new(
                        "ActiveWorkerThreadCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "RetiredWorkerThreadCount".into(), "u32".into(),
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

                54 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadAdjustmentSample".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Throughput".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                55 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadAdjustmentAdjustment".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "AverageThroughput".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 4;
                    format.add_field(EventField::new(
                        "NewWorkerThreadCount".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Reason".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                56 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadPoolWorkerThreadAdjustmentStats".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Duration".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Throughput".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ThreadWave".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ThroughputWave".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ThroughputErrorEstimate".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "AverageThroughputErrorEstimate".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ThroughputRatio".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Confidence".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "NewControlSetting".into(), "double".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "NewThreadWaveMagnitude".into(), "u16".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[8..16].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                44 => {
                    let mut event = new_event(
                        event.id.into(),
                        "IOThreadCreate".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Count".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "NumRetired".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                46 => {
                    let mut event = new_event(
                        event.id.into(),
                        "IOThreadRetire".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Count".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "NumRetired".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                47 => {
                    let mut event = new_event(
                        event.id.into(),
                        "IOThreadUnretire".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Count".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "NumRetired".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                45 => {
                    let mut event = new_event(
                        event.id.into(),
                        "IOThreadTerminate".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "Count".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "NumRetired".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[0..8].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Count(value))
                        }),
                        record,
                    }
                },

                81 => {
                    let mut event = new_event(
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

                85 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadCreated".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "ThreadID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "AppDomainID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 4;
                    format.add_field(EventField::new(
                        "Flags".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ManagedThreadIndex".into(), "u32".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "OSThreadID".into(), "u32".into(),
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

                86 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadTerminated".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "ThreadID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "AppDomainID".into(), "u64".into(),
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

                87 => {
                    let mut event = new_event(
                        event.id.into(),
                        "ThreadAppDomainEnter".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "ThreadID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "AppDomainID".into(), "u64".into(),
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

                83 => {
                    let mut event = new_event(
                        event.id.into(),
                        "AppDomainMemAllocated".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "AppDomainID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Allocated".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[8..16].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Bytes(value))
                        }),
                        record,
                    }
                },

                84 => {
                    let mut event = new_event(
                        event.id.into(),
                        "AppDomainMemSurvived".into());

                    let format = event.format_mut();
                    let mut offset = 0;
                    let mut len;

                    len = 8;
                    format.add_field(EventField::new(
                        "AppDomainID".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "Survived".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    format.add_field(EventField::new(
                        "ProcessSurvived".into(), "u64".into(),
                        LocationType::Static, offset, len));
                    offset += len;

                    len = 2;
                    format.add_field(EventField::new(
                        "ClrInstanceID".into(), "u16".into(),
                        LocationType::Static, offset, len));

                    DotNetSample {
                        event,
                        sample_value: Box::new(move |data| {
                            let slice = data[8..16].try_into()?;
                            let value = u64::from_ne_bytes(slice);

                            Ok(MetricValue::Bytes(value))
                        }),
                        record,
                    }
                },

                91 => {
                    let mut event = new_event(
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

            add_sample(sample)
        }
    }

    pub fn with_arm_threads(&mut self) {
        /* Created */
        self.runtime.add(
            DotNetEvent {
                id: 85,
                keywords: 0x10800,
                level: 4,
            });

        /* Terminated */
        self.runtime.add(
            DotNetEvent {
                id: 86,
                keywords: 0x10800,
                level: 4,
            });

        /* Enter */
        self.runtime.add(
            DotNetEvent {
                id: 87,
                keywords: 0x10800,
                level: 4,
            });
    }

    pub fn with_arm_allocs(&mut self) {
        /* Alloc */
        self.runtime.add(
            DotNetEvent {
                id: 83,
                keywords: 0x800,
                level: 4,
            });

        /* Survived */
        self.runtime.add(
            DotNetEvent {
                id: 84,
                keywords: 0x800,
                level: 4,
            });
    }

    pub fn with_tp_worker_threads(&mut self) {
        /* Start */
        self.runtime.add(
            DotNetEvent {
                id: 50,
                keywords: 0x10000,
                level: 4,
            });

        /* Stop */
        self.runtime.add(
            DotNetEvent {
                id: 51,
                keywords: 0x10000,
                level: 4,
            });

        /* RetireStart */
        self.runtime.add(
            DotNetEvent {
                id: 52,
                keywords: 0x10000,
                level: 4,
            });

        /* RetireStop */
        self.runtime.add(
            DotNetEvent {
                id: 53,
                keywords: 0x10000,
                level: 4,
            });
    }

    pub fn with_tp_worker_thread_adjustments(&mut self) {
        /* Sample */
        self.runtime.add(
            DotNetEvent {
                id: 54,
                keywords: 0x10000,
                level: 4,
            });

        /* Adjustment */
        self.runtime.add(
            DotNetEvent {
                id: 55,
                keywords: 0x10000,
                level: 4,
            });

        /* Stats */
        self.runtime.add(
            DotNetEvent {
                id: 56,
                keywords: 0x10000,
                level: 4,
            });
    }

    pub fn with_tp_io_threads(&mut self) {
        /* Retire */
        self.runtime.add(
            DotNetEvent {
                id: 46,
                keywords: 0x10000,
                level: 4,
            });

        /* Unretire */
        self.runtime.add(
            DotNetEvent {
                id: 47,
                keywords: 0x10000,
                level: 4,
            });

        /* Terminate */
        self.runtime.add(
            DotNetEvent {
                id: 45,
                keywords: 0x10000,
                level: 4,
            });
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
