use super::*;

type BoxedBuilderHook = Box<dyn FnOnce(&mut RingBufSessionBuilder)>;
type BoxedSessionHook = Box<dyn FnOnce(&mut PerfSession)>;

struct RingBufSessionHook {
    builder_hook: Option<BoxedBuilderHook>,
    session_hook: Option<BoxedSessionHook>,
}

impl RingBufSessionHook {
    pub fn new(
        builder_hook: impl FnOnce(&mut RingBufSessionBuilder) + 'static,
        session_hook: impl FnOnce(&mut PerfSession) + 'static) -> Self {
        Self {
            builder_hook: Some(Box::new(builder_hook)),
            session_hook: Some(Box::new(session_hook)),
        }
    }

    pub fn builder_hook(&mut self) -> Option<BoxedBuilderHook> {
        self.builder_hook.take()
    }

    pub fn session_hook(&mut self) -> Option<BoxedSessionHook> {
        self.session_hook.take()
    }
}

pub struct RingBufSessionBuilder {
    pages: usize,
    target_pids: Option<Vec<i32>>,
    kernel_builder: Option<RingBufBuilder<Kernel>>,
    event_builder: Option<RingBufBuilder<Tracepoint>>,
    profiling_builder: Option<RingBufBuilder<Profiling>>,
    cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
    bpf_builder: Option<RingBufBuilder<Bpf>>,
    process_tracking_options: ProcessTrackingOptions,
    hooks: Option<Vec<RingBufSessionHook>>,
}

impl Default for RingBufSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBufSessionBuilder {
    pub fn new() -> Self {
        Self {
            pages: 1,
            target_pids: None,
            kernel_builder: None,
            event_builder: None,
            profiling_builder: None,
            cswitch_builder: None,
            bpf_builder: None,
            process_tracking_options: ProcessTrackingOptions::default(),
            hooks: None,
        }
    }

    pub fn with_target_pid(
        &mut self,
        pid: i32) -> Self {
        let pids = match self.target_pids.take() {
            Some(mut pids) => {
                pids.push(pid);
                Some(pids)
            },
            None => {
                let mut pids = Vec::new();
                pids.push(pid);
                Some(pids)
            },
        };

        Self {
            pages: self.pages,
            target_pids: pids,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn with_page_count(
        &mut self,
        pages: usize) -> Self {
        Self {
            pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn with_kernel_events(
        &mut self,
        builder: RingBufBuilder<Kernel>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: Some(builder),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_kernel_events(
        &mut self) -> Option<RingBufBuilder<Kernel>> {
        self.kernel_builder.take()
    }

    pub fn replace_kernel_events(
        &mut self,
        builder: RingBufBuilder<Kernel>) -> Option<RingBufBuilder<Kernel>> {
        self.kernel_builder.replace(builder)
    }

    pub fn with_tracepoint_events(
        &mut self,
        builder: RingBufBuilder<Tracepoint>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: Some(builder),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_tracepoint_events(
        &mut self) -> Option<RingBufBuilder<Tracepoint>> {
        self.event_builder.take()
    }

    pub fn replace_tracepoint_events(
        &mut self,
        builder: RingBufBuilder<Tracepoint>) -> Option<RingBufBuilder<Tracepoint>> {
        self.event_builder.replace(builder)
    }

    pub fn with_profiling_events(
        &mut self,
        builder: RingBufBuilder<Profiling>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: Some(builder),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_profiling_events(
        &mut self) -> Option<RingBufBuilder<Profiling>> {
        self.profiling_builder.take()
    }

    pub fn replace_profiling_events(
        &mut self,
        builder: RingBufBuilder<Profiling>) -> Option<RingBufBuilder<Profiling>> {
        self.profiling_builder.replace(builder)
    }

    pub fn with_cswitch_events(
        &mut self,
        builder: RingBufBuilder<ContextSwitches>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: Some(builder),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn track_process_state(
        &mut self,
        options: ProcessTrackingOptions) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: options,
            bpf_builder: self.bpf_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_cswitch_events(
        &mut self) -> Option<RingBufBuilder<ContextSwitches>> {
        self.cswitch_builder.take()
    }

    pub fn replace_cswitch_events(
        &mut self,
        builder: RingBufBuilder<ContextSwitches>) -> Option<RingBufBuilder<ContextSwitches>> {
        self.cswitch_builder.replace(builder)
    }

    pub fn with_bpf_events(
        &mut self,
        builder: RingBufBuilder<Bpf>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: Some(builder),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_bpf_events(
        &mut self) -> Option<RingBufBuilder<Bpf>> {
        self.bpf_builder.take()
    }

    pub fn replace_bpf_events(
        &mut self,
        builder: RingBufBuilder<Bpf>) -> Option<RingBufBuilder<Bpf>> {
        self.bpf_builder.replace(builder)
    }

    pub fn with_hooks(
        &mut self,
        builder_hook: impl FnOnce(&mut RingBufSessionBuilder) + 'static,
        session_hook: impl FnOnce(&mut PerfSession) + 'static) -> Self {
        let mut hooks = self.hooks.take().unwrap_or_default();

        hooks.push(
            RingBufSessionHook::new(
                Box::new(builder_hook),
                Box::new(session_hook)));

        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            process_tracking_options: self.process_tracking_options,
            bpf_builder: self.bpf_builder.take(),
            hooks: Some(hooks),
        }
    }

    pub fn build(&mut self) -> IOResult<PerfSession> {
        let mut hooks = self.hooks.take();

        if let Some(hooks) = &mut hooks {
            for hook in hooks {
                if let Some(hook) = hook.builder_hook() {
                    (hook)(self);
                }
            }
        }

        let mut source = RingBufDataSource::new(
            self.pages,
            self.target_pids.take(),
            self.kernel_builder.take(),
            self.event_builder.take(),
            self.profiling_builder.take(),
            self.cswitch_builder.take(),
            self.bpf_builder.take());

        source.build()?;

        let mut session = PerfSession::new(Box::new(source), self.process_tracking_options);

        if let Some(hooks) = &mut hooks {
            for hook in hooks {
                if let Some(hook) = hook.session_hook() {
                    (hook)(&mut session);
                }
            }
        }

        Ok(session)
    }
}

pub struct RingBufDataSource {
    readers: Vec<CpuRingReader>,
    cursors: Vec<CpuRingCursor>,
    temp: Vec<u8>,
    leader_ids: HashMap<u32, u64>,
    ring_bufs: HashMap<u64, CpuRingBuf>,
    pages: usize,
    enabled: bool,
    target_pids: Option<Vec<i32>>,
    kernel_builder: Option<RingBufBuilder<Kernel>>,
    event_builder: Option<RingBufBuilder<Tracepoint>>,
    profiling_builder: Option<RingBufBuilder<Profiling>>,
    cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
    bpf_builder: Option<RingBufBuilder<Bpf>>,
    next_time: Option<u64>,
    oldest_cpu: Option<usize>,
}

impl RingBufDataSource {
    fn new(
        pages: usize,
        target_pids: Option<Vec<i32>>,
        kernel_builder: Option<RingBufBuilder<Kernel>>,
        event_builder: Option<RingBufBuilder<Tracepoint>>,
        profiling_builder: Option<RingBufBuilder<Profiling>>,
        cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
        bpf_builder: Option<RingBufBuilder<Bpf>>) -> Self {
        Self {
            readers: Vec::new(),
            cursors: Vec::new(),
            temp: Vec::new(),
            leader_ids: HashMap::new(),
            ring_bufs: HashMap::new(),
            pages,
            target_pids,
            kernel_builder,
            event_builder,
            profiling_builder,
            cswitch_builder,
            bpf_builder,
            next_time: None,
            oldest_cpu: None,
            enabled: false,
        }
    }

    fn add_cpu_bufs(
        target_pid: Option<i32>,
        leader_ids: &HashMap<u32, u64>,
        ring_bufs: &mut HashMap<u64, CpuRingBuf>,
        common_buf: &CommonRingBuf,
        mut fds: Option<&mut Vec<PerfDataFile>>) -> IOResult<()> {
        /*
         * Utility function to allocate per-cpu buffers and
         * redirect them to the kernel leader buffers on the
         * same CPU.
         */
        for i in 0..cpu_count() {
            let leader_id = leader_ids[&i];
            let leader = &ring_bufs[&leader_id];
            let mut cpu_buf = common_buf.for_cpu(i);

            cpu_buf.open(target_pid)?;

            match cpu_buf.id() {
                Some(id) => {
                    cpu_buf.redirect_to(leader)?;

                    if let Some(fds) = fds.as_mut() {
                        fds.push(
                            PerfDataFile::new(
                                id,
                                cpu_buf.fd.unwrap()));
                    }

                    ring_bufs.insert(id, cpu_buf);
                },
                None => {
                    return Err(io_error(
                        "Internal error getting buffer ID."));
                }
            }
        }

        Ok(())
    }

    fn build(&mut self) -> IOResult<()> {
        /* Always required */
        let common = self.kernel_builder
            .get_or_insert_with(RingBufBuilder::for_kernel)
            .build();

        let empty_pids = Vec::new();

        let pids = match &self.target_pids {
            Some(pids) => { pids },
            None => { &empty_pids },
        };

        /* Build the kernel only dummy rings first */
        for i in 0..cpu_count() {
            let mut cpu_buf = common.for_cpu(i);

            if pids.is_empty() {
                cpu_buf.open(None)?;
            } else {
                cpu_buf.open(Some(pids[0]))?;
            }

            match cpu_buf.id() {
                Some(id) => {
                    self.leader_ids.insert(i, id);

                    /* We need to map these in, and only these */
                    let reader = cpu_buf.create_reader(self.pages)?;
                    self.readers.push(reader);
                    self.cursors.push(CpuRingCursor::default());

                    self.ring_bufs.insert(id, cpu_buf);
                },
                None => {
                    return Err(io_error(
                        "Internal error getting buffer ID."));
                }
            }
        }

        /* Redirect other kernel events for other PIDs */
        if !pids.is_empty() {
            /* Note the skip first here */
            for pid in &pids[1..] {
                Self::add_cpu_bufs(
                    Some(*pid),
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            }
        }

        /* Add in profiling samples and redirect to kernel outputs */
        if let Some(profiling_builder) = self.profiling_builder.as_mut() {
            let common = profiling_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        /* Add in cswitch samples and redirect to kernel outputs */
        if let Some(cswitch_builder) = self.cswitch_builder.as_mut() {
            let common = cswitch_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        Ok(())
    }

    fn enable(&mut self) -> IOResult<()> {
        for rb in self.ring_bufs.values() {
            rb.enable()?;
        }

        self.enabled = true;

        Ok(())
    }

    fn disable(&mut self) -> IOResult<()> {
        for rb in self.ring_bufs.values() {
            rb.disable()?;
        }

        self.enabled = false;

        Ok(())
    }

    fn read_time<'a>(
        reader: &'a CpuRingReader,
        cursor: &'a CpuRingCursor,
        ring_bufs: &'a HashMap<u64, CpuRingBuf>) -> Option<(u64, &'a CpuRingBuf)> {
        let mut start = 0;
        let slice = reader.data_slice();

        /* No more data means no time */
        if !cursor.more() {
            return None;
        }

        match reader.peek_header(
            cursor,
            slice,
            &mut start) {
            Ok(header) => {
                let id_offset: u16;
                let mut time_offset: Option<u16> = None;

                if header.entry_type == abi::PERF_RECORD_SAMPLE {
                    /* Sample records have a static id offset only */
                    id_offset = abi::Header::data_offset() as u16;
                } else {
                    /* Non-Sample records have both static offsets */
                    time_offset = Some(header.size - 16);
                    id_offset = header.size - 8;
                }

                /* All cases require to fetch the id */
                let id = reader.peek_u64(
                    cursor,
                    id_offset as u64);

                /* Fetch the buffer */
                let buf = &ring_bufs[&id];

                /* Time offset is not set, must be a sample */
                if time_offset.is_none() {
                    /* Fetch per-buffer time offset */
                    time_offset = Some(buf.sample_time_offset());
                }

                /* Peek time */
                let time = reader.peek_u64(
                    cursor,
                    time_offset.unwrap() as u64);

                /* Give back time and sample format to use */
                Some((time, buf))
            },
            Err(_) => None,
        }
    }

    fn find_current_buffer(
        &mut self) {
        let mut oldest_time: Option<u64> = None;
        let mut next_time: Option<u64> = None;
        let mut oldest_cpu: Option<usize> = None;

        for i in 0..self.readers.len() {
            let reader = &mut self.readers[i];
            let cursor = &mut self.cursors[i];

            if let Some((time, _rb)) = Self::read_time(
                reader,
                cursor,
                &self.ring_bufs) {
                match oldest_time {
                    Some(prev_time) => {
                        if time < prev_time {
                            next_time = oldest_time;
                            oldest_time = Some(time);
                            oldest_cpu = Some(i);
                        } else {
                            match next_time {
                                Some(current_next_time) => {
                                    if time < current_next_time {
                                        next_time = Some(time);
                                    }
                                },
                                None => {
                                    next_time = Some(time);
                                }
                            }
                        }
                    },
                    None => {
                        oldest_time = Some(time);
                        oldest_cpu = Some(i);
                    },
                }
            }
        }

        self.oldest_cpu = oldest_cpu;
        self.next_time = next_time;
    }
}

impl PerfDataSource for RingBufDataSource {
    fn enable(&mut self) -> IOResult<()> {
        self.enable()
    }

    fn disable(&mut self) -> IOResult<()> {
        self.disable()
    }

    fn create_bpf_files(
        &mut self,
        event: Option<&Event>) -> IOResult<Vec<PerfDataFile>> {
        let mut files = Vec::new();

        if let Some(bpf_builder) = self.bpf_builder.as_mut() {
            let mut common = bpf_builder.build();

            if let Some(event) = &event {
                if event.has_no_callstack_flag() {
                    common = common.without_callstack();
                }
            }

            match &self.target_pids {
                None => {
                    Self::add_cpu_bufs(
                        None,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        Some(&mut files))?;
                },
                Some(pids) => {
                    for pid in pids {
                        Self::add_cpu_bufs(
                            Some(*pid),
                            &self.leader_ids,
                            &mut self.ring_bufs,
                            &common,
                            Some(&mut files))?;
                    }
                },
            }
        }

        Ok(files)
    }

    fn add_event(
        &mut self,
        event: &Event) -> IOResult<()> {
        /* Add in all the events and redirect to kernel outputs */
        if let Some(event_builder) = self.event_builder.as_mut() {
            let mut common = event_builder.build(event.id() as u64);

            /* Mutate attributes based on flags */
            if event.has_no_callstack_flag() {
                common = common.without_callstack();
            }

            match &self.target_pids {
                None => {
                    Self::add_cpu_bufs(
                        None,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                },
                Some(pids) => {
                    for pid in pids {
                        Self::add_cpu_bufs(
                            Some(*pid),
                            &self.leader_ids,
                            &mut self.ring_bufs,
                            &common,
                            None)?;
                    }
                },
            }
        }

        Ok(())
    }

    fn begin_reading(&mut self) {
        for i in 0..self.readers.len() {
            let reader = &mut self.readers[i];
            let cursor = &mut self.cursors[i];

            reader.begin_reading(cursor);
        }

        self.find_current_buffer();
    }

    fn read(
        &mut self,
        timeout: Duration) -> Option<PerfData<'_>> {
        /* Bail if we couldn't find a current buffer */
        if self.oldest_cpu.is_none() {
            std::thread::sleep(timeout);
            return None;
        }

        let cpu = self.oldest_cpu.unwrap();
        let reader = &self.readers[cpu];
        let cursor = &mut self.cursors[cpu];
        let ancillary: AncillaryData;

        /* Ensure current entry is still under the limit */
        match Self::read_time(
            reader,
            cursor,
            &self.ring_bufs) {
            /* We have some data/time left in this buffer */
            Some((time, rb)) => {
                if let Some(next_time) = self.next_time {
                    /* If older than next oldest, stop */
                    if time > next_time {
                        return None;
                    }
                }

                /* Under limit, save off ancillary details */
                ancillary = rb.ancillary();
            },
            /* No data left, stop */
            None => {
                return None;
            }
        }

        /* Read perf data */
        match reader.read(
            cursor,
            &mut self.temp) {
            Ok(raw_data) => {
                let perf_data = PerfData {
                    ancillary,
                    raw_data,
                };

                Some(perf_data)
            },
            Err(_) => None,
        }
    }

    fn end_reading(&mut self) {
        if let Some(oldest_cpu) = self.oldest_cpu {
            let reader = &mut self.readers[oldest_cpu];
            let cursor = &mut self.cursors[oldest_cpu];

            reader.end_reading(cursor);
        }
    }

    fn more(&self) -> bool {
        if self.oldest_cpu.is_some() {
            return true;
        }

        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn config() {
        let kernel = RingBufBuilder::for_kernel()
            .with_mmap_records()
            .with_comm_records()
            .with_task_records()
            .with_cswitch_records();

        let freq = 1000;

        let profiling = RingBufBuilder::for_profiling(
            freq)
            .with_callchain_data();

        let _builder = RingBufSessionBuilder::new()
            .with_page_count(1)
            .with_kernel_events(kernel)
            .with_profiling_events(profiling);
    }

    #[test]
    #[ignore]
    fn profile() {
        let freq = 1000;

        let profiling = RingBufBuilder::for_profiling(
            freq)
            .with_callchain_data();

        let mut session = RingBufSessionBuilder::new()
            .with_page_count(8)
            .with_profiling_events(profiling)
            .build()
            .unwrap();

        session.set_read_timeout(Duration::from_millis(0));

        let samples = Arc::new(AtomicUsize::new(0));

        let callback_samples = samples.clone();

        /* Context from session for callback */
        let time_data = session.time_data_ref();
        let ancillary = session.ancillary_data();

        /* Setup event logic w/context */
        let prof_event = session.cpu_profile_event();

        let atomic_time = Arc::new(AtomicUsize::new(0));

        prof_event.add_callback(move |full_data,_format,_event_data| {
            let time = time_data.try_get_u64(full_data).unwrap() as usize;
            let prev = atomic_time.load(Ordering::Relaxed);
            let mut cpu: u32 = 0;

            ancillary.read(|ancillary| {
                cpu = ancillary.cpu();
            });

            /* Ensure in order */
            assert!(time >= prev);

            callback_samples.fetch_add(1, Ordering::Relaxed);
            atomic_time.store(time, Ordering::Relaxed);

            Ok(())
        });

        session.enable().unwrap();

        /* Spin for 100 ms */
        let now = std::time::Instant::now();

        while now.elapsed().as_millis() < 100 {
            /* Nothing */
        }

        session.disable().unwrap();

        let now = std::time::Instant::now();

        /* Parse all the samples */
        session.parse_all().unwrap();

        println!("Took {}us", now.elapsed().as_micros());

        /* Ensure we got at least a sample per-ms */
        let count = samples.load(Ordering::Relaxed);

        println!("Got {} samples", count);
        assert!(count >= 100);
    }
}
