// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;

use tracing::{debug, info, trace, warn};

use super::*;

type BoxedBuilderHook = Box<dyn FnOnce(&mut RingBufSessionBuilder)>;
type BoxedSessionHook = Box<dyn FnOnce(&mut PerfSession)>;

struct RingBufSessionHook {
    builder_hook: Option<BoxedBuilderHook>,
    session_hook: Option<BoxedSessionHook>,
}

impl RingBufSessionHook {
    pub(crate) fn new(
        builder_hook: impl FnOnce(&mut RingBufSessionBuilder) + 'static,
        session_hook: impl FnOnce(&mut PerfSession) + 'static) -> Self {
        Self {
            builder_hook: Some(Box::new(builder_hook)),
            session_hook: Some(Box::new(session_hook)),
        }
    }

    pub(crate) fn builder_hook(&mut self) -> Option<BoxedBuilderHook> {
        self.builder_hook.take()
    }

    pub(crate) fn session_hook(&mut self) -> Option<BoxedSessionHook> {
        self.session_hook.take()
    }
}

pub struct RingBufSessionBuilder {
    pages: usize,
    target_pids: Option<Vec<i32>>,
    target_cpus: Option<Vec<u16>>,
    wakeup_watermark: Option<u32>,
    kernel_builder: Option<RingBufBuilder<Kernel>>,
    event_builder: Option<RingBufBuilder<Tracepoint>>,
    profiling_builder: Option<RingBufBuilder<Profiling>>,
    cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
    soft_page_faults_builder: Option<RingBufBuilder<PageFaults>>,
    hard_page_faults_builder: Option<RingBufBuilder<PageFaults>>,
    bpf_builder: Option<RingBufBuilder<Bpf>>,
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
            target_cpus: None,
            wakeup_watermark: None,
            kernel_builder: None,
            event_builder: None,
            profiling_builder: None,
            cswitch_builder: None,
            soft_page_faults_builder: None,
            hard_page_faults_builder: None,
            bpf_builder: None,
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn with_target_cpu(
        &mut self,
        cpu: u16) -> Self {
        let cpus = match self.target_cpus.take() {
            Some(mut cpus) => {
                cpus.push(cpu);
                Some(cpus)
            },
            None => {
                let mut cpus = Vec::new();
                cpus.push(cpu);
                Some(cpus)
            },
        };

        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            target_cpus: cpus,
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn with_page_count(
        &mut self,
        pages: usize) -> Self {
        Self {
            pages,
            target_pids: self.target_pids.take(),
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    /// Configure the kernel to defer marking a per-CPU perf fd readable
    /// until at least `bytes` of data have accumulated in its ring
    /// buffer.
    ///
    /// By default the kernel marks the fd readable on every event.
    /// Raising the watermark amortizes wakeup cost in exchange for
    /// additional latency.
    ///
    /// This setting only takes effect for consumers that wait on the
    /// per-CPU perf fds (for example via `epoll(2)` or
    /// `tokio::io::unix::AsyncFd`). The default [`PerfSession`] read
    /// loop sleeps on a timeout and does not consult the fd's readable
    /// state, so it sees no behavior change from this method.
    ///
    /// `bytes` must be strictly smaller than the per-CPU ring data area
    /// configured by [`Self::with_page_count`]; otherwise the kernel
    /// would never reach the watermark and the fd would never be marked
    /// readable. [`Self::build`] returns an error if this constraint is
    /// violated.
    ///
    /// A value of `0` keeps the kernel default of marking the fd
    /// readable on every event.
    pub fn with_wakeup_watermark(
        &mut self,
        bytes: u32) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: Some(bytes),
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn with_kernel_events(
        &mut self,
        builder: RingBufBuilder<Kernel>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: Some(builder),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: Some(builder),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: Some(builder),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: Some(builder),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: Some(builder),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
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

    pub fn with_soft_page_faults_events(
        &mut self,
        builder: RingBufBuilder<PageFaults>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: Some(builder),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_soft_page_faults_events(
        &mut self) -> Option<RingBufBuilder<PageFaults>> {
        self.soft_page_faults_builder.take()
    }

    pub fn replace_soft_page_faults_events(
        &mut self,
        builder: RingBufBuilder<PageFaults>) -> Option<RingBufBuilder<PageFaults>> {
        self.soft_page_faults_builder.replace(builder)
    }

    pub fn with_hard_page_faults_events(
        &mut self,
        builder: RingBufBuilder<PageFaults>) -> Self {
        Self {
            pages: self.pages,
            target_pids: self.target_pids.take(),
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: Some(builder),
            hooks: self.hooks.take(),
        }
    }

    pub fn take_hard_page_faults_events(
        &mut self) -> Option<RingBufBuilder<PageFaults>> {
        self.hard_page_faults_builder.take()
    }

    pub fn replace_hard_page_faults_events(
        &mut self,
        builder: RingBufBuilder<PageFaults>) -> Option<RingBufBuilder<PageFaults>> {
        self.hard_page_faults_builder.replace(builder)
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
            target_cpus: self.target_cpus.take(),
            wakeup_watermark: self.wakeup_watermark,
            kernel_builder: self.kernel_builder.take(),
            event_builder: self.event_builder.take(),
            profiling_builder: self.profiling_builder.take(),
            cswitch_builder: self.cswitch_builder.take(),
            bpf_builder: self.bpf_builder.take(),
            soft_page_faults_builder: self.soft_page_faults_builder.take(),
            hard_page_faults_builder: self.hard_page_faults_builder.take(),
            hooks: Some(hooks),
        }
    }

    pub fn build(&mut self) -> IOResult<PerfSession> {
        debug!(
            "RingBufSessionBuilder::build: pages={}, target_pids={:?}",
            self.pages, self.target_pids
        );

        let mut hooks = self.hooks.take();

        if let Some(hooks) = &mut hooks {
            for hook in hooks {
                if let Some(hook) = hook.builder_hook() {
                    (hook)(self);
                }
            }
        }

        /* Apply wakeup watermark to the kernel/leader perf_event_attr. The
         * leader fd is the one the kernel wakes when data lands in its
         * per-CPU ring; all other event types redirect into the same
         * ring, so the leader's watermark covers them.
         *
         * The watermark must be strictly smaller than the per-CPU ring
         * data area (see `ring_data_bytes`). The kernel does not validate
         * this at `perf_event_open()` time and silently never wakes the fd
         * if the watermark cannot be reached, so we reject the
         * misconfiguration here. */
        if let Some(bytes) = self.wakeup_watermark.take() {
            let ring_bytes = ring_data_bytes(self.pages);

            if (bytes as usize) >= ring_bytes {
                let msg = format!(
                    "wakeup_watermark ({} bytes) must be smaller than the \
                     per-CPU ring data area ({} bytes from {} pages); the \
                     kernel would never wake the perf fds",
                    bytes, ring_bytes, self.pages);
                warn!("RingBufSessionBuilder::build: {}", msg);
                return Err(io_error(&msg));
            }

            let mut kernel = self.kernel_builder
                .take()
                .unwrap_or_else(RingBufBuilder::for_kernel);

            kernel.set_wakeup_watermark(bytes);
            self.kernel_builder = Some(kernel);

            debug!(
                "RingBufSessionBuilder::build: wakeup_watermark applied, bytes={}, ring_bytes={}",
                bytes, ring_bytes);
        }

        let mut source = RingBufDataSource::new(
            self.pages,
            self.target_pids.take(),
            self.target_cpus.take(),
            self.kernel_builder.take(),
            self.event_builder.take(),
            self.profiling_builder.take(),
            self.cswitch_builder.take(),
            self.bpf_builder.take(),
            self.soft_page_faults_builder.take(),
            self.hard_page_faults_builder.take());

        source.build()?;

        let mut session = PerfSession::new(Box::new(source));

        if let Some(hooks) = &mut hooks {
            for hook in hooks {
                if let Some(hook) = hook.session_hook() {
                    (hook)(&mut session);
                }
            }
        }

        info!("PerfSession created successfully");

        Ok(session)
    }
}

pub struct RingBufDataSource {
    readers: Vec<CpuRingReader>,
    cursors: Vec<CpuRingCursor>,
    temp: Vec<u8>,
    leader_ids: HashMap<u32, u64>,
    ring_bufs: HashMap<u64, CpuRingBuf>,
    ksymbol_buf_ids: HashSet<u64>,
    pages: usize,
    enabled: bool,
    recording_started: bool,
    target_pids: Option<Vec<i32>>,
    target_cpus: Option<Vec<u16>>,
    kernel_builder: Option<RingBufBuilder<Kernel>>,
    event_builder: Option<RingBufBuilder<Tracepoint>>,
    profiling_builder: Option<RingBufBuilder<Profiling>>,
    cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
    bpf_builder: Option<RingBufBuilder<Bpf>>,
    soft_page_faults_builder: Option<RingBufBuilder<PageFaults>>,
    hard_page_faults_builder: Option<RingBufBuilder<PageFaults>>,
    next_time: Option<u64>,
    oldest_cpu: Option<usize>,
    cpu_to_reader_index: Vec<Option<usize>>,
    in_process_ring_buf: Option<InProcessRingBuf>,
}

impl RingBufDataSource {
    fn new(
        pages: usize,
        target_pids: Option<Vec<i32>>,
        target_cpus: Option<Vec<u16>>,
        kernel_builder: Option<RingBufBuilder<Kernel>>,
        event_builder: Option<RingBufBuilder<Tracepoint>>,
        profiling_builder: Option<RingBufBuilder<Profiling>>,
        cswitch_builder: Option<RingBufBuilder<ContextSwitches>>,
        bpf_builder: Option<RingBufBuilder<Bpf>>,
        soft_page_faults_builder: Option<RingBufBuilder<PageFaults>>,
        hard_page_faults_builder: Option<RingBufBuilder<PageFaults>>) -> Self {
        Self {
            readers: Vec::new(),
            cursors: Vec::new(),
            temp: Vec::new(),
            leader_ids: HashMap::new(),
            ring_bufs: HashMap::new(),
            ksymbol_buf_ids: HashSet::new(),
            pages,
            target_pids,
            target_cpus,
            kernel_builder,
            event_builder,
            profiling_builder,
            cswitch_builder,
            bpf_builder,
            soft_page_faults_builder,
            hard_page_faults_builder,
            next_time: None,
            oldest_cpu: None,
            cpu_to_reader_index: Vec::new(),
            enabled: false,
            recording_started: false,
            in_process_ring_buf: None,
        }
    }

    fn add_cpu_bufs(
        target_pid: Option<i32>,
        target_cpus: &Option<Vec<u16>>,
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
            /* Only enable online/target CPUs */
            if let Some(target_cpus) = target_cpus {
                if !target_cpus.contains(&(i as u16)) {
                    continue;
                }
            }

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

                    debug!(
                        "add_cpu_bufs: cpu={}, id={}, leader_id={}, target_pid={:?}",
                        i, id, leader_id, target_pid
                    );

                    ring_bufs.insert(id, cpu_buf);
                },
                None => {
                    warn!(
                        "add_cpu_bufs failed: no buffer ID returned, cpu={}, target_pid={:?}",
                        i, target_pid
                    );
                    return Err(io_error(
                        "Internal error getting buffer ID."));
                }
            }
        }

        Ok(())
    }

    fn set_new_bufs_filter(
        ring_bufs: &HashMap<u64, CpuRingBuf>,
        before: &HashSet<u64>,
        mut set_filter: impl FnMut(&CpuRingBuf) -> IOResult<()>) -> IOResult<()> {
        for (id, buf) in ring_bufs.iter() {
            if before.contains(id) {
                continue;
            }

            if let Err(err) = set_filter(buf) {
                warn!(
                    "set_new_bufs_filter: failed to set perf filter, cpu={}, id={}: {}",
                    buf.cpu, id, err
                );
                return Err(err);
            }
        }

        Ok(())
    }

    fn remove_new_bufs(
        ring_bufs: &mut HashMap<u64, CpuRingBuf>,
        before: &HashSet<u64>) {
        ring_bufs.retain(|id, _| before.contains(id));
    }

    fn reclaim_ksymbol_bufs(
        ring_bufs: &mut HashMap<u64, CpuRingBuf>,
        ksymbol_buf_ids: &mut HashSet<u64>,
        allow_reclaim: bool,
        required: &str) -> bool {
        if !allow_reclaim || ksymbol_buf_ids.is_empty() {
            return false;
        }

        warn!("Closing optional kernel dynamic symbol descriptors to make room for {}; \
            BPF symbols may be unknown", required);
        for id in ksymbol_buf_ids.drain() {
            if let Some(buf) = ring_bufs.get_mut(&id) {
                if let Some(fd) = buf.fd.take() {
                    unsafe { libc::close(fd); }
                }
            }
        }

        // Keep the closed buffers' metadata so already queued records remain decodable.
        true
    }

    fn add_required_bufs<T>(
        ring_bufs: &mut HashMap<u64, CpuRingBuf>,
        ksymbol_buf_ids: &mut HashSet<u64>,
        allow_reclaim: bool,
        required: &str,
        mut add: impl FnMut(&mut HashMap<u64, CpuRingBuf>) -> IOResult<T>) -> IOResult<(HashSet<u64>, T)> {
        let before: HashSet<u64> = ring_bufs.keys().copied().collect();
        match add(ring_bufs) {
            Ok(value) => return Ok((before, value)),
            Err(err) => {
                Self::remove_new_bufs(ring_bufs, &before);
                if !matches!(err.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
                    || !Self::reclaim_ksymbol_bufs(
                        ring_bufs, ksymbol_buf_ids, allow_reclaim, required) {
                    return Err(err);
                }
            },
        }

        let before: HashSet<u64> = ring_bufs.keys().copied().collect();
        match add(ring_bufs) {
            Ok(value) => Ok((before, value)),
            Err(err) => {
                Self::remove_new_bufs(ring_bufs, &before);
                Err(err)
            },
        }
    }

    fn add_required_bpf_bufs(
        ring_bufs: &mut HashMap<u64, CpuRingBuf>,
        ksymbol_buf_ids: &mut HashSet<u64>,
        allow_reclaim: bool,
        mut add: impl FnMut(&mut HashMap<u64, CpuRingBuf>, &mut Vec<PerfDataFile>) -> IOResult<()>) -> IOResult<Vec<PerfDataFile>> {
        let (_, files) = Self::add_required_bufs(
            ring_bufs,
            ksymbol_buf_ids,
            allow_reclaim,
            "BPF output",
            |ring_bufs| {
                // A failed attempt's file entries must not survive the retry.
                let mut files = Vec::new();
                add(ring_bufs, &mut files)?;
                Ok(files)
            })?;
        Ok(files)
    }

    fn tasks_for_pids(pids: &mut Vec<i32>) {
        let mut tasks = HashSet::new();

        /* Find all unique tasks IDs */
        for pid in pids.drain(..) {
            tasks.insert(pid);

            procfs::iter_proc_tasks(
                pid as u32,
                |task| { tasks.insert(task as i32); });
        }

        /* Update PIDs with unique tasks */
        for task in tasks.drain() {
            pids.push(task);
        }
    }

    fn build(&mut self) -> IOResult<()> {
        debug!(
            "RingBufDataSource::build: pages={}, target_pids={:?}",
            self.pages, self.target_pids
        );

        let empty_pids = Vec::new();

        let target_pids = &mut self.target_pids.as_mut();
        let target_cpus = &self.target_cpus;

        let pids = match target_pids {
            Some(pids) => {
                /* Populate current tasks for PIDs */
                Self::tasks_for_pids(pids);

                debug!("build: found {} task(s) for target PIDs", pids.len());

                pids
            },
            None => { &empty_pids },
        };

        let kernel_builder = self.kernel_builder
            .get_or_insert_with(RingBufBuilder::for_kernel);
        let common = if pids.is_empty() {
            kernel_builder.build()
        } else {
            kernel_builder.build_without_ksymbol_records()
        };

        self.cpu_to_reader_index.resize(cpu_count() as usize, None);

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
                    /* Record this CPU's reader index so per-CPU draining
                     * (parse_for_cpu) can locate the right reader/cursor
                     * without relying on positional ordering. */
                    let reader_index = self.readers.len();
                    self.cpu_to_reader_index[i as usize] = Some(reader_index);
                    self.readers.push(reader);
                    self.cursors.push(CpuRingCursor::default());

                    debug!("build: leader ring buffer created, cpu={}, id={}", i, id);

                    self.ring_bufs.insert(id, cpu_buf);
                },
                None => {
                    warn!("build failed: no buffer ID returned for leader ring, cpu={}", i);
                    return Err(io_error(
                        "Internal error getting buffer ID."));
                }
            }
        }

        debug!(
            "build: leader ring buffers created, cpu_count={}, ring_buf_count={}",
            cpu_count(), self.ring_bufs.len()
        );

        /* Redirect other kernel events for other PIDs */
        if !pids.is_empty() {
            /* Note the skip first here */
            for pid in &pids[1..] {
                Self::add_cpu_bufs(
                    Some(*pid),
                    &None, /* Kernel events are for all CPUs */
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            }
        }

        /* Add in profiling samples and redirect to kernel outputs */
        if let Some(profiling_builder) = self.profiling_builder.as_mut() {
            debug!("build: adding profiling event buffers");
            let common = profiling_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    target_cpus,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        target_cpus,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        /* Add in cswitch samples and redirect to kernel outputs */
        if let Some(cswitch_builder) = self.cswitch_builder.as_mut() {
            debug!("build: adding context switch event buffers");
            let common = cswitch_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    target_cpus,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        target_cpus,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        /* Add in page fault samples and redirect to kernel outputs */
        if let Some(faults_builder) = self.soft_page_faults_builder.as_mut() {
            debug!("build: adding soft page faults event buffers");
            let common = faults_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    target_cpus,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        target_cpus,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        if let Some(faults_builder) = self.hard_page_faults_builder.as_mut() {
            debug!("build: adding hard page faults event buffers");
            let common = faults_builder.build();

            if pids.is_empty() {
                Self::add_cpu_bufs(
                    None,
                    target_cpus,
                    &self.leader_ids,
                    &mut self.ring_bufs,
                    &common,
                    None)?;
            } else {
                for pid in pids {
                    Self::add_cpu_bufs(
                        Some(*pid),
                        target_cpus,
                        &self.leader_ids,
                        &mut self.ring_bufs,
                        &common,
                        None)?;
                }
            }
        }

        /*
         * Allocate the optional sideband after the fixed required descriptors.
         * Before recording starts, later required events and BPF maps can
         * reclaim it if they run out of fds. Never stop lifecycle capture
         * once recording has started.
         * Use one scope at a time: duplicate task and CPU subscriptions can
         * corrupt ksymbol record trailers on some kernels.
         */
        if !pids.is_empty() {
            if let Some(ksymbols) = self.kernel_builder.as_ref()
                .and_then(|builder| builder.ksymbol_only()) {
                let before: HashSet<u64> = self.ring_bufs.keys().copied().collect();
                if let Err(err) = Self::add_cpu_bufs(
                    None, &None, &self.leader_ids, &mut self.ring_bufs, &ksymbols, None) {
                    Self::remove_new_bufs(&mut self.ring_bufs, &before);
                    warn!("Unable to observe kernel dynamic symbols system wide ({}); \
                        attempting task-scoped collection", err);

                    let task_symbols = self.kernel_builder.as_ref()
                        .and_then(|builder| builder.task_ksymbol_only()).unwrap();
                    for pid in pids {
                        if let Err(err) = Self::add_cpu_bufs(
                            Some(*pid), &None, &self.leader_ids, &mut self.ring_bufs,
                            &task_symbols, None) {
                            Self::remove_new_bufs(&mut self.ring_bufs, &before);
                            warn!("Unable to observe task-scoped kernel dynamic symbols ({}); \
                                BPF symbols may be unknown", err);
                            break;
                        }
                    }
                }
                self.ksymbol_buf_ids.extend(
                    self.ring_bufs.keys().filter(|id| !before.contains(id)).copied());
            }
        }

        /* Create in-process ring buffer for capture_environment.
         * The reader is added to the normal readers/cursors so that
         * in-process events are processed in time order alongside
         * kernel events. */
        let mut in_process = InProcessRingBuf::new(self.pages);
        let reader = in_process.create_reader();

        self.readers.push(reader);
        self.cursors.push(CpuRingCursor::default());
        self.in_process_ring_buf = Some(in_process);

        /* Insert a dummy CpuRingBuf at id=0 so that read_time() can
         * look up the attributes for in-process records (which use
         * identifier 0). */
        let common_attrs = Rc::new(RingBufBuilder::common_attributes());
        self.ring_bufs.insert(0, CpuRingBuf::new(0, common_attrs));

        info!(
            "RingBufDataSource built successfully: ring_buf_count={}, reader_count={}",
            self.ring_bufs.len(), self.readers.len()
        );

        Ok(())
    }

    fn enable(&mut self) -> IOResult<()> {
        debug!("RingBufDataSource::enable: enabling {} ring buffers", self.ring_bufs.len());

        // An unsuccessful enable may already have enabled some descriptors.
        self.recording_started = true;
        for rb in self.ring_bufs.values() {
            if !rb.is_open() {
                continue;
            }
            rb.enable()?;
        }

        self.enabled = true;

        info!("RingBufDataSource enabled: ring_buf_count={}", self.ring_bufs.len());

        Ok(())
    }

    fn disable(&mut self) -> IOResult<()> {
        debug!("RingBufDataSource::disable: disabling {} ring buffers", self.ring_bufs.len());

        for rb in self.ring_bufs.values() {
            if !rb.is_open() {
                continue;
            }
            rb.disable()?;
        }

        self.enabled = false;

        info!("RingBufDataSource disabled: ring_buf_count={}", self.ring_bufs.len());

        Ok(())
    }

    /// CPUs whose leader-ring fd should be exposed by
    /// [`PerfDataSource::perf_fds`]. CPUs masked out by the builder's
    /// `target_cpus` are excluded so the exposed fds match the
    /// configured CPU set. Yields CPUs in `leader_ids` order;
    /// [`PerfDataSource::perf_fds`] sorts the final result.
    #[cfg(target_os = "linux")]
    fn fd_cpus(&self) -> impl Iterator<Item = u32> + '_ {
        self.leader_ids
            .keys()
            .copied()
            .filter(move |cpu| match &self.target_cpus {
                Some(target_cpus) => target_cpus.contains(&(*cpu as u16)),
                None => true,
            })
    }

    fn read_time<'a>(
        reader: &'a CpuRingReader,
        cursor: &'a mut CpuRingCursor,
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
                /* A valid record must be large enough to hold the header plus
                 * the trailing id (and time, for non-sample records). If the
                 * size is smaller we cannot safely decode time/id; advance by
                 * at least the header size so the ring drains and return None
                 * so the caller can retry on the next pass. */
                let min_size = abi::Header::data_offset() + 16;
                if (header.size as usize) < min_size {
                    warn!(
                        "read_time: invalid header size={}, skipping record",
                        header.size
                    );
                    let skip = std::cmp::max(
                        header.size as usize,
                        abi::Header::data_offset(),
                    ) as u16;
                    cursor.advance(skip);
                    return None;
                }

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

                /* Fetch the buffer; if we don't know this id, skip just this
                 * record so we make forward progress without silently
                 * consuming any subsequent records on this CPU. */
                let Some(buf) = ring_bufs.get(&id) else {
                    warn!(
                        "read_time: no ring buffer found for id={}, skipping record",
                        id
                    );
                    cursor.advance(header.size);
                    return None;
                };

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

        trace!(
            "find_current_buffer: oldest_cpu={:?}, oldest_time={:?}, next_time={:?}",
            oldest_cpu, oldest_time, next_time
        );
    }
}

impl PerfDataSource for RingBufDataSource {
    fn enable(&mut self) -> IOResult<()> {
        self.enable()
    }

    fn disable(&mut self) -> IOResult<()> {
        self.disable()
    }

    fn target_pids(&self) -> Option<&[i32]> {
        match &self.target_pids {
            Some(pids) => { Some(&pids) },
            None => { None },
        }
    }

    fn reclaim_optional_fds(&mut self) -> bool {
        Self::reclaim_ksymbol_bufs(
            &mut self.ring_bufs,
            &mut self.ksymbol_buf_ids,
            !self.recording_started,
            "a BPF map")
    }

    fn create_bpf_files(
        &mut self,
        event: Option<&Event>) -> IOResult<Vec<PerfDataFile>> {
        if let Some(bpf_builder) = self.bpf_builder.as_mut() {
            debug!("create_bpf_files: creating BPF event buffers");

            let mut common = bpf_builder.build();
            let mut target_cpus = &None;

            if let Some(event) = &event {
                debug!("create_bpf_files: event_name={}, event_id={}", event.name(), event.id());
                if event.has_no_callstack_flag() {
                    debug!("create_bpf_files: event has no_callstack flag, disabling callstack");
                    common = common.without_callstack();
                }

                if !event.has_no_cpu_mask_flag() {
                    target_cpus = &self.target_cpus;
                }
            }

            let files = Self::add_required_bpf_bufs(
                &mut self.ring_bufs,
                &mut self.ksymbol_buf_ids,
                !self.recording_started,
                |ring_bufs, files| match &self.target_pids {
                    None => {
                        Self::add_cpu_bufs(
                            None,
                            target_cpus,
                            &self.leader_ids,
                            ring_bufs,
                            &common,
                            Some(files))
                    },
                    Some(pids) => {
                        for pid in pids {
                            Self::add_cpu_bufs(
                                Some(*pid),
                                target_cpus,
                                &self.leader_ids,
                                ring_bufs,
                                &common,
                                Some(&mut *files))?;
                        }
                        Ok(())
                    },
                })?;

            info!("BPF files created: file_count={}", files.len());
            Ok(files)
        } else {
            warn!("create_bpf_files: no BPF builder configured");
            Ok(Vec::new())
        }
    }

    fn add_event(
        &mut self,
        event: &Event) -> IOResult<()> {
        /* Add in all the events and redirect to kernel outputs */
        if let Some(event_builder) = self.event_builder.as_mut() {
            debug!("add_event: adding event_name={}, event_id={}", event.name(), event.id());

            let mut common = event_builder.build(event.id() as u64);

            /* Mutate attributes based on flags */
            if event.has_no_callstack_flag() {
                debug!("add_event: event has no_callstack flag, disabling callstack");
                common = common.without_callstack();
            }

            let target_cpus = match event.has_no_cpu_mask_flag() {
                true => { &None },
                false => { &self.target_cpus },
            };

            let filter_cstr = event.extension().perf_filter()
                .map(std::ffi::CString::new)
                .transpose()
                .map_err(|_| io_error("Invalid perf filter string"))?;

            let result = (|| -> IOResult<()> {
                let (before, ()) = Self::add_required_bufs(
                    &mut self.ring_bufs,
                    &mut self.ksymbol_buf_ids,
                    !self.recording_started,
                    "a tracepoint",
                    |ring_bufs| match &self.target_pids {
                        None => {
                            Self::add_cpu_bufs(
                                None,
                                target_cpus,
                                &self.leader_ids,
                                ring_bufs,
                                &common,
                                None)
                        },
                        Some(pids) => {
                            for pid in pids {
                                Self::add_cpu_bufs(
                                    Some(*pid),
                                    target_cpus,
                                    &self.leader_ids,
                                    ring_bufs,
                                    &common,
                                    None)?;
                            }
                            Ok(())
                        },
                    })?;

                if let Some(filter_cstr) = &filter_cstr {
                    if let Err(err) = Self::set_new_bufs_filter(
                        &self.ring_bufs,
                        &before,
                        |buf| buf.set_filter(filter_cstr)) {
                        // Do not leave partially configured, unfiltered tracepoint fds open.
                        Self::remove_new_bufs(&mut self.ring_bufs, &before);
                        return Err(err);
                    }

                    debug!(
                        "add_event: perf filter applied, event_name={}, filter={:?}",
                        event.name(),
                        filter_cstr
                    );
                }

                Ok(())
            })();

            if let Err(err) = result {
                warn!(
                    "add_event: failed, new fds closed, event_name={}, event_id={}: {}",
                    event.name(),
                    event.id(),
                    err
                );

                return Err(err);
            }

            info!("Event added: event_name={}, event_id={}", event.name(), event.id());
        } else {
            warn!("add_event: no event builder configured");
        }

        Ok(())
    }

    fn begin_reading(&mut self) {
        trace!("begin_reading: starting read cycle for {} readers", self.readers.len());

        for i in 0..self.readers.len() {
            let reader = &mut self.readers[i];
            let cursor = &mut self.cursors[i];

            reader.begin_reading(cursor);
        }

        self.find_current_buffer();

        trace!(
            "begin_reading: oldest_cpu={:?}, next_time={:?}",
            self.oldest_cpu, self.next_time
        );
    }

    fn read(
        &mut self,
        timeout: Duration) -> Option<PerfData<'_>> {
        /* Bail if we couldn't find a current buffer */
        if self.oldest_cpu.is_none() {
            trace!("read: no data available, sleeping for {:?}", timeout);
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
                        trace!(
                            "read: time {} exceeds next_time {}, switching buffers",
                            time, next_time
                        );
                        return None;
                    }
                }

                /* Under limit, save off ancillary details */
                ancillary = rb.ancillary();
            },
            /* No data left, stop */
            None => {
                trace!("read: no more data in buffer for cpu={}", cpu);
                return None;
            }
        }

        /* Read perf data */
        match reader.read(
            cursor,
            &mut self.temp) {
            Ok(raw_data) => {
                trace!("read: data read from cpu={}, size={}", cpu, raw_data.len());

                let perf_data = PerfData {
                    ancillary,
                    raw_data,
                };

                Some(perf_data)
            },
            Err(e) => {
                warn!("read failed: cpu={}, error={}", cpu, e);
                None
            },
        }
    }

    fn end_reading(&mut self) {
        if let Some(oldest_cpu) = self.oldest_cpu {
            trace!("end_reading: completing read for cpu={}", oldest_cpu);

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

    fn begin_reading_cpu(
        &mut self,
        cpu: u32) -> Option<CpuReadContext> {
        let Some(Some(index)) = self.cpu_to_reader_index.get(cpu as usize) else {
            return None;
        };
        let index = *index;

        let reader = &self.readers[index];
        let cursor = &mut self.cursors[index];

        reader.begin_reading(cursor);

        trace!("begin_reading_cpu: primed cpu={}, index={}", cpu, index);

        Some(CpuReadContext::new(cpu, index))
    }

    fn read_cpu(
        &mut self,
        ctx: &CpuReadContext) -> Option<PerfData<'_>> {
        /* The context resolved the reader slot once in begin_reading_cpu,
         * so the per-record drain loop indexes directly without repeating
         * the CPU-to-reader lookup. */
        let index = ctx.reader_index();

        let reader = &self.readers[index];
        let cursor = &mut self.cursors[index];

        /* A single CPU ring is already time-ordered, so we read records
         * sequentially without the cross-CPU oldest/next_time merge that
         * the all-CPU read() path performs. Ancillary still varies per
         * record because multiple event types redirect into one CPU ring,
         * so it is resolved for each record rather than cached. */
        let ancillary = match Self::read_time(
            reader,
            cursor,
            &self.ring_bufs) {
            Some((_time, rb)) => rb.ancillary(),
            None => {
                trace!("read_cpu: no data for cpu={}", ctx.cpu());
                return None;
            }
        };

        match reader.read(
            cursor,
            &mut self.temp) {
            Ok(raw_data) => {
                trace!("read_cpu: data read from cpu={}, size={}", ctx.cpu(), raw_data.len());

                Some(PerfData {
                    ancillary,
                    raw_data,
                })
            },
            Err(e) => {
                warn!("read_cpu failed: cpu={}, error={}", ctx.cpu(), e);
                None
            },
        }
    }

    fn end_reading_cpu(
        &mut self,
        ctx: &CpuReadContext) {
        let index = ctx.reader_index();

        trace!("end_reading_cpu: completing read for cpu={}", ctx.cpu());

        let reader = &mut self.readers[index];
        let cursor = &mut self.cursors[index];

        reader.end_reading(cursor);
    }

    #[cfg(target_os = "linux")]
    fn perf_fds(&self) -> Vec<(u32, BorrowedFd<'_>)> {
        /* Each leader's per-CPU ring is the one the kernel marks
         * readable; non-leader event types redirect into the same ring
         * via `PERF_EVENT_IOC_SET_OUTPUT`, so their fds are not
         * separately wakeable and are intentionally not exposed.
         *
         * Only CPUs selected by the builder's `target_cpus` are
         * returned. Leader rings exist on every CPU (all-CPU events such
         * as kernel records and `no_cpu_mask` events redirect into
         * them), but a consumer that masked CPUs out should not be handed
         * fds for them; that data still flows through the normal
         * `parse_all` path. */
        let mut fds: Vec<(u32, BorrowedFd<'_>)> = self
            .fd_cpus()
            .filter_map(|cpu| {
                let leader_id = self.leader_ids[&cpu];
                self.ring_bufs
                    .get(&leader_id)
                    .and_then(|buf| buf.borrowed_fd())
                    .map(|fd| (cpu, fd))
            })
            .collect();

        /* Deterministic ascending CPU order for consumers. */
        fds.sort_unstable_by_key(|(cpu, _)| *cpu);
        fds
    }

    fn take_in_process_writer(
        &mut self) -> Option<InProcessRingBufWriter> {
        self.in_process_ring_buf.as_mut().map(|rb| rb.writer())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_open_buf(attributes: Rc<perf_event_attr>) -> (CpuRingBuf, UnixStream) {
        let (descriptor, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut buf = CpuRingBuf::new(0, attributes);
        buf.fd = Some(descriptor.into_raw_fd());
        (buf, peer)
    }

    #[test]
    fn config() {
        let kernel = RingBufBuilder::for_kernel()
            .with_executable_mmap_records()
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
    fn perf_fds_respects_target_cpus() {
        /* Leader rings are created for every CPU (all-CPU events redirect
         * into them), but fd_cpus must only select the CPUs in the
         * builder's target_cpus. */
        let mut source = RingBufDataSource::new(
            1,
            None,
            Some(vec![3u16, 1u16]),
            None,
            None,
            None,
            None,
            None,
            None,
            None);

        for cpu in 0..4u32 {
            source.leader_ids.insert(cpu, cpu as u64);
        }

        let mut cpus: Vec<u32> = source.fd_cpus().collect();
        cpus.sort_unstable();
        assert_eq!(vec![1u32, 3u32], cpus);
    }

    #[test]
    fn fd_cpus_returns_all_when_unmasked() {
        /* With no target_cpus, every leader CPU is selected. */
        let mut source = RingBufDataSource::new(
            1,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None);

        for cpu in [2u32, 0u32, 1u32] {
            source.leader_ids.insert(cpu, cpu as u64);
        }

        let mut cpus: Vec<u32> = source.fd_cpus().collect();
        cpus.sort_unstable();
        assert_eq!(vec![0u32, 1u32, 2u32], cpus);
    }

    #[test]
    fn set_new_bufs_filter_failure_rolls_back_only_new() {
        let common_attrs = std::rc::Rc::new(RingBufBuilder::common_attributes());
        let mut ring_bufs = HashMap::new();

        ring_bufs.insert(1u64, CpuRingBuf::new(0, common_attrs.clone()));
        let before: HashSet<u64> = ring_bufs.keys().copied().collect();

        ring_bufs.insert(2u64, CpuRingBuf::new(0, common_attrs.clone()));
        ring_bufs.insert(3u64, CpuRingBuf::new(1, common_attrs.clone()));

        let result = RingBufDataSource::set_new_bufs_filter(
            &ring_bufs,
            &before,
            |_| Err(IOError::from_raw_os_error(libc::EINVAL)));

        assert_eq!(Some(libc::EINVAL), result.unwrap_err().raw_os_error());

        RingBufDataSource::remove_new_bufs(&mut ring_bufs, &before);

        let remaining: HashSet<u64> = ring_bufs.keys().copied().collect();
        assert_eq!(before, remaining);
    }

    #[test]
    fn tracepoint_fd_exhaustion_reclaims_optional_ksymbols_and_retries() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let mut ring_bufs = HashMap::new();
        ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
        let mut optional = CpuRingBuf::new(0, attrs.clone());
        let (descriptor, mut peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        optional.fd = Some(descriptor.into_raw_fd());
        ring_bufs.insert(2, optional);
        let mut ksymbol_buf_ids = HashSet::from([2]);
        let mut attempts = 0;

        let (before, ()) = RingBufDataSource::add_required_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            true,
            "a tracepoint",
            |bufs| {
                attempts += 1;
                if attempts == 1 {
                    bufs.insert(3, CpuRingBuf::new(0, attrs.clone()));
                    return Err(IOError::from_raw_os_error(libc::EMFILE));
                }
                assert!(!bufs.contains_key(&3));
                assert_eq!(0, peer.read(&mut [0u8; 1]).unwrap());
                assert!(!bufs[&2].is_open());
                bufs.insert(4, CpuRingBuf::new(0, attrs.clone()));
                Ok(())
            }).unwrap();

        assert_eq!(2, attempts);
        assert_eq!(HashSet::from([1, 2]), before);
        assert_eq!(HashSet::from([1, 2, 4]), ring_bufs.keys().copied().collect());
        assert!(ksymbol_buf_ids.is_empty());
    }

    #[test]
    fn tracepoint_success_keeps_optional_ksymbols() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let mut ring_bufs = HashMap::new();
        ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
        let mut ksymbol_buf_ids = HashSet::from([1]);
        let (before, ()) = RingBufDataSource::add_required_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            true,
            "a tracepoint",
            |bufs| {
                bufs.insert(2, CpuRingBuf::new(0, attrs.clone()));
                Ok(())
            }).unwrap();
        assert_eq!(HashSet::from([1]), before);
        assert_eq!(HashSet::from([1]), ksymbol_buf_ids);
        assert_eq!(HashSet::from([1, 2]), ring_bufs.keys().copied().collect());
    }

    #[test]
    fn tracepoint_failure_keeps_optional_ksymbols_unless_fd_exhausted() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        for error in [libc::EINVAL, libc::EMFILE] {
            let mut ring_bufs = HashMap::new();
            ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
            let mut ksymbol_buf_ids = if error == libc::EINVAL {
                HashSet::from([1])
            } else {
                HashSet::new()
            };
            let original_ids = ksymbol_buf_ids.clone();
            let mut attempts = 0;
            let result = RingBufDataSource::add_required_bufs(
                &mut ring_bufs,
                &mut ksymbol_buf_ids,
                true,
                "a tracepoint",
                |bufs| -> IOResult<()> {
                    attempts += 1;
                    bufs.insert(2, CpuRingBuf::new(0, attrs.clone()));
                    Err(IOError::from_raw_os_error(error))
                });
            assert_eq!(Some(error), result.unwrap_err().raw_os_error());
            assert_eq!(1, attempts);
            assert_eq!(original_ids, ksymbol_buf_ids);
            assert_eq!(HashSet::from([1]), ring_bufs.keys().copied().collect());
        }
    }

    #[test]
    fn tracepoint_retry_failure_closes_partial_buffers() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let mut ring_bufs = HashMap::new();
        ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
        let mut ksymbol_buf_ids = HashSet::from([1]);
        let mut attempts = 0;
        let result = RingBufDataSource::add_required_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            true,
            "a tracepoint",
            |bufs| -> IOResult<()> {
                attempts += 1;
                bufs.insert(2, CpuRingBuf::new(0, attrs.clone()));
                Err(IOError::from_raw_os_error(if attempts == 1 {
                    libc::ENFILE
                } else {
                    libc::EINVAL
                }))
            });
        assert_eq!(Some(libc::EINVAL), result.unwrap_err().raw_os_error());
        assert_eq!(2, attempts);
        assert_eq!(HashSet::from([1]), ring_bufs.keys().copied().collect());
        assert!(ksymbol_buf_ids.is_empty());
    }

    #[test]
    fn tracepoint_fd_exhaustion_does_not_stop_active_lifecycle_capture() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let mut ring_bufs = HashMap::new();
        ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
        let mut ksymbol_buf_ids = HashSet::from([1]);
        let mut attempts = 0;
        let result = RingBufDataSource::add_required_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            false,
            "a tracepoint",
            |bufs| -> IOResult<()> {
                attempts += 1;
                bufs.insert(2, CpuRingBuf::new(0, attrs.clone()));
                Err(IOError::from_raw_os_error(libc::EMFILE))
            });
        assert_eq!(Some(libc::EMFILE), result.unwrap_err().raw_os_error());
        assert_eq!(1, attempts);
        assert_eq!(HashSet::from([1]), ksymbol_buf_ids);
        assert_eq!(HashSet::from([1]), ring_bufs.keys().copied().collect());
    }

    #[test]
    fn bpf_buf_exhaustion_retries_without_stale_files() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let (optional1, mut optional1_peer) = test_open_buf(attrs.clone());
        let (optional2, mut optional2_peer) = test_open_buf(attrs.clone());
        let (partial, mut partial_peer) = test_open_buf(attrs.clone());
        let (retry, mut retry_peer) = test_open_buf(attrs.clone());
        let retry_fd = retry.fd.unwrap();
        let mut partial = Some(partial);
        let mut retry = Some(retry);
        let mut ring_bufs = HashMap::from([
            (1, CpuRingBuf::new(0, attrs)),
            (2, optional1),
            (3, optional2),
        ]);
        let mut ksymbol_buf_ids = HashSet::from([2, 3]);
        let mut attempts = 0;

        let files = RingBufDataSource::add_required_bpf_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            true,
            |bufs, files| {
                attempts += 1;
                if attempts == 1 {
                    let buf = partial.take().unwrap();
                    files.push(PerfDataFile::new(4, buf.fd.unwrap()));
                    bufs.insert(4, buf);
                    return Err(IOError::from_raw_os_error(libc::EMFILE));
                }

                assert!(files.is_empty());
                assert!(!bufs.contains_key(&4));
                assert_eq!(0, partial_peer.read(&mut [0]).unwrap());
                assert_eq!(0, optional1_peer.read(&mut [0]).unwrap());
                assert_eq!(0, optional2_peer.read(&mut [0]).unwrap());
                let buf = retry.take().unwrap();
                files.push(PerfDataFile::new(5, buf.fd.unwrap()));
                bufs.insert(5, buf);
                Ok(())
            }).unwrap();

        assert_eq!(2, attempts);
        assert_eq!(1, files.len());
        assert_eq!((5, retry_fd), (files[0].id(), files[0].fd()));
        assert!(ksymbol_buf_ids.is_empty());
        assert_eq!(HashSet::from([1, 2, 3, 5]), ring_bufs.keys().copied().collect());
        assert!(!ring_bufs[&2].is_open());
        assert!(!ring_bufs[&3].is_open());
        drop(ring_bufs);
        assert_eq!(0, retry_peer.read(&mut [0]).unwrap());
    }

    #[test]
    fn bpf_buf_retry_failure_rolls_back_both_attempts() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let (optional, mut optional_peer) = test_open_buf(attrs.clone());
        let (first, mut first_peer) = test_open_buf(attrs.clone());
        let (second, mut second_peer) = test_open_buf(attrs);
        let mut first = Some(first);
        let mut second = Some(second);
        let mut ring_bufs = HashMap::from([(1, optional)]);
        let mut ksymbol_buf_ids = HashSet::from([1]);
        let mut attempts = 0;

        let result = RingBufDataSource::add_required_bpf_bufs(
            &mut ring_bufs,
            &mut ksymbol_buf_ids,
            true,
            |bufs, files| {
                attempts += 1;
                assert!(files.is_empty());
                let (id, buf, error) = if attempts == 1 {
                    (2, first.take().unwrap(), libc::ENFILE)
                } else {
                    assert_eq!(0, first_peer.read(&mut [0]).unwrap());
                    assert_eq!(0, optional_peer.read(&mut [0]).unwrap());
                    (3, second.take().unwrap(), libc::EINVAL)
                };
                files.push(PerfDataFile::new(id, buf.fd.unwrap()));
                bufs.insert(id, buf);
                Err(IOError::from_raw_os_error(error))
            });

        assert_eq!(Some(libc::EINVAL), result.err().unwrap().raw_os_error());
        assert_eq!(2, attempts);
        assert_eq!(HashSet::from([1]), ring_bufs.keys().copied().collect());
        assert!(ksymbol_buf_ids.is_empty());
        assert_eq!(0, second_peer.read(&mut [0]).unwrap());
    }

    #[test]
    fn bpf_buf_success_and_non_exhaustion_failure_preserve_symbols() {
        for fail in [false, true] {
            let attrs = Rc::new(RingBufBuilder::common_attributes());
            let (optional, mut optional_peer) = test_open_buf(attrs.clone());
            let (required, mut required_peer) = test_open_buf(attrs);
            let required_fd = required.fd.unwrap();
            let mut required = Some(required);
            let mut ring_bufs = HashMap::from([(1, optional)]);
            let mut ksymbol_buf_ids = HashSet::from([1]);
            let mut attempts = 0;

            let result = RingBufDataSource::add_required_bpf_bufs(
                &mut ring_bufs,
                &mut ksymbol_buf_ids,
                true,
                |bufs, files| {
                    attempts += 1;
                    let buf = required.take().unwrap();
                    files.push(PerfDataFile::new(2, buf.fd.unwrap()));
                    bufs.insert(2, buf);
                    if fail {
                        Err(IOError::from_raw_os_error(libc::EINVAL))
                    } else {
                        Ok(())
                    }
                });

            assert_eq!(1, attempts);
            assert_eq!(HashSet::from([1]), ksymbol_buf_ids);
            assert_eq!(
                std::io::ErrorKind::WouldBlock,
                optional_peer.read(&mut [0]).unwrap_err().kind());
            if fail {
                assert_eq!(Some(libc::EINVAL), result.err().unwrap().raw_os_error());
                assert_eq!(HashSet::from([1]), ring_bufs.keys().copied().collect());
                assert_eq!(0, required_peer.read(&mut [0]).unwrap());
            } else {
                let files = result.unwrap();
                assert_eq!(1, files.len());
                assert_eq!((2, required_fd), (files[0].id(), files[0].fd()));
                assert_eq!(HashSet::from([1, 2]), ring_bufs.keys().copied().collect());
                drop(ring_bufs);
                assert_eq!(0, required_peer.read(&mut [0]).unwrap());
            }
        }
    }

    #[test]
    fn bpf_map_open_exhaustion_reclaims_symbols_and_retries() {
        for (error, retry_error) in [
            (libc::EMFILE, None),
            (libc::ENFILE, None),
            (libc::EMFILE, Some(libc::EACCES)),
        ] {
            let attrs = Rc::new(RingBufBuilder::common_attributes());
            let (optional, mut peer) = test_open_buf(attrs);
            let mut source = RingBufDataSource::new(
                1, None, None, None, None, None, None, None, None, None);
            source.ring_bufs.insert(1, optional);
            source.ksymbol_buf_ids.insert(1);
            let mut attempts = 0;

            let result = PerfSession::open_bpf_map_with_retry(&mut source, || {
                attempts += 1;
                if attempts == 1 {
                    Err(IOError::from_raw_os_error(error))
                } else {
                    assert_eq!(0, peer.read(&mut [0]).unwrap());
                    match retry_error {
                        Some(error) => Err(IOError::from_raw_os_error(error)),
                        None => Ok(42),
                    }
                }
            });

            match retry_error {
                Some(error) => assert_eq!(Some(error), result.unwrap_err().raw_os_error()),
                None => assert_eq!(42, result.unwrap()),
            }
            assert_eq!(2, attempts);
            assert!(source.ksymbol_buf_ids.is_empty());
            assert!(!source.ring_bufs[&1].is_open());
        }
    }

    #[test]
    fn bpf_map_open_success_and_other_errors_keep_symbols() {
        for error in [None, Some(libc::EINVAL)] {
            let attrs = Rc::new(RingBufBuilder::common_attributes());
            let (optional, mut peer) = test_open_buf(attrs);
            let mut source = RingBufDataSource::new(
                1, None, None, None, None, None, None, None, None, None);
            source.ring_bufs.insert(1, optional);
            source.ksymbol_buf_ids.insert(1);
            let mut attempts = 0;

            let result = PerfSession::open_bpf_map_with_retry(&mut source, || {
                attempts += 1;
                match error {
                    Some(error) => Err(IOError::from_raw_os_error(error)),
                    None => Ok(42),
                }
            });

            match error {
                Some(error) => assert_eq!(Some(error), result.unwrap_err().raw_os_error()),
                None => assert_eq!(42, result.unwrap()),
            }
            assert_eq!(1, attempts);
            assert_eq!(HashSet::from([1]), source.ksymbol_buf_ids);
            assert_eq!(
                std::io::ErrorKind::WouldBlock,
                peer.read(&mut [0]).unwrap_err().kind());
        }
    }

    #[test]
    fn bpf_exhaustion_never_reclaims_symbols_after_recording_starts() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let mut source = RingBufDataSource::new(
            1, None, None, None, None, None, None, None, None, None);
        source.ring_bufs.insert(1, CpuRingBuf::new(0, attrs.clone()));
        source.ksymbol_buf_ids.insert(1);
        source.enable().unwrap();

        for disabled in [false, true] {
            if disabled {
                source.disable().unwrap();
            }
            let mut map_attempts = 0;
            let result = PerfSession::open_bpf_map_with_retry(&mut source, || {
                map_attempts += 1;
                Err(IOError::from_raw_os_error(libc::EMFILE))
            });
            assert_eq!(Some(libc::EMFILE), result.unwrap_err().raw_os_error());
            assert_eq!(1, map_attempts);

            let mut buf_attempts = 0;
            let result = RingBufDataSource::add_required_bpf_bufs(
                &mut source.ring_bufs,
                &mut source.ksymbol_buf_ids,
                !source.recording_started,
                |bufs, files| {
                    buf_attempts += 1;
                    bufs.insert(2, CpuRingBuf::new(0, attrs.clone()));
                    files.push(PerfDataFile::new(2, 123));
                    Err(IOError::from_raw_os_error(libc::ENFILE))
                });
            assert_eq!(Some(libc::ENFILE), result.err().unwrap().raw_os_error());
            assert_eq!(1, buf_attempts);
            assert_eq!(HashSet::from([1]), source.ksymbol_buf_ids);
            assert_eq!(HashSet::from([1]), source.ring_bufs.keys().copied().collect());
        }
    }

    #[test]
    fn failed_enable_does_not_allow_symbol_reclamation() {
        let attrs = Rc::new(RingBufBuilder::common_attributes());
        let (optional, mut peer) = test_open_buf(attrs);
        let mut source = RingBufDataSource::new(
            1, None, None, None, None, None, None, None, None, None);
        source.ring_bufs.insert(1, optional);
        source.ksymbol_buf_ids.insert(1);

        assert!(source.enable().is_err());
        assert!(!source.enabled);
        assert!(!source.reclaim_optional_fds());
        assert_eq!(HashSet::from([1]), source.ksymbol_buf_ids);
        assert_eq!(
            std::io::ErrorKind::WouldBlock,
            peer.read(&mut [0]).unwrap_err().kind());
    }

    #[test]
    #[ignore]
    fn add_event_filter_failure_closes_new_fds() {
        let tracefs = crate::tracefs::TraceFS::open().unwrap();

        let mut source = RingBufDataSource::new(
            1,
            None,
            None,
            None,
            Some(RingBufBuilder::for_tracepoint()),
            None,
            None,
            None,
            None,
            None);

        source.build().unwrap();

        let base = source.ring_bufs.len();

        let mut event = tracefs.find_event("syscalls", "sys_enter_sync").unwrap();
        event.extension_mut().set_perf_filter("I'm gonna blow you to smithereens!");

        assert!(source.add_event(&event).is_err());
        assert_eq!(base, source.ring_bufs.len());
    }

    #[test]
    fn read_time_skips_unknown_ring_buffer_id() {
        const TEST_RECORD_TYPE: u32 = 1024;

        let mut ring_buf = InProcessRingBuf::new(1);
        let mut writer = ring_buf.writer();
        let reader = ring_buf.create_reader();
        let mut cursor = CpuRingCursor::default();

        let mut record = Vec::new();
        let mut payload = Vec::new();

        let unknown_time = 10u64;
        let unknown_id = 99u64;
        payload.extend_from_slice(&unknown_time.to_ne_bytes());
        payload.extend_from_slice(&unknown_id.to_ne_bytes());
        abi::Header::write(TEST_RECORD_TYPE, 0, &payload, &mut record);
        writer.write(&record);

        record.clear();
        payload.clear();

        let known_time = 20u64;
        let known_id = 7u64;
        payload.extend_from_slice(&known_time.to_ne_bytes());
        payload.extend_from_slice(&known_id.to_ne_bytes());
        abi::Header::write(TEST_RECORD_TYPE, 0, &payload, &mut record);
        writer.write(&record);

        reader.begin_reading(&mut cursor);

        let mut ring_bufs = std::collections::HashMap::new();
        let common_attrs = std::rc::Rc::new(RingBufBuilder::common_attributes());
        ring_bufs.insert(known_id, CpuRingBuf::new(0, common_attrs));

        /* First call: encounters the unknown id, advances past just that one
         * record and returns None so the caller can retry. */
        let first = RingBufDataSource::read_time(
            &reader,
            &mut cursor,
            &ring_bufs);
        assert!(first.is_none());
        assert_eq!(24, cursor.start());

        /* Second call: now positioned on the known record, returns its time. */
        let (time, _buf) = RingBufDataSource::read_time(
            &reader,
            &mut cursor,
            &ring_bufs).unwrap();

        assert_eq!(known_time, time);
        assert_eq!(24, cursor.start());
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

        prof_event.add_callback(move |data| {
            let full_data = data.full_data();

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

    #[test]
    fn wakeup_watermark_rejected_when_equal_to_ring_size() {
        /* A watermark equal to the data area must be rejected by build();
         * the kernel would otherwise never reach it. */
        let pages = 1;
        let ring_bytes = ring_data_bytes(pages);
        let watermark = ring_bytes as u32;
        let err = match RingBufSessionBuilder::new()
            .with_page_count(pages)
            .with_wakeup_watermark(watermark)
            .build()
        {
            Ok(_) => panic!("build() must reject watermark == ring size"),
            Err(err) => err,
        };

        let expected = format!(
            "wakeup_watermark ({} bytes) must be smaller than the per-CPU \
             ring data area ({} bytes from {} pages); the kernel would \
             never wake the perf fds",
            watermark, ring_bytes, pages);
        assert_eq!(format!("{}", err), expected);
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn wakeup_watermark_rejected_when_above_ring_size() {
        /* A watermark strictly larger than the data area must also be
         * rejected. */
        let pages = 1;
        let ring_bytes = ring_data_bytes(pages);
        let watermark = (ring_bytes + 1) as u32;
        let err = match RingBufSessionBuilder::new()
            .with_page_count(pages)
            .with_wakeup_watermark(watermark)
            .build()
        {
            Ok(_) => panic!("build() must reject watermark > ring size"),
            Err(err) => err,
        };

        let expected = format!(
            "wakeup_watermark ({} bytes) must be smaller than the per-CPU \
             ring data area ({} bytes from {} pages); the kernel would \
             never wake the perf fds",
            watermark, ring_bytes, pages);
        assert_eq!(format!("{}", err), expected);
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn wakeup_watermark_accepted_when_below_ring_size() {
        /* A watermark strictly smaller than the data area must pass the
         * builder-level validation. */
        let pages = 1;
        let ring_bytes = ring_data_bytes(pages);
        let watermark = (ring_bytes - 1) as u32;
        if let Err(err) = RingBufSessionBuilder::new()
            .with_page_count(pages)
            .with_wakeup_watermark(watermark)
            .build()
        {
            let msg = format!("{}", err);
            assert!(
                !msg.contains("wakeup_watermark"),
                "watermark < ring size must not trigger validation error, \
                 got: {}",
                msg);
        }
    }
}
