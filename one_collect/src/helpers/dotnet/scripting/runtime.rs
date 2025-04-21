use super::*;

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
            .with_fn("with_gc_restarts", Self::with_gc_restarts);
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
