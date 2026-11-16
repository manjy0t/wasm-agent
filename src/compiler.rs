//! Bound both resident compilation jobs and the threads which perform them.
//!
//! A dedicated Rayon pool also contains Wasmtime's nested parallel iterators.
//! It is a thread budget, not CPU affinity or an OS CPU quota. Keeping the old
//! backend available permits an otherwise identical comparison on the VM.
use anyhow::{Context, Result};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::{oneshot, Semaphore};

#[derive(Default)]
struct Counts {
    submitted: AtomicU64,
    finished: AtomicU64,
}

pub struct Compiler {
    slots: Arc<Semaphore>,
    capacity: usize,
    pool: Option<rayon::ThreadPool>,
    counts: Arc<Counts>,
}

pub struct Timings {
    pub slot_wait_ms: f64,
    pub executor_wait_ms: f64,
    pub work_ms: f64,
}

impl Compiler {
    pub fn new(jobs: usize, threads: Option<usize>) -> Result<Self> {
        let pool = threads
            .map(|threads| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .thread_name(|i| format!("hal-compile-{i}"))
                    .build()
            })
            .transpose()?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(jobs)),
            capacity: jobs,
            pool,
            counts: Arc::new(Counts::default()),
        })
    }

    pub async fn run<T, F>(&self, operation: F) -> Result<(T, Timings)>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let wait = Instant::now();
        let permit = self.slots.clone().acquire_owned().await?;
        let slot_wait_ms = wait.elapsed().as_secs_f64() * 1000.0;
        let queued = Instant::now();
        let counts = self.counts.clone();
        counts.submitted.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        let work = move || {
            // Cancellation of the HTTP request cannot release this slot while
            // compilation is still running. No unbounded orphan compilations.
            let _permit = permit;
            let start = Instant::now();
            let executor_wait_ms = queued.elapsed().as_secs_f64() * 1000.0;
            // A detached Rayon's task panic would otherwise abort the process.
            let result = catch_unwind(AssertUnwindSafe(operation))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("compiler task panicked")));
            let work_ms = start.elapsed().as_secs_f64() * 1000.0;
            counts.finished.fetch_add(1, Ordering::Relaxed);
            let _ = sender.send(result.map(|value| {
                (
                    value,
                    Timings {
                        slot_wait_ms,
                        executor_wait_ms,
                        work_ms,
                    },
                )
            }));
        };
        if let Some(pool) = &self.pool {
            pool.spawn_fifo(work);
        } else {
            tokio::task::spawn_blocking(work);
        }
        receiver.await.context("compiler task stopped")?
    }

    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "submitted": self.counts.submitted.load(Ordering::Relaxed),
            "finished": self.counts.finished.load(Ordering::Relaxed),
            "occupied_slots": self.capacity - self.slots.available_permits(),
            "job_limit": self.capacity,
            "dedicated_threads": self.pool.as_ref().map(|p| p.current_num_threads()),
        })
    }
}
