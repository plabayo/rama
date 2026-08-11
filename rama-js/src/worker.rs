use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rama_core::graceful::ShutdownGuard;
use rama_core::telemetry::tracing;
use rama_utils::macros::generate_set_and_with;

use crate::error::{JsError, JsErrorKind};
use crate::runtime::{JsRuntime, JsRuntimeBuilder};
use crate::value::JsValue;

const WORKER_STACK_SIZE: usize = rama_utils::octets::mib(4);

type JobFn = Box<dyn FnOnce(&mut JsRuntime) + Send>;

struct Job {
    state: Arc<JobState>,
    run: JobFn,
}

impl Job {
    fn execute(self, runtime: &mut JsRuntime) {
        if self
            .state
            .status
            .compare_exchange(JOB_QUEUED, JOB_RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // A caller whose timeout elapsed while this job was still queued
            // cancels it. In particular, no abandoned caller can leave a
            // delayed state mutation behind.
            debug_assert_eq!(self.state.status.load(Ordering::Acquire), JOB_CANCELLED);
            return;
        }

        let _completion = JobCompletion(&self.state);
        (self.run)(runtime);
    }
}

struct JobCompletion<'a>(&'a JobState);

impl Drop for JobCompletion<'_> {
    fn drop(&mut self) {
        self.0.status.store(JOB_COMPLETED, Ordering::Release);
    }
}

struct JobState {
    status: AtomicU8,
}

impl JobState {
    fn queued() -> Self {
        Self {
            status: AtomicU8::new(JOB_QUEUED),
        }
    }

    fn cancel_if_queued(&self) -> bool {
        self.status
            .compare_exchange(
                JOB_QUEUED,
                JOB_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn is_running(&self) -> bool {
        self.status.load(Ordering::Acquire) == JOB_RUNNING
    }
}

struct CancelQueuedJob(Arc<JobState>);

impl Drop for CancelQueuedJob {
    fn drop(&mut self) {
        self.0.cancel_if_queued();
    }
}

const JOB_QUEUED: u8 = 0;
const JOB_RUNNING: u8 = 1;
const JOB_COMPLETED: u8 = 2;
const JOB_CANCELLED: u8 = 3;

/// A [`JsRuntime`] owned by a dedicated OS thread: the
/// compile-once, call-many execution model.
///
/// State (globals, function definitions, ...) persists for the lifetime
/// of the worker: execute a script once, then [`call`][Self::call] into
/// its functions per request. This is the model browsers and proxies use
/// for long-lived configuration scripts; spawn a fresh worker instead
/// when a script must not observe earlier executions.
///
/// The handle is cheap to clone; all handles share the same runtime and
/// jobs run strictly in order. The thread exits once the last handle is
/// dropped.
///
/// A job that exceeds the worker's [`timeout`][JsWorkerBuilder::with_timeout]
/// releases its caller with a [`JsErrorKind::Timeout`]. A job still waiting
/// in the queue is cancelled and never runs. A job already running cannot be
/// interrupted when it is inside an arbitrary Rust host callback; until that
/// exact job finishes the worker is [abandoned][Self::is_abandoned], and
/// later jobs fail fast with [`JsErrorKind::Setup`] instead of queueing behind
/// work that may never end. If it never returns, the worker is retired and
/// its thread remains occupied, so spawn a replacement. Without a timeout
/// configured, such a job blocks its caller and the queue indefinitely.
///
/// A panicking host function kills the worker: the pending and all later
/// jobs fail fast with a [`JsErrorKind::Setup`] error (fail-loud, rather
/// than continuing on a runtime in unknown state).
#[derive(Clone)]
pub struct JsWorker {
    jobs: flume::Sender<Job>,
    // closes when the worker thread exits: jobs racing into the dying
    // queue would otherwise leave their callers waiting forever
    death: tokio::sync::watch::Receiver<()>,
    timeout: Option<Duration>,
    // The exact running job that exceeded its timeout. Tracking the job,
    // rather than a shared progress counter, makes timeout/completion races
    // and concurrent queued timeouts unambiguous.
    stuck: Arc<Mutex<Option<Arc<JobState>>>>,
}

impl fmt::Debug for JsWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsWorker")
            .field("timeout", &self.timeout)
            .field("abandoned", &self.is_abandoned())
            .finish_non_exhaustive()
    }
}

/// Builder to configure and [`spawn`][Self::spawn] a [`JsWorker`].
pub struct JsWorkerBuilder {
    queue_capacity: usize,
    timeout: Option<Duration>,
    graceful: Option<ShutdownGuard>,
    thread_guard: Option<Arc<dyn Send + Sync + 'static>>,
}

impl Default for JsWorkerBuilder {
    fn default() -> Self {
        Self {
            queue_capacity: JsWorker::DEFAULT_QUEUE_CAPACITY,
            timeout: None,
            graceful: None,
            thread_guard: None,
        }
    }
}

impl fmt::Debug for JsWorkerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsWorkerBuilder")
            .field("queue_capacity", &self.queue_capacity)
            .field("timeout", &self.timeout)
            .field("graceful", &self.graceful)
            .field("thread_guard", &self.thread_guard.is_some())
            .finish()
    }
}

impl JsWorkerBuilder {
    generate_set_and_with! {
        /// Capacity of the worker's job queue
        /// (defaults to [`JsWorker::DEFAULT_QUEUE_CAPACITY`]).
        ///
        /// The queue is bounded so a stalled worker exerts backpressure on
        /// its callers instead of accumulating jobs without limit: once
        /// full, callers wait (async) for a slot.
        pub fn queue_capacity(mut self, capacity: usize) -> Self {
            self.queue_capacity = capacity;
            self
        }
    }

    generate_set_and_with! {
        /// Fail jobs with [`JsErrorKind::Timeout`] when their result did
        /// not arrive within the given duration, queue time included
        /// (defaults to `None`: callers wait indefinitely).
        ///
        /// A queued timed-out job is cancelled before execution. A job that
        /// already entered the runtime keeps running, bounded by the
        /// runtime's [limits][JsRuntimeBuilder]. Give the runtime an
        /// [execution time limit][JsRuntimeBuilder::set_execution_time_limit]
        /// to bound the job itself (at the cost of the worker when it
        /// fires). Requires a tokio runtime with timers enabled.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Tie the worker to a graceful shutdown guard
        /// (see [`rama_core::graceful`]).
        ///
        /// Once shutdown triggers, the worker finishes the jobs already
        /// accepted into its queue and exits; the shutdown in turn waits
        /// for that, as the worker thread holds the guard until it exits.
        /// Spawning a graceful worker requires an ambient tokio runtime.
        pub fn graceful(mut self, guard: Option<ShutdownGuard>) -> Self {
            self.graceful = guard;
            self
        }
    }

    generate_set_and_with! {
        /// Keep an opaque value alive for exactly the lifetime of the worker
        /// thread (defaults to `None`).
        ///
        /// The value moves into the thread before its runtime is built and is
        /// dropped when the thread exits, including after a panic. This lets a
        /// caller observe thread lifetime through a corresponding weak handle
        /// without coupling the worker to a particular accounting policy.
        pub fn thread_guard(
            mut self,
            guard: Option<Arc<dyn Send + Sync + 'static>>,
        ) -> Self {
            self.thread_guard = guard;
            self
        }
    }

    /// Spawn a worker thread owning a fresh [`JsRuntime`]
    /// built from the given builder.
    pub fn spawn(self, runtime: JsRuntimeBuilder) -> Result<JsWorker, JsError> {
        let (jobs, inbox) = flume::bounded::<Job>(self.queue_capacity);
        let (ready, built) = flume::bounded(1);
        let (death_tx, death) = tokio::sync::watch::channel(());

        let ctrl = match &self.graceful {
            Some(guard) => {
                let handle = tokio::runtime::Handle::try_current().map_err(|_e| {
                    JsError::new(
                        JsErrorKind::Setup,
                        "a graceful js worker requires an ambient tokio runtime",
                    )
                })?;
                let (ctrl_tx, ctrl_rx) = flume::bounded::<()>(1);
                let weak = guard.clone_weak();
                let mut death = death.clone();
                handle.spawn(async move {
                    tokio::select! {
                        _ = weak.cancelled() => {
                            let _sent = ctrl_tx.send_async(()).await;
                        }
                        _ = death.changed() => {}
                    }
                });
                Some(ctrl_rx)
            }
            None => None,
        };
        let guard = self.graceful;
        let thread_guard = self.thread_guard;
        std::thread::Builder::new()
            .name("rama-js-worker".to_owned())
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                // both dropped when the thread exits, even by panic unwind:
                // the death watch resolves waiting callers, the shutdown
                // guard lets a pending graceful shutdown complete
                let _death_tx = death_tx;
                let _guard = guard;
                let _thread_guard = thread_guard;

                let mut runtime = match runtime.build() {
                    Ok(runtime) => {
                        let _sent = ready.send(Ok(()));
                        runtime
                    }
                    Err(err) => {
                        let _sent = ready.send(Err(err));
                        return;
                    }
                };
                loop {
                    let next = match &ctrl {
                        Some(ctrl) => flume::Selector::new()
                            .recv(&inbox, |job| job.ok())
                            .recv(ctrl, |_stop| None)
                            .wait(),
                        None => inbox.recv().ok(),
                    };
                    match next {
                        Some(job) => {
                            job.execute(&mut runtime);
                            // a poisoned runtime cannot serve further
                            // jobs: exit fail-loud, like a panic would
                            if runtime.is_poisoned() {
                                return;
                            }
                        }
                        None => break,
                    }
                }
                // graceful stop: finish only the jobs accepted by the cutoff;
                // an open-ended drain would keep admitting senders blocked on
                // a full queue, letting a backlog extend shutdown indefinitely
                for _ in 0..inbox.len() {
                    match inbox.try_recv() {
                        Ok(job) => {
                            job.execute(&mut runtime);
                            if runtime.is_poisoned() {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|err| {
                JsError::new(
                    JsErrorKind::Setup,
                    format!("failed to spawn js worker thread: {err}"),
                )
            })?;

        built.recv().map_err(|_e| worker_gone())??;
        Ok(JsWorker {
            jobs,
            death,
            timeout: self.timeout,
            stuck: Arc::new(Mutex::new(None)),
        })
    }
}

impl JsWorker {
    /// Default capacity of the worker's job queue.
    pub const DEFAULT_QUEUE_CAPACITY: usize = 128;

    /// Create a [`JsWorkerBuilder`] to configure a new worker.
    #[must_use]
    pub fn builder() -> JsWorkerBuilder {
        JsWorkerBuilder::default()
    }

    /// Spawn a worker thread owning a fresh [`JsRuntime`] built from
    /// the given builder, with the default worker configuration.
    pub fn spawn(builder: JsRuntimeBuilder) -> Result<Self, JsError> {
        JsWorkerBuilder::default().spawn(builder)
    }

    /// Whether the worker is stuck on a job that overran its timeout.
    ///
    /// Abandoned workers refuse further jobs. The state clears by itself if
    /// the overrunning job does eventually finish; a job that never returns
    /// retires the worker for good, so spawn a replacement.
    #[must_use]
    pub fn is_abandoned(&self) -> bool {
        let mut stuck = self.stuck.lock();
        if stuck.as_ref().is_some_and(|job| job.is_running()) {
            true
        } else {
            *stuck = None;
            false
        }
    }

    /// Execute the given closure with exclusive access
    /// to the worker's runtime.
    ///
    /// Dropping this future cancels the job while it is still queued. Once the
    /// job is running it is allowed to finish, since arbitrary Rust host code
    /// cannot be interrupted safely.
    pub async fn run<T, F>(&self, f: F) -> Result<T, JsError>
    where
        F: FnOnce(&mut JsRuntime) -> Result<T, JsError> + Send + 'static,
        T: Send + 'static,
    {
        if self.is_abandoned() {
            return Err(abandoned());
        }

        let state = Arc::new(JobState::queued());
        let _cancel_queued = CancelQueuedJob(state.clone());
        let wait = async {
            let (reply, output) = tokio::sync::oneshot::channel();
            self.jobs
                .send_async(Job {
                    state: state.clone(),
                    run: Box::new(move |runtime| {
                        let _sent = reply.send(f(runtime));
                    }),
                })
                .await
                .map_err(|_e| worker_gone())?;
            let mut death = self.death.clone();
            tokio::select! {
                biased;
                output = output => output.map_err(|_e| worker_gone())?,
                _ = death.changed() => Err(worker_gone()),
            }
        };
        match self.timeout {
            Some(limit) => match tokio::time::timeout(limit, wait).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    let message = if state.cancel_if_queued() {
                        tracing::warn!(
                            "js worker job exceeded its {limit:?} timeout before it began: \
                             cancelling the queued job"
                        );
                        "js worker job timed out before it began and was cancelled"
                    } else if state.is_running() {
                        let mut stuck = self.stuck.lock();
                        if state.is_running() {
                            *stuck = Some(state);
                        }
                        tracing::warn!(
                            "js worker job exceeded its {limit:?} timeout while running: abandoning \
                             the worker until that job completes, its host callback cannot be interrupted"
                        );
                        "js worker job timed out; the worker is abandoned until that job completes"
                    } else {
                        // Completion and the tokio timeout may become ready in
                        // the same poll. The timeout still wins this call, but
                        // a completed job must not retire the worker.
                        "js worker job timed out as it completed"
                    };
                    Err(JsError::new(JsErrorKind::Timeout, message))
                }
            },
            None => wait.await,
        }
    }

    /// Evaluate a script on the worker's runtime,
    /// returning the value of its final expression.
    pub async fn eval<S>(&self, src: S) -> Result<JsValue, JsError>
    where
        S: AsRef<str> + Send + 'static,
    {
        self.run(move |runtime| runtime.eval(src)).await
    }

    /// Execute a script on the worker's runtime,
    /// discarding its final expression value.
    pub async fn exec<S>(&self, src: S) -> Result<(), JsError>
    where
        S: AsRef<str> + Send + 'static,
    {
        self.run(move |runtime| runtime.exec(src)).await
    }

    /// Call a global function (defined by a previously executed
    /// script, or registered as a host function) with the given arguments.
    pub async fn call<N, I, V>(&self, name: N, args: I) -> Result<JsValue, JsError>
    where
        N: AsRef<str> + Send + 'static,
        I: IntoIterator<Item = V>,
        V: Into<JsValue>,
    {
        let args: Vec<JsValue> = args.into_iter().map(Into::into).collect();
        self.run(move |runtime| runtime.call(name, args)).await
    }
}

fn worker_gone() -> JsError {
    JsError::new(JsErrorKind::Setup, "js worker is gone")
}

fn abandoned() -> JsError {
    JsError::new(
        JsErrorKind::Setup,
        "js worker is stuck on a job that exceeded its timeout",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_queued_run_future_cancels_its_job() {
        let worker = JsWorker::builder()
            .with_queue_capacity(1)
            .spawn(JsRuntimeBuilder::default())
            .unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let blocking_worker = worker.clone();
        let blocking = tokio::spawn(async move {
            blocking_worker
                .run(move |_runtime| {
                    let _sent = started_tx.send(());
                    release_rx.recv().map_err(|_error| {
                        JsError::new(JsErrorKind::Setup, "test release sender was dropped")
                    })
                })
                .await
        });
        started_rx.await.unwrap();

        let ran = Arc::new(AtomicUsize::new(0));
        let queued_worker = worker.clone();
        let queued_ran = ran.clone();
        let queued = tokio::spawn(async move {
            queued_worker
                .run(move |_runtime| {
                    queued_ran.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.jobs.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        release_tx.send(()).unwrap();
        blocking.await.unwrap().unwrap();
        worker.run(|_runtime| Ok(())).await.unwrap();

        assert_eq!(ran.load(Ordering::Relaxed), 0);
    }
}
