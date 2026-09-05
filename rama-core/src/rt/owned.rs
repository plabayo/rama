//! Owned asynchronous runtimes with optional dial9 task tracking.

use core::future::Future;
use std::time::Duration;
use tokio::runtime::{EnterGuard, Handle, Runtime};

/// A cloneable handle targeting one specific [`OwnedRuntime`].
///
/// Unlike an ambient spawn helper, this handle targets one Tokio runtime. It
/// can therefore spawn correctly instrumented tasks from arbitrary threads.
///
/// The handle does not keep the runtime itself alive. Retain the owning
/// [`OwnedRuntime`], a [`blocking::Runtime`](super::blocking::Runtime), or a
/// derived blocking wrapper while using it.
#[derive(Clone, Debug)]
pub struct OwnedRuntimeHandle {
    tokio: Handle,
}

impl OwnedRuntimeHandle {
    /// Capture the current Tokio runtime.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime context.
    #[must_use]
    pub fn current() -> Self {
        Self {
            tokio: Handle::current(),
        }
    }

    pub(crate) fn tokio_handle(&self) -> &Handle {
        &self.tokio
    }

    /// Enter the targeted Tokio runtime on the calling thread.
    pub fn enter(&self) -> tokio::runtime::EnterGuard<'_> {
        self.tokio.enter()
    }

    /// Spawn an owned task on the targeted runtime.
    ///
    /// With `dial9` enabled, the task is associated with the exact telemetry
    /// session of the targeted runtime, even when called from another thread.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        #[cfg(feature = "dial9")]
        {
            ::dial9::spawn_in(&self.tokio, future)
        }
        #[cfg(not(feature = "dial9"))]
        {
            self.tokio.spawn(future)
        }
    }

    /// Spawn an owned task and block the calling thread until it completes.
    #[expect(
        clippy::panic,
        reason = "task cancellation is unrecoverable at this infallible blocking boundary"
    )]
    pub(crate) fn block_on_task<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let runtime = self.clone();
        self.tokio.block_on(async move {
            let task = runtime.spawn(future);
            match task.await {
                Ok(output) => output,
                Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                Err(err) => panic!("blocking runtime task was cancelled: {err}"),
            }
        })
    }
}

impl From<Handle> for OwnedRuntimeHandle {
    fn from(tokio: Handle) -> Self {
        Self { tokio }
    }
}

/// An owned Tokio runtime with an optional dial9 telemetry session.
///
/// This type centralizes runtime access for components that own their runtime.
/// Use [`block_on_task`](Self::block_on_task) and [`spawn`](Self::spawn) for
/// owned work that should participate in dial9 task tracking. The borrowed
/// [`block_on`](Self::block_on) variant exists for construction futures that
/// cannot be `'static`.
#[derive(Debug)]
pub struct OwnedRuntime {
    inner: RuntimeInner,
}

#[derive(Debug)]
enum RuntimeInner {
    Tokio(Runtime),
    #[cfg(feature = "dial9")]
    Dial9 {
        runtime: Runtime,
        recorder: ::dial9::Recorder,
    },
}

impl OwnedRuntime {
    /// Wrap a Tokio runtime.
    #[must_use]
    pub fn from_tokio(runtime: Runtime) -> Self {
        Self {
            inner: RuntimeInner::Tokio(runtime),
        }
    }

    /// Wrap a dial9 traced runtime and retain its recorder.
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn from_dial9(attached: ::dial9::AttachedRuntime) -> Self {
        let (recorder, runtime) = attached;
        Self {
            inner: RuntimeInner::Dial9 { runtime, recorder },
        }
    }

    /// Return a cloneable handle targeting this runtime and telemetry session.
    ///
    /// The handle does not keep this runtime alive.
    #[must_use]
    pub fn handle(&self) -> OwnedRuntimeHandle {
        match &self.inner {
            RuntimeInner::Tokio(runtime) => runtime.handle().clone().into(),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9 { runtime, .. } => runtime.handle().clone().into(),
        }
    }

    pub(crate) fn tokio_runtime(&self) -> &Runtime {
        match &self.inner {
            RuntimeInner::Tokio(runtime) => runtime,
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9 { runtime, .. } => runtime,
        }
    }

    /// Enter the underlying Tokio runtime on the calling thread.
    pub fn enter(&self) -> EnterGuard<'_> {
        self.tokio_runtime().enter()
    }

    /// Run a possibly borrowed future to completion.
    ///
    /// This directly drives Tokio and does not create a dial9-tracked task.
    /// An attached recorder still supplies the ambient handle for protocol
    /// events on the calling thread. The caller's previous handle is restored
    /// when the future completes or unwinds.
    /// Prefer [`block_on_task`](Self::block_on_task) for owned work.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        match &self.inner {
            RuntimeInner::Tokio(runtime) => runtime.block_on(future),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9 { runtime, recorder } => {
                // Runtime::block_on polls this future on the caller, which may
                // be a foreign thread that never ran a runtime thread hook.
                // Keep borrowed polling inline while selecting this recorder
                // independently of whatever telemetry context the caller has.
                struct RestoreHandle(Option<::dial9::Dial9Handle>);

                impl Drop for RestoreHandle {
                    fn drop(&mut self) {
                        if let Some(previous) = self.0.take() {
                            ::dial9::core::set_tl_handle(previous);
                        } else {
                            ::dial9::core::clear_tl_handle();
                        }
                    }
                }

                let _restore = RestoreHandle(::dial9::Dial9Handle::try_current_thread());
                ::dial9::core::set_tl_handle(recorder.handle().clone());
                runtime.block_on(future)
            }
        }
    }

    /// Run an owned future to completion as a task on this runtime.
    ///
    /// With `dial9` enabled, this routes through the runtime's exact telemetry
    /// handle so wake tracking remains active. Rama protocol events that use
    /// dial9's ambient handle require a multi-thread Tokio runtime.
    pub fn block_on_task<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.inner {
            RuntimeInner::Tokio(runtime) => runtime.block_on(future),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9 { runtime, .. } => ::dial9::block_on(runtime, future),
        }
    }

    /// Spawn an owned future on this runtime.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle().spawn(future)
    }

    pub(crate) fn shutdown(self, grace: Duration) {
        self.shutdown_bounded(grace);
    }

    /// Dispose of the runtime without blocking the caller indefinitely.
    ///
    /// `grace` is the total budget: workers get it to stop, and with `dial9`
    /// the trace pipeline drains within whatever of it remains.
    pub fn shutdown_bounded(self, grace: Duration) {
        match self.inner {
            RuntimeInner::Tokio(runtime) => runtime.shutdown_timeout(grace),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9 { runtime, recorder } => {
                let started = std::time::Instant::now();
                runtime.shutdown_timeout(grace);
                recorder.graceful_shutdown(grace.saturating_sub(started.elapsed()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_blocking_task_has_a_readable_panic() {
        let runtime = OwnedRuntime::from_tokio(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let handle = runtime.handle();
        drop(runtime);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle.block_on_task(async {});
        }))
        .unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(message.contains("blocking runtime task was cancelled"));
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn borrowed_block_on_scopes_dial9_on_foreign_threads_and_restores_after_unwind() {
        use ::dial9::{Dial9Handle, Dial9HandleTokioExt as _};

        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let recorder = crate::rt::dial9_test_util::recorder(temp_dir.path());
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        let tokio_runtime = recorder
            .handle()
            .attach_tokio_runtime(builder, ::dial9::TokioAttachOptions::default())
            .unwrap();
        let runtime = OwnedRuntime::from_dial9((recorder, tokio_runtime));

        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(Dial9Handle::try_current_thread().is_none());
                    for has_previous in [false, true] {
                        if has_previous {
                            ::dial9::core::set_tl_handle(Dial9Handle::disabled());
                        }
                        let caller = std::thread::current().id();
                        let mut borrowed = Vec::new();
                        runtime.block_on(async {
                            assert_eq!(std::thread::current().id(), caller);
                            assert!(Dial9Handle::current().is_enabled());
                            borrowed.push(42);
                            tokio::task::yield_now().await;
                            assert_eq!(std::thread::current().id(), caller);
                            assert!(Dial9Handle::current().is_enabled());
                        });
                        assert_eq!(borrowed, [42]);
                        assert_eq!(Dial9Handle::try_current_thread().is_some(), has_previous);
                        assert!(!Dial9Handle::current().is_enabled());

                        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.block_on(async {
                                assert!(Dial9Handle::current().is_enabled());
                                panic!("synthetic borrowed future panic");
                            });
                        }));
                        assert!(panic.is_err());
                        assert_eq!(Dial9Handle::try_current_thread().is_some(), has_previous);
                        assert!(!Dial9Handle::current().is_enabled());
                    }
                })
                .join()
                .unwrap();
        });
        runtime.shutdown_bounded(Duration::from_secs(1));
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn external_spawn_keeps_its_dial9_session() {
        use ::dial9::Dial9HandleTokioExt as _;
        use std::sync::mpsc;

        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let recorder = crate::rt::dial9_test_util::recorder(temp_dir.path());
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        let tokio_runtime = recorder
            .handle()
            .attach_tokio_runtime(builder, ::dial9::TokioAttachOptions::default())
            .unwrap();
        let runtime = OwnedRuntime::from_dial9((recorder, tokio_runtime));
        let handle = runtime.handle();
        let (tx, rx) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            _ = handle.spawn(async move {
                tx.send(::dial9::Dial9Handle::current().is_enabled())
                    .unwrap();
            });
        })
        .join()
        .unwrap();

        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        drop(runtime);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn dial9_shutdown_honors_the_grace_period() {
        use ::dial9::Dial9HandleTokioExt as _;
        use std::sync::mpsc;

        // A disabled recorder claims no process-wide slot, so this one needs no
        // serializing against the other dial9 tests.
        let recorder = ::dial9::recorder_disabled();
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all();
        let tokio_runtime = recorder
            .handle()
            .attach_tokio_runtime(builder, ::dial9::TokioAttachOptions::default())
            .unwrap();
        let runtime = OwnedRuntime::from_dial9((recorder, tokio_runtime));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        _ = runtime.spawn(async move {
            started_tx.send(()).unwrap();
            _ = release_rx.recv();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let started = std::time::Instant::now();
        runtime.shutdown_bounded(Duration::from_millis(10));
        assert!(started.elapsed() < Duration::from_secs(1));

        release_tx.send(()).unwrap();
    }
}
