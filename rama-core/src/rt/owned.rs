//! Owned asynchronous runtimes with optional dial9 task tracking.

use core::future::Future;
use std::time::Duration;
use tokio::runtime::{EnterGuard, Handle, Runtime};

#[cfg(feature = "dial9")]
use crate::telemetry::tracing;

/// A cloneable handle targeting one specific [`OwnedRuntime`].
///
/// Unlike an ambient spawn helper, this handle targets one Tokio runtime and,
/// when enabled, retains the dial9 telemetry session to which work belongs. It
/// can therefore spawn correctly instrumented tasks from arbitrary threads.
///
/// The handle does not keep the runtime itself alive. Retain the owning
/// [`OwnedRuntime`], a [`blocking::Runtime`](super::blocking::Runtime), or a
/// derived blocking wrapper while using it.
#[derive(Clone, Debug)]
pub struct OwnedRuntimeHandle {
    tokio: Handle,
    #[cfg(feature = "dial9")]
    dial9: ::dial9_tokio_telemetry::telemetry::TelemetryHandle,
}

impl OwnedRuntimeHandle {
    /// Capture the current Tokio runtime and dial9 telemetry session.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime context.
    #[must_use]
    pub fn current() -> Self {
        Self {
            tokio: Handle::current(),
            #[cfg(feature = "dial9")]
            dial9: ::dial9_tokio_telemetry::telemetry::TelemetryHandle::current(),
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
    /// session captured by this handle, even when called from another thread.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        #[cfg(feature = "dial9")]
        {
            let _enter = self.tokio.enter();
            self.dial9.spawn(future)
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
        Self {
            tokio,
            #[cfg(feature = "dial9")]
            dial9: ::dial9_tokio_telemetry::telemetry::TelemetryHandle::disabled(),
        }
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
    Dial9(::dial9_tokio_telemetry::TracedRuntime),
}

impl OwnedRuntime {
    /// Wrap a Tokio runtime.
    #[must_use]
    pub fn from_tokio(runtime: Runtime) -> Self {
        Self {
            inner: RuntimeInner::Tokio(runtime),
        }
    }

    /// Wrap a dial9 traced runtime and retain its telemetry guard.
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn from_dial9(runtime: ::dial9_tokio_telemetry::TracedRuntime) -> Self {
        Self {
            inner: RuntimeInner::Dial9(runtime),
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
            RuntimeInner::Dial9(runtime) => OwnedRuntimeHandle {
                tokio: runtime.runtime().handle().clone(),
                dial9: runtime.guard().handle(),
            },
        }
    }

    pub(crate) fn tokio_runtime(&self) -> &Runtime {
        match &self.inner {
            RuntimeInner::Tokio(runtime) => runtime,
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9(runtime) => runtime.runtime(),
        }
    }

    /// Enter the underlying Tokio runtime on the calling thread.
    pub fn enter(&self) -> EnterGuard<'_> {
        self.tokio_runtime().enter()
    }

    /// Run a possibly borrowed future to completion.
    ///
    /// This directly drives Tokio and does not create a dial9-tracked task.
    /// Prefer [`block_on_task`](Self::block_on_task) for owned work.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.tokio_runtime().block_on(future)
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
            RuntimeInner::Dial9(runtime) => runtime.block_on(future),
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
    /// Tokio supports a bounded consuming shutdown directly. dial9's traced
    /// runtime does not currently expose one, so its drop is isolated on a
    /// reaper thread and awaited for at most `grace`.
    pub fn shutdown_bounded(self, grace: Duration) {
        match self.inner {
            RuntimeInner::Tokio(runtime) => runtime.shutdown_timeout(grace),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9(runtime) => {
                let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
                let mut runtime = std::mem::ManuallyDrop::new(runtime);
                let spawned = std::thread::Builder::new()
                    .name("rama-runtime-dispose".to_owned())
                    .spawn(move || {
                        // SAFETY: the closure is the sole owner and takes the
                        // value exactly once.
                        drop(unsafe { std::mem::ManuallyDrop::take(&mut runtime) });
                        _ = done_tx.send(());
                    });
                match spawned {
                    Ok(thread) => match done_rx.recv_timeout(grace) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            if thread.join().is_err() {
                                tracing::error!("dial9 runtime dispose thread panicked");
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            tracing::warn!(
                                ?grace,
                                "dial9 runtime shutdown timed out; detaching dispose thread"
                            );
                        }
                    },
                    Err(err) => {
                        tracing::error!(
                            %err,
                            "failed to spawn dial9 runtime dispose thread; leaking runtime"
                        );
                    }
                }
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
    fn external_spawn_keeps_its_dial9_session() {
        use std::sync::mpsc;

        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let config = ::dial9_tokio_telemetry::Dial9Config::builder()
            .enabled(true)
            .base_path(temp_dir.path().join("owned-runtime.bin"))
            .max_file_size(1024 * 1024)
            .max_total_size(4 * 1024 * 1024)
            .build()
            .unwrap();
        let runtime = OwnedRuntime::from_dial9(
            ::dial9_tokio_telemetry::TracedRuntime::try_new(config).unwrap(),
        );
        let handle = runtime.handle();
        let (tx, rx) = mpsc::sync_channel(1);

        std::thread::spawn(move || {
            _ = handle.spawn(async move {
                tx.send(
                    ::dial9_tokio_telemetry::telemetry::TelemetryHandle::current().is_enabled(),
                )
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
        use std::sync::mpsc;

        let config = ::dial9_tokio_telemetry::Dial9Config::builder()
            .enabled(false)
            .build()
            .unwrap();
        let runtime = OwnedRuntime::from_dial9(
            ::dial9_tokio_telemetry::TracedRuntime::try_new(config).unwrap(),
        );
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
