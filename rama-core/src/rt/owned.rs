//! Owned asynchronous runtimes with optional dial9 task tracking.

use core::future::Future;
use std::time::Duration;
use tokio::runtime::{EnterGuard, Handle, Runtime};

#[cfg(feature = "dial9")]
use crate::telemetry::tracing;

/// A cloneable handle targeting one specific [`OwnedRuntime`].
///
/// Unlike an ambient spawn helper, this handle retains both the Tokio runtime
/// and, when enabled, the dial9 telemetry session to which work belongs. It can
/// therefore spawn correctly instrumented tasks from arbitrary threads.
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

    /// Borrow the underlying Tokio runtime handle.
    #[must_use]
    pub fn tokio_handle(&self) -> &Handle {
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
    pub(crate) fn block_on_task<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let task = self.spawn(future);
        self.tokio.block_on(async move {
            match task.await {
                Ok(output) => output,
                Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                Err(err) => std::panic::resume_unwind(Box::new(err)),
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

    /// Borrow the underlying Tokio runtime.
    #[must_use]
    pub fn tokio_runtime(&self) -> &Runtime {
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
        match self.inner {
            RuntimeInner::Tokio(runtime) => runtime.shutdown_timeout(grace),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9(runtime) => drop(runtime),
        }
    }

    /// Dispose of the runtime without blocking the caller indefinitely.
    ///
    /// Tokio supports a bounded consuming shutdown directly. dial9's traced
    /// runtime does not currently expose one, so its drop is isolated on a
    /// reaper thread instead.
    pub fn shutdown_bounded(self, grace: Duration) {
        match self.inner {
            RuntimeInner::Tokio(runtime) => runtime.shutdown_timeout(grace),
            #[cfg(feature = "dial9")]
            RuntimeInner::Dial9(runtime) => {
                let mut runtime = std::mem::ManuallyDrop::new(runtime);
                let spawned = std::thread::Builder::new()
                    .name("rama-runtime-dispose".to_owned())
                    .spawn(move || {
                        // SAFETY: the closure is the sole owner and takes the
                        // value exactly once.
                        drop(unsafe { std::mem::ManuallyDrop::take(&mut runtime) });
                    });
                if let Err(err) = spawned {
                    tracing::error!(
                        %err,
                        "failed to spawn dial9 runtime dispose thread; leaking runtime"
                    );
                }
            }
        }
    }
}

#[cfg(all(test, feature = "dial9"))]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn external_spawn_keeps_its_dial9_session() {
        let temp_dir = tempfile::tempdir().unwrap();
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
}
