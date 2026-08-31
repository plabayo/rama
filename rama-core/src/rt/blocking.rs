//! Blocking boundaries for asynchronous Rama services and I/O.
//!
//! The runtime in this module is continuously driven on a dedicated thread.
//! This matters for services that return before their background protocol
//! tasks are finished, such as streaming HTTP responses, WebSockets, and
//! multiplexed RPC clients.
//!
//! # Panics
//!
//! Blocking operations in this module must not run directly on an asynchronous
//! executor thread.

use crate::{
    BlockingService, Service as AsyncService,
    extensions::{Extensions, ExtensionsRef},
    rt::{OwnedRuntime, OwnedRuntimeHandle},
};
#[cfg(feature = "dial9")]
use ::dial9::Dial9HandleTokioExt as _;
use core::{
    fmt,
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::Poll,
};
use parking_lot::Mutex;
use std::{
    io,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncSeek, AsyncWrite};
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio_util::io::SyncIoBridge;

const DEFAULT_THREAD_NAME: &str = "rama-blocking-runtime";
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The Tokio scheduler used by a [`Runtime`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeFlavor {
    /// A single-thread scheduler, driven continuously by the runtime owner
    /// thread.
    #[default]
    CurrentThread,
    /// A multi-thread scheduler with the requested number of worker threads.
    MultiThread {
        /// Number of Tokio worker threads.
        worker_threads: usize,
    },
}

/// Builder for a dedicated blocking-boundary [`Runtime`].
#[derive(Debug)]
pub struct RuntimeBuilder {
    thread_name: String,
    shutdown_timeout: Duration,
    flavor: RuntimeFlavor,
    flavor_explicit: bool,
    #[cfg(feature = "dial9")]
    dial9_recorder: RuntimeDial9Recorder,
    #[cfg(feature = "dial9")]
    dial9_attach_options: Option<::dial9::TokioAttachOptions>,
    #[cfg(feature = "dial9")]
    dial9_may_be_enabled: bool,
}

#[cfg(feature = "dial9")]
#[derive(Debug)]
enum RuntimeDial9Recorder {
    FromEnv,
    Disabled,
    Custom(Box<::dial9::Recorder>),
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self {
            thread_name: DEFAULT_THREAD_NAME.to_owned(),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            flavor: RuntimeFlavor::CurrentThread,
            flavor_explicit: false,
            #[cfg(feature = "dial9")]
            dial9_recorder: RuntimeDial9Recorder::FromEnv,
            #[cfg(feature = "dial9")]
            dial9_attach_options: None,
            #[cfg(feature = "dial9")]
            dial9_may_be_enabled: implicit_dial9_may_be_enabled(),
        }
    }
}

#[cfg(feature = "dial9")]
fn implicit_dial9_may_be_enabled() -> bool {
    match std::env::var("DIAL9_ENABLED") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "f" | "false" | "0" | "n" | "no" | "off"
        ),
        // Let dial9 decide unknown or non-Unicode values. This avoids silently
        // disabling telemetry if its environment syntax expands in the future.
        Err(std::env::VarError::NotUnicode(_)) => true,
    }
}

impl RuntimeBuilder {
    /// Create a runtime builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the name of the dedicated runtime owner thread.
        pub fn thread_name(mut self, name: impl Into<String>) -> Self {
            self.thread_name = name.into();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum time spent shutting down Tokio work when the final
        /// runtime lease is dropped.
        pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
            self.shutdown_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Use a current-thread Tokio scheduler.
        ///
        /// With the `dial9` feature, this overrides the implicit environment
        /// config when telemetry is disabled. Enabled telemetry needs the
        /// multi-thread scheduler and conflicts with this setting.
        pub fn current_thread(mut self) -> Self {
            self.flavor = RuntimeFlavor::CurrentThread;
            self.flavor_explicit = true;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Use a multi-thread Tokio scheduler.
        ///
        /// With the `dial9` feature, this overrides the implicit environment
        /// config when telemetry is disabled, and its worker count applies to
        /// the instrumented runtime otherwise.
        pub fn worker_threads(mut self, worker_threads: usize) -> Self {
            self.flavor = RuntimeFlavor::MultiThread { worker_threads };
            self.flavor_explicit = true;
            self
        }
    }

    #[cfg(feature = "dial9")]
    rama_utils::macros::generate_set_and_with! {
        /// Set the [`Recorder`] this runtime records into.
        ///
        /// With the `dial9` feature, this defaults to resolving the `DIAL9_*`
        /// environment when the runtime is built. Combining an enabled recorder
        /// with [`with_current_thread`](Self::with_current_thread) is rejected
        /// by [`try_build`](Self::try_build). An implicit environment config
        /// yields to an explicit Rama scheduler when telemetry is disabled. Use
        /// [`without_dial9_recorder`](Self::without_dial9_recorder) to
        /// explicitly select a Rama-configured scheduler without dial9.
        ///
        /// An enabled recorder must produce a multi-thread runtime because dial9
        /// installs ambient telemetry handles on Tokio-owned worker threads.
        ///
        /// [`Recorder`]: dial9::Recorder
        #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
        pub fn dial9_recorder(
            mut self,
            dial9_recorder: Option<::dial9::Recorder>,
        ) -> Self {
            self.dial9_recorder = match dial9_recorder {
                Some(recorder) => RuntimeDial9Recorder::Custom(Box::new(recorder)),
                None => RuntimeDial9Recorder::Disabled,
            };
            self
        }
    }

    #[cfg(feature = "dial9")]
    rama_utils::macros::generate_set_and_with! {
        /// Set how this runtime is traced: task tracking, dumps, hooks, and its
        /// name in the trace.
        ///
        /// Only used alongside [`with_dial9_recorder`](Self::with_dial9_recorder).
        /// When unset, the runtime takes this builder's thread name. Set options
        /// and you name it yourself.
        #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
        pub fn dial9_attach_options(
            mut self,
            dial9_attach_options: ::dial9::TokioAttachOptions,
        ) -> Self {
            self.dial9_attach_options = Some(dial9_attach_options);
            self
        }
    }

    /// Build the dedicated runtime.
    pub fn try_build(self) -> io::Result<Runtime> {
        if matches!(
            self.flavor,
            RuntimeFlavor::MultiThread { worker_threads: 0 }
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blocking runtime worker thread count must be greater than zero",
            ));
        }

        let Self {
            thread_name,
            shutdown_timeout,
            flavor,
            flavor_explicit,
            #[cfg(feature = "dial9")]
            dial9_recorder,
            #[cfg(feature = "dial9")]
            dial9_attach_options,
            #[cfg(feature = "dial9")]
            dial9_may_be_enabled,
        } = self;

        #[cfg(not(feature = "dial9"))]
        {
            _ = flavor_explicit;
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) =
            mpsc::sync_channel::<io::Result<(OwnedRuntimeHandle, RuntimeFlavor)>>(1);
        let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);
        let runtime_thread_name = thread_name.clone();

        let thread = thread::Builder::new().name(thread_name).spawn(move || {
            #[cfg(feature = "dial9")]
            let runtime = match (|| -> io::Result<OwnedRuntime> {
                let plain = || {
                    build_tokio_runtime(flavor, &runtime_thread_name).map(OwnedRuntime::from_tokio)
                };

                match dial9_recorder {
                    RuntimeDial9Recorder::Disabled => plain(),
                    // An unset `DIAL9_ENABLED` means the implicit environment is
                    // off, so skip dial9 and leave Rama's scheduler in charge.
                    RuntimeDial9Recorder::FromEnv if !dial9_may_be_enabled => plain(),
                    RuntimeDial9Recorder::FromEnv => {
                        let (recorder, runtime) = ::dial9::recorder_from_env_with(|builder| {
                            configure_dial9_builder(builder, flavor, &runtime_thread_name);
                        })?;
                        // The environment resolved to telemetry-off after all;
                        // hand the scheduler choice back to Rama.
                        if !recorder.handle().is_enabled() {
                            drop((runtime, recorder));
                            return plain();
                        }
                        require_multi_thread(flavor, flavor_explicit)?;
                        Ok(OwnedRuntime::from_dial9((recorder, runtime)))
                    }
                    RuntimeDial9Recorder::Custom(recorder) => {
                        // A disabled recorder records nothing, so it does not
                        // constrain the scheduler.
                        if !recorder.handle().is_enabled() {
                            return plain();
                        }
                        require_multi_thread(flavor, flavor_explicit)?;
                        let mut builder = tokio::runtime::Builder::new_multi_thread();
                        builder.enable_all();
                        configure_dial9_builder(&mut builder, flavor, &runtime_thread_name);
                        let options = dial9_attach_options.unwrap_or_else(|| {
                            ::dial9::TokioAttachOptions::builder()
                                .runtime_name(runtime_thread_name.as_str())
                                .build()
                        });
                        let runtime = recorder.handle().attach_tokio_runtime(builder, options)?;
                        Ok(OwnedRuntime::from_dial9((*recorder, runtime)))
                    }
                }
            })() {
                Ok(runtime) => runtime,
                Err(err) => {
                    _ = ready_tx.send(Err(err));
                    return;
                }
            };
            #[cfg(not(feature = "dial9"))]
            let runtime = match build_tokio_runtime(flavor, &runtime_thread_name) {
                Ok(runtime) => OwnedRuntime::from_tokio(runtime),
                Err(err) => {
                    _ = ready_tx.send(Err(err));
                    return;
                }
            };

            let flavor = match describe_runtime_flavor(&runtime) {
                Ok(flavor) => flavor,
                Err(err) => {
                    _ = ready_tx.send(Err(err));
                    return;
                }
            };

            if ready_tx.send(Ok((runtime.handle(), flavor))).is_err() {
                return;
            }

            runtime.block_on(async move {
                _ = shutdown_rx.await;
            });
            runtime.shutdown(shutdown_timeout);
            _ = done_tx.send(());
        })?;

        let (handle, flavor) = match ready_rx.recv() {
            Ok(Ok(ready)) => ready,
            Ok(Err(err)) => {
                _ = thread.join();
                return Err(err);
            }
            Err(err) => {
                _ = thread.join();
                return Err(io::Error::other(err));
            }
        };

        Ok(Runtime {
            inner: Arc::new(RuntimeInner {
                handle,
                flavor,
                shutdown_timeout,
                shutdown_tx: Mutex::new(Some(shutdown_tx)),
                done_rx: Mutex::new(Some(done_rx)),
                thread: Mutex::new(Some(thread)),
            }),
        })
    }
}

fn build_tokio_runtime(
    flavor: RuntimeFlavor,
    thread_name: &str,
) -> io::Result<tokio::runtime::Runtime> {
    let mut builder = match flavor {
        RuntimeFlavor::CurrentThread => tokio::runtime::Builder::new_current_thread(),
        RuntimeFlavor::MultiThread { worker_threads } => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(worker_threads);
            builder
        }
    };
    builder.enable_all();
    builder.thread_name(format!("{thread_name}-worker"));
    builder.build()
}

/// Reject an explicit current-thread scheduler paired with enabled telemetry.
///
/// dial9 installs its ambient handles on Tokio-owned worker threads, so an
/// unset scheduler takes multi-thread implicitly rather than erroring.
#[cfg(feature = "dial9")]
fn require_multi_thread(flavor: RuntimeFlavor, flavor_explicit: bool) -> io::Result<()> {
    if flavor_explicit && matches!(flavor, RuntimeFlavor::CurrentThread) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dial9 telemetry at a blocking boundary requires a multi-thread Tokio runtime",
        ));
    }
    Ok(())
}

/// Apply this builder's scheduler settings to a dial9-instrumented runtime.
/// An unset worker count leaves Tokio's default in place.
#[cfg(feature = "dial9")]
fn configure_dial9_builder(
    builder: &mut tokio::runtime::Builder,
    flavor: RuntimeFlavor,
    thread_name: &str,
) {
    if let RuntimeFlavor::MultiThread { worker_threads } = flavor {
        builder.worker_threads(worker_threads);
    }
    builder.thread_name(format!("{thread_name}-worker"));
}

fn describe_runtime_flavor(runtime: &OwnedRuntime) -> io::Result<RuntimeFlavor> {
    match runtime.tokio_runtime().handle().runtime_flavor() {
        tokio::runtime::RuntimeFlavor::CurrentThread => Ok(RuntimeFlavor::CurrentThread),
        tokio::runtime::RuntimeFlavor::MultiThread => Ok(RuntimeFlavor::MultiThread {
            worker_threads: runtime.tokio_runtime().metrics().num_workers(),
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported Tokio runtime flavor",
        )),
    }
}

/// A cloneable, continuously driven Tokio runtime for blocking API boundaries.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Create a dedicated runtime with default settings.
    pub fn try_new() -> io::Result<Self> {
        RuntimeBuilder::new().try_build()
    }

    /// Create a [`RuntimeBuilder`].
    #[must_use]
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

    /// Return a cloneable handle targeting this runtime and telemetry session.
    #[must_use]
    pub fn handle(&self) -> OwnedRuntimeHandle {
        self.inner.handle.clone()
    }

    /// Return the scheduler flavor backing this runtime.
    #[must_use]
    pub fn flavor(&self) -> RuntimeFlavor {
        self.inner.flavor
    }

    /// Run `future` to completion, blocking the calling thread.
    ///
    /// This directly drives the future and does not create a dial9-tracked
    /// task. Prefer [`block_on_task`](Self::block_on_task) for owned work.
    ///
    /// # Panics
    ///
    /// Panics when Tokio rejects synchronously driving the runtime, such as
    /// directly from an asynchronous task executor thread. It can be called
    /// from ordinary synchronous threads, [`tokio::task::spawn_blocking`], and
    /// [`tokio::task::block_in_place`].
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.inner.handle.tokio_handle().block_on(future)
    }

    /// Run an owned future as a task on this runtime and block until it
    /// completes.
    ///
    /// This is the preferred entry point for blocking boundaries. With
    /// `dial9` enabled, the task is routed through the runtime's telemetry
    /// handle so wake tracking and Rama protocol events are preserved.
    ///
    /// # Panics
    ///
    /// Panics when Tokio rejects synchronously driving the runtime, such as
    /// directly from an asynchronous task executor thread. It can be called
    /// from ordinary synchronous threads, [`tokio::task::spawn_blocking`], and
    /// [`tokio::task::block_in_place`].
    pub fn block_on_task<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.handle.block_on_task(future)
    }

    /// Enter this runtime while synchronously constructing a runtime-bound
    /// value.
    ///
    /// This is primarily intended for protocol wrappers whose constructors
    /// synchronously call `tokio::spawn`.
    ///
    /// Work spawned directly by the closure only has Tokio context. Use
    /// [`OwnedRuntimeHandle::spawn`] through [`handle`](Self::handle) for tasks
    /// that must retain dial9 tracking.
    ///
    pub fn with_context<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = self.inner.handle.enter();
        f()
    }

    /// Wrap an asynchronous Rama service in a blocking boundary.
    pub fn service<S>(&self, service: S) -> Service<S> {
        Service::new(service, self.clone())
    }

    /// Wrap an asynchronous stream as a blocking iterator.
    pub fn stream<S>(&self, stream: S) -> Stream<S>
    where
        S: crate::futures::Stream,
    {
        Stream::new(stream, self.clone())
    }

    /// Wrap asynchronous I/O as blocking `std::io` traits.
    pub fn io<T>(&self, io: T) -> Io<T>
    where
        T: Unpin,
    {
        Io::new(io, self.clone())
    }
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("handle", &self.inner.handle)
            .finish_non_exhaustive()
    }
}

struct RuntimeInner {
    handle: OwnedRuntimeHandle,
    flavor: RuntimeFlavor,
    shutdown_timeout: Duration,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    done_rx: Mutex<Option<mpsc::Receiver<()>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

fn finish_runtime_shutdown(
    thread: thread::JoinHandle<()>,
    done_rx: Option<mpsc::Receiver<()>>,
    wait_timeout: Duration,
) -> bool {
    let should_join = match done_rx {
        Some(done_rx) => match done_rx.recv_timeout(wait_timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    runtime_thread = thread.thread().name().unwrap_or("<unnamed>"),
                    ?wait_timeout,
                    "blocking runtime shutdown timed out; detaching owner thread"
                );
                false
            }
        },
        None => true,
    };

    if should_join {
        _ = thread.join();
    }
    should_join
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.lock().take() {
            _ = shutdown_tx.send(());
        }

        let Some(thread) = self.thread.lock().take() else {
            return;
        };

        let done_rx = self.done_rx.lock().take();
        let wait_timeout = self
            .shutdown_timeout
            .saturating_add(Duration::from_millis(100));

        // Waiting on the owner from one of its own workers would make runtime
        // shutdown wait on the worker that is waiting here. Blocking an
        // unrelated async executor thread in Drop is equally surprising. A
        // small reaper preserves bounded shutdown and timeout diagnostics in
        // both cases.
        if thread.thread().id() == thread::current().id() || Handle::try_current().is_ok() {
            if let Err(err) = thread::Builder::new()
                .name("rama-blocking-runtime-reaper".to_owned())
                .spawn(move || {
                    _ = finish_runtime_shutdown(thread, done_rx, wait_timeout);
                })
            {
                tracing::warn!(
                    %err,
                    "failed to spawn blocking runtime reaper; detaching owner thread"
                );
            }
            return;
        }

        _ = finish_runtime_shutdown(thread, done_rx, wait_timeout);
    }
}

/// An asynchronous service exposed through a synchronous [`BlockingService`]
/// boundary.
///
/// The wrapper owns `S` directly and clones it for each owned asynchronous
/// task. Use `Arc<S>` as the service type when calls should share one service
/// instance.
#[derive(Debug, Clone)]
pub struct Service<S> {
    inner: S,
    runtime: Runtime,
}

impl<S> Service<S> {
    /// Create a blocking service using `runtime`.
    #[must_use]
    pub fn new(inner: S, runtime: Runtime) -> Self {
        Self { inner, runtime }
    }

    /// Borrow the asynchronous service.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Borrow the runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Consume this boundary and return its service and runtime.
    #[must_use]
    pub fn into_parts(self) -> (S, Runtime) {
        (self.inner, self.runtime)
    }

    /// Serve `input`, blocking until the asynchronous service returns.
    pub fn serve<Input>(&self, input: Input) -> Result<Guarded<S::Output>, S::Error>
    where
        S: AsyncService<Input> + Clone,
        Input: Send + 'static,
    {
        <Self as BlockingService<Input>>::serve(self, input)
    }
}

impl<S, Input> BlockingService<Input> for Service<S>
where
    S: AsyncService<Input> + Clone,
    Input: Send + 'static,
{
    type Output = Guarded<S::Output>;
    type Error = S::Error;

    fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let inner = self.inner.clone();
        let output = self
            .runtime
            .block_on_task(async move { inner.serve(input).await })?;
        Ok(Guarded::new(output, self.runtime.clone()))
    }
}

/// A value carrying a runtime lease.
///
/// The runtime remains driven until this value is consumed or dropped.
#[derive(Debug)]
pub struct Guarded<T> {
    inner: T,
    runtime: Runtime,
}

impl<T> Guarded<T> {
    /// Guard `inner` with a runtime lease.
    #[must_use]
    pub fn new(inner: T, runtime: Runtime) -> Self {
        Self { inner, runtime }
    }

    /// Borrow the runtime lease.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Transform the guarded value while retaining its runtime lease.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Guarded<U> {
        Guarded {
            inner: f(self.inner),
            runtime: self.runtime,
        }
    }

    /// Consume the guard and return both components.
    #[must_use]
    pub fn into_parts(self) -> (T, Runtime) {
        (self.inner, self.runtime)
    }
}

impl<T> Deref for Guarded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Guarded<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> AsRef<T> for Guarded<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Guarded<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

/// An asynchronous stream exposed as a blocking [`Iterator`].
///
/// Each item is polled directly on the runtime and is not a separate
/// dial9-tracked task. Tasks spawned by the stream through a telemetry-aware
/// [`OwnedRuntimeHandle`] remain tracked.
#[derive(Debug)]
pub struct Stream<S> {
    inner: Pin<Box<S>>,
    runtime: Runtime,
}

impl<S> Stream<S>
where
    S: crate::futures::Stream,
{
    /// Create a blocking stream.
    #[must_use]
    pub fn new(stream: S, runtime: Runtime) -> Self {
        Self {
            inner: Box::pin(stream),
            runtime,
        }
    }

    /// Borrow the runtime lease.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Consume the wrapper and return the pinned stream and runtime.
    #[must_use]
    pub fn into_parts(self) -> (Pin<Box<S>>, Runtime) {
        (self.inner, self.runtime)
    }
}

impl<S> Iterator for Stream<S>
where
    S: crate::futures::Stream,
{
    type Item = S::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let runtime = self.runtime.clone();
        runtime.block_on(core::future::poll_fn(|cx| {
            match self.inner.as_mut().poll_next(cx) {
                Poll::Ready(item) => Poll::Ready(item),
                Poll::Pending => Poll::Pending,
            }
        }))
    }
}

/// Asynchronous I/O exposed through blocking `std::io` traits.
///
/// I/O is polled directly through [`SyncIoBridge`] and is not a separate
/// dial9-tracked task. Background tasks spawned through a telemetry-aware
/// [`OwnedRuntimeHandle`] remain tracked.
#[derive(Debug)]
pub struct Io<T> {
    inner: SyncIoBridge<T>,
    runtime: Runtime,
}

impl<T> Io<T>
where
    T: Unpin,
{
    /// Create a blocking I/O wrapper.
    #[must_use]
    pub fn new(io: T, runtime: Runtime) -> Self {
        let inner = SyncIoBridge::new_with_handle(io, runtime.inner.handle.tokio_handle().clone());
        Self { inner, runtime }
    }

    /// Borrow the asynchronous I/O object.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        self.inner.as_ref()
    }

    /// Mutably borrow the asynchronous I/O object.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.as_mut()
    }

    /// Borrow the runtime lease.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Consume the wrapper and return the asynchronous I/O object and runtime.
    #[must_use]
    pub fn into_parts(self) -> (T, Runtime) {
        (self.inner.into_inner(), self.runtime)
    }

    /// Shut down the asynchronous write side.
    pub fn shutdown(&mut self) -> io::Result<()>
    where
        T: AsyncWrite,
    {
        self.inner.shutdown()
    }
}

impl<T> io::Read for Io<T>
where
    T: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<T> io::BufRead for Io<T>
where
    T: AsyncBufRead + Unpin,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt);
    }
}

impl<T> io::Write for Io<T>
where
    T: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }
}

impl<T> io::Seek for Io<T>
where
    T: AsyncSeek + Unpin,
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl<T> ExtensionsRef for Io<T>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        self.inner.as_ref().extensions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::service_fn;
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn spawned_tasks_continue_between_calls() {
        let runtime = Runtime::try_new().unwrap();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_task = Arc::clone(&completed);

        runtime.block_on(async move {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                completed_task.store(true, Ordering::Release);
            });
        });

        for _ in 0..100 {
            if completed.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("spawned task did not make progress after block_on returned");
    }

    #[test]
    fn service_output_keeps_runtime_alive() {
        let runtime = Runtime::try_new().unwrap();
        let service = runtime.service(service_fn(|()| async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                _ = tx.send(42_u8);
            });
            Ok::<_, core::convert::Infallible>(rx)
        }));

        let output = service.serve(()).unwrap();
        drop(service);
        drop(runtime);
        let (rx, runtime) = output.into_parts();
        assert_eq!(runtime.block_on(rx).unwrap(), 42);
    }

    #[test]
    fn service_preserves_the_callers_ownership_type() {
        #[derive(Clone, Copy)]
        struct ZstService;

        impl crate::Service<()> for ZstService {
            type Output = ();
            type Error = core::convert::Infallible;

            fn serve(
                &self,
                (): (),
            ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
                core::future::ready(Ok(()))
            }
        }

        let service = Runtime::try_new().unwrap().service(ZstService);
        service.serve(()).unwrap();
        let (inner, _) = service.into_parts();
        let _: ZstService = inner;
    }

    #[test]
    fn stream_is_a_blocking_iterator() {
        let runtime = Runtime::try_new().unwrap();
        let mut stream = runtime.stream(crate::futures::stream::iter([1, 2, 3]));
        assert_eq!(stream.by_ref().collect::<Vec<_>>(), [1, 2, 3]);
    }

    #[test]
    fn cloned_runtime_supports_concurrent_callers() {
        let runtime = Runtime::try_new().unwrap();
        let threads = (0..4)
            .map(|value| {
                let runtime = runtime.clone();
                thread::spawn(move || {
                    runtime.block_on(async move {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        value
                    })
                })
            })
            .collect::<Vec<_>>();

        let mut output = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        output.sort_unstable();
        assert_eq!(output, [0, 1, 2, 3]);
    }

    #[test]
    fn blocking_runtime_works_from_tokio_spawn_blocking() {
        let runtime = Runtime::try_new().unwrap();
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let output = outer.block_on(async move {
            tokio::task::spawn_blocking(move || {
                assert_eq!(runtime.block_on(async { 21_u8 }), 21);
                runtime.block_on_task(async { 42_u8 })
            })
            .await
            .unwrap()
        });
        assert_eq!(output, 42);
    }

    #[test]
    fn blocking_runtime_works_from_tokio_block_in_place() {
        let runtime = Runtime::try_new().unwrap();
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let output = outer.block_on(async move {
            tokio::task::block_in_place(move || runtime.block_on_task(async { 42_u8 }))
        });
        assert_eq!(output, 42);
    }

    #[test]
    fn with_context_works_from_tokio_spawn_blocking() {
        let runtime = Runtime::try_new().unwrap();
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let output = outer.block_on(async move {
            tokio::task::spawn_blocking(move || {
                let task = runtime.with_context(|| tokio::spawn(async { 42_u8 }));
                runtime.block_on(task).unwrap()
            })
            .await
            .unwrap()
        });
        assert_eq!(output, 42);
    }

    #[test]
    fn final_runtime_lease_can_drop_on_worker() {
        let builder = Runtime::builder();
        #[cfg(feature = "dial9")]
        let builder = builder.without_dial9_recorder();
        let runtime = builder
            .with_worker_threads(1)
            .with_shutdown_timeout(Duration::from_secs(1))
            .try_build()
            .unwrap();
        let task_runtime = runtime.clone();
        let (release_tx, release_rx) = oneshot::channel();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        _ = runtime.handle().spawn(async move {
            _ = release_rx.await;
            drop(task_runtime);
            done_tx.send(()).unwrap();
        });

        drop(runtime);
        release_tx.send(()).unwrap();
        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("runtime drop on its worker must not wait for owner shutdown");
    }

    #[test]
    fn multi_thread_runtime_is_supported() {
        let builder = Runtime::builder();
        #[cfg(feature = "dial9")]
        let builder = builder.without_dial9_recorder();
        let runtime = builder.with_worker_threads(2).try_build().unwrap();
        assert_eq!(
            runtime.flavor(),
            RuntimeFlavor::MultiThread { worker_threads: 2 }
        );
        assert_eq!(
            runtime.block_on(async { tokio::spawn(async { 42_u8 }).await.unwrap() }),
            42
        );
    }

    #[test]
    fn zero_worker_threads_is_rejected() {
        let builder = Runtime::builder();
        #[cfg(feature = "dial9")]
        let builder = builder.without_dial9_recorder();
        let err = builder.with_worker_threads(0).try_build().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn default_builder_defers_dial9_environment_resolution() {
        let builder = Runtime::builder();
        assert!(matches!(
            builder.dial9_recorder,
            RuntimeDial9Recorder::FromEnv
        ));

        let builder = builder.without_dial9_recorder();
        assert!(matches!(
            builder.dial9_recorder,
            RuntimeDial9Recorder::Disabled
        ));
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn implicit_disabled_dial9_uses_current_thread_scheduler() {
        let mut builder = Runtime::builder();
        builder.dial9_may_be_enabled = false;

        let runtime = builder.try_build().unwrap();
        assert_eq!(runtime.flavor(), RuntimeFlavor::CurrentThread);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn explicit_scheduler_overrides_disabled_implicit_dial9() {
        let mut builder = Runtime::builder();
        builder.dial9_may_be_enabled = false;

        let runtime = builder.with_worker_threads(1).try_build().unwrap();
        assert_eq!(
            runtime.flavor(),
            RuntimeFlavor::MultiThread { worker_threads: 1 }
        );
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn explicit_worker_threads_apply_to_the_dial9_runtime() {
        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let runtime = Runtime::builder()
            .with_dial9_recorder(crate::rt::dial9_test_util::recorder(temp_dir.path()))
            .with_worker_threads(2)
            .try_build()
            .unwrap();

        assert_eq!(
            runtime.flavor(),
            RuntimeFlavor::MultiThread { worker_threads: 2 }
        );
        drop(runtime);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn dial9_attach_options_are_applied() {
        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let runtime = Runtime::builder()
            .with_dial9_recorder(crate::rt::dial9_test_util::recorder(temp_dir.path()))
            .with_dial9_attach_options(
                ::dial9::TokioAttachOptions::builder()
                    .tokio_instrumentation_enabled(false)
                    .build(),
            )
            .try_build()
            .unwrap();

        // The recorder is live, but this runtime opted out of instrumentation,
        // so its workers never join the session.
        let service = runtime.service(service_fn(|()| async {
            Ok::<_, core::convert::Infallible>(::dial9::Dial9Handle::current().is_enabled())
        }));
        assert!(!*service.serve(()).unwrap());
        drop(service);
        drop(runtime);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn disabled_dial9_recorder_keeps_the_rama_scheduler() {
        let runtime = Runtime::builder()
            .with_dial9_recorder(::dial9::recorder_disabled())
            .with_current_thread()
            .try_build()
            .unwrap();

        assert_eq!(runtime.flavor(), RuntimeFlavor::CurrentThread);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn dial9_tracks_blocking_service_root() {
        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let runtime = Runtime::builder()
            .with_dial9_recorder(crate::rt::dial9_test_util::recorder(temp_dir.path()))
            .try_build()
            .unwrap();
        let service = runtime.service(service_fn(|()| async {
            Ok::<_, core::convert::Infallible>(::dial9::Dial9Handle::current().is_enabled())
        }));

        assert!(matches!(
            runtime.flavor(),
            RuntimeFlavor::MultiThread { worker_threads } if worker_threads > 0
        ));
        assert!(*service.serve(()).unwrap());
        drop(service);
        drop(runtime);
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn dial9_tracks_tasks_spawned_through_handle() {
        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let runtime = Runtime::builder()
            .with_dial9_recorder(crate::rt::dial9_test_util::recorder(temp_dir.path()))
            .try_build()
            .unwrap();
        let handle = runtime.handle();
        let (tx, rx) = mpsc::sync_channel(1);

        thread::spawn(move || {
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
    fn dial9_rejects_current_thread_scheduler() {
        let _slot = crate::rt::dial9_test_util::recorder_slot();
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let err = Runtime::builder()
            .with_dial9_recorder(crate::rt::dial9_test_util::recorder(temp_dir.path()))
            .with_current_thread()
            .try_build()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn io_bridges_async_io() {
        let runtime = Runtime::try_new().unwrap();
        let (client, mut server) = tokio::io::duplex(64);
        let server_task = runtime.handle().spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            server.write_all(b"hello").await.unwrap();
            let mut input = Vec::new();
            server.read_to_end(&mut input).await.unwrap();
            input
        });

        let mut client = runtime.io(client);
        let mut output = [0_u8; 5];
        client.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"hello");
        client.write_all(b"goodbye").unwrap();
        client.shutdown().unwrap();
        assert_eq!(runtime.block_on(server_task).unwrap(), b"goodbye");
    }

    #[test]
    #[should_panic]
    fn blocking_inside_async_executor_panics() {
        let runtime = Runtime::try_new().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                runtime.block_on(core::future::ready(()));
            });
    }

    #[test]
    fn shutdown_wait_timeout_detaches_owner_thread() {
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let (exited_tx, exited_rx) = mpsc::sync_channel(1);
        let owner = thread::Builder::new()
            .name("stuck-test-runtime".to_owned())
            .spawn(move || {
                release_rx.recv().unwrap();
                drop(done_tx);
                exited_tx.send(()).unwrap();
            })
            .unwrap();

        assert!(!finish_runtime_shutdown(
            owner,
            Some(done_rx),
            Duration::from_millis(1),
        ));
        release_tx.send(()).unwrap();
        exited_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }
}
