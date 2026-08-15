//! Blocking boundaries for asynchronous Rama services and I/O.
//!
//! The runtime in this module is continuously driven on a dedicated thread.
//! This matters for services that return before their background protocol
//! tasks are finished, such as streaming HTTP responses, WebSockets, and
//! multiplexed RPC clients.

use crate::{
    BlockingService, Service as AsyncService,
    extensions::{Extensions, ExtensionsRef},
};
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
#[derive(Debug, Clone)]
pub struct RuntimeBuilder {
    thread_name: String,
    shutdown_timeout: Duration,
    flavor: RuntimeFlavor,
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self {
            thread_name: DEFAULT_THREAD_NAME.to_owned(),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            flavor: RuntimeFlavor::CurrentThread,
        }
    }
}

impl RuntimeBuilder {
    /// Create a runtime builder with a current-thread Tokio scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the name of the dedicated runtime owner thread.
    #[must_use]
    pub fn thread_name(mut self, name: impl Into<String>) -> Self {
        self.thread_name = name.into();
        self
    }

    /// Set the maximum time spent shutting down Tokio work when the final
    /// runtime lease is dropped.
    #[must_use]
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Use a current-thread Tokio scheduler.
    #[must_use]
    pub fn current_thread(mut self) -> Self {
        self.flavor = RuntimeFlavor::CurrentThread;
        self
    }

    /// Use a multi-thread Tokio scheduler.
    #[must_use]
    pub fn worker_threads(mut self, worker_threads: usize) -> Self {
        self.flavor = RuntimeFlavor::MultiThread { worker_threads };
        self
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
        } = self;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<io::Result<Handle>>(1);
        let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);
        let runtime_thread_name = thread_name.clone();

        let thread = thread::Builder::new().name(thread_name).spawn(move || {
            let runtime = match build_tokio_runtime(flavor, &runtime_thread_name) {
                Ok(runtime) => runtime,
                Err(err) => {
                    _ = ready_tx.send(Err(err));
                    return;
                }
            };

            if ready_tx.send(Ok(runtime.handle().clone())).is_err() {
                return;
            }

            runtime.block_on(async move {
                _ = shutdown_rx.await;
            });
            runtime.shutdown_timeout(shutdown_timeout);
            _ = done_tx.send(());
        })?;

        let handle = match ready_rx.recv() {
            Ok(Ok(handle)) => handle,
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

/// A cloneable, continuously driven Tokio runtime for blocking API boundaries.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

impl Runtime {
    /// Create a dedicated current-thread runtime with default settings.
    pub fn try_new() -> io::Result<Self> {
        RuntimeBuilder::new().try_build()
    }

    /// Create a [`RuntimeBuilder`].
    #[must_use]
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

    /// Return the Tokio handle backing this runtime.
    #[must_use]
    pub fn handle(&self) -> &Handle {
        &self.inner.handle
    }

    /// Return the scheduler flavor backing this runtime.
    #[must_use]
    pub fn flavor(&self) -> RuntimeFlavor {
        self.inner.flavor
    }

    /// Run `future` to completion, blocking the calling thread.
    ///
    /// # Panics
    ///
    /// Panics when called from an asynchronous Tokio execution context. Use
    /// Rama's asynchronous APIs there, or move the blocking operation to a
    /// dedicated blocking thread.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        assert!(
            Handle::try_current().is_err(),
            "a Rama blocking API was called from an asynchronous Tokio context"
        );
        self.inner.handle.block_on(future)
    }

    /// Enter this runtime while synchronously constructing a runtime-bound
    /// value.
    ///
    /// This is primarily intended for protocol wrappers whose constructors
    /// synchronously call `tokio::spawn`.
    ///
    /// # Panics
    ///
    /// Panics when called from an asynchronous Tokio execution context.
    pub fn with_context<T>(&self, f: impl FnOnce() -> T) -> T {
        assert!(
            Handle::try_current().is_err(),
            "a Rama blocking runtime context was entered from an asynchronous Tokio context"
        );
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
    handle: Handle,
    flavor: RuntimeFlavor,
    shutdown_timeout: Duration,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    done_rx: Mutex<Option<mpsc::Receiver<()>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.lock().take() {
            _ = shutdown_tx.send(());
        }

        let Some(thread) = self.thread.lock().take() else {
            return;
        };

        if thread.thread().id() == thread::current().id() {
            return;
        }

        let should_join = match self.done_rx.lock().take() {
            Some(done_rx) => match done_rx.recv_timeout(
                self.shutdown_timeout
                    .saturating_add(Duration::from_millis(100)),
            ) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
                Err(mpsc::RecvTimeoutError::Timeout) => false,
            },
            None => true,
        };

        if should_join {
            _ = thread.join();
        }
    }
}

/// An asynchronous service exposed through a synchronous [`BlockingService`]
/// boundary.
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
        S: AsyncService<Input>,
    {
        <Self as BlockingService<Input>>::serve(self, input)
    }
}

impl<S, Input> BlockingService<Input> for Service<S>
where
    S: AsyncService<Input>,
{
    type Output = Guarded<S::Output>;
    type Error = S::Error;

    fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let output = self
            .runtime
            .block_on(async { self.inner.serve(input).await })?;
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
        let inner = SyncIoBridge::new_with_handle(io, runtime.handle().clone());
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
    fn multi_thread_runtime_is_supported() {
        let runtime = Runtime::builder().worker_threads(2).try_build().unwrap();
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
        let err = Runtime::builder()
            .worker_threads(0)
            .try_build()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn io_bridges_async_io() {
        let runtime = Runtime::try_new().unwrap();
        let (client, mut server) = tokio::io::duplex(64);
        runtime.block_on(async move {
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                server.write_all(b"hello").await.unwrap();
            });
        });

        let mut client = runtime.io(client);
        let mut output = String::new();
        client.read_to_string(&mut output).unwrap();
        assert_eq!(output, "hello");
        client.write_all(b"").unwrap();
    }

    #[test]
    #[should_panic(expected = "called from an asynchronous Tokio context")]
    fn blocking_inside_async_context_panics_clearly() {
        let runtime = Runtime::try_new().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                runtime.block_on(core::future::ready(()));
            });
    }
}
