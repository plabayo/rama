//! FastCGI server implementation for Rama.
//!
//! [`FastCgiServer`] accepts incoming IO streams and handles the FastCGI framing.
//! It dispatches each request to an inner [`Service`] and writes the response back
//! over the same connection.
//!
//! The inner service receives a [`FastCgiRequest`] and must return a [`FastCgiResponse`].

mod conn;
mod options;
mod types;

pub use options::ServerOptions;
pub use types::{FastCgiRequest, FastCgiResponse};

use std::fmt;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use rama_core::{Service, bytes::Bytes, error::BoxError, io::Io, telemetry::tracing};

use crate::body::FastCgiBody;
use crate::proto::{ProtocolError, Role};

/// FastCGI server that accepts connections and dispatches requests to an inner service.
///
/// The inner service `S` must implement `Service<FastCgiRequest>` with
/// `Output = FastCgiResponse`. Each accepted connection is handled synchronously:
/// one request per connection at a time (multiplexed requests are not supported).
/// A second concurrent `FCGI_BEGIN_REQUEST` is replied to with
/// `FCGI_END_REQUEST{CantMpxConn}` (see [`ServerOptions::respond_cant_mpx_conn`]).
///
/// All three FastCGI roles are dispatched to the inner service:
/// [`Role::Responder`], [`Role::Authorizer`], and [`Role::Filter`].
/// The service inspects `req.role` to handle each case appropriately.
#[derive(Debug, Clone)]
pub struct FastCgiServer<S> {
    inner: S,
    options: ServerOptions,
}

impl<S> FastCgiServer<S> {
    /// Create a new [`FastCgiServer`] wrapping the given inner service.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            options: ServerOptions::default(),
        }
    }

    /// Replace the [`ServerOptions`] used for parsing connections.
    #[must_use]
    pub fn with_options(mut self, options: ServerOptions) -> Self {
        self.options = options;
        self
    }

    /// Get a reference to the current [`ServerOptions`].
    pub fn options(&self) -> &ServerOptions {
        &self.options
    }

    rama_utils::macros::define_inner_service_accessors!();
}

/// Error returned by the [`FastCgiServer`] when handling a connection.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<BoxError>,
}

#[derive(Debug)]
enum ErrorKind {
    IO,
    Protocol,
    Service,
}

impl Error {
    pub(crate) fn io(err: io::Error) -> Self {
        Self {
            kind: ErrorKind::IO,
            source: Some(err.into()),
        }
    }

    pub(crate) fn protocol(err: ProtocolError) -> Self {
        Self {
            kind: ErrorKind::Protocol,
            source: Some(err.into()),
        }
    }

    fn service(err: impl Into<BoxError>) -> Self {
        Self {
            kind: ErrorKind::Service,
            source: Some(err.into()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::IO => write!(f, "fastcgi server: I/O error"),
            ErrorKind::Protocol => write!(f, "fastcgi server: protocol error"),
            ErrorKind::Service => write!(f, "fastcgi server: inner service error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().and_then(|e| e.source())
    }
}

/// Abort the wrapped task on drop. Used to ensure that a body-reader task
/// spawned by `serve_connection` does not outlive the future when the future
/// is cancelled mid-request. Calling [`AbortOnDrop::disarm`] disables the
/// drop guard so the task can run to completion.
struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    /// Disable the abort-on-drop behaviour. Returns the wrapped handle so the
    /// caller can await it.
    fn disarm(mut self) -> Option<JoinHandle<T>> {
        self.0.take()
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

impl<S> FastCgiServer<S> {
    /// Handle a single FastCGI connection.
    ///
    /// The IO stream is split into independent read and write halves so that the
    /// inner service can stream the request body while the response is written
    /// concurrently. A background task reads `FCGI_STDIN` (and `FCGI_DATA` for
    /// Filter requests) records and forwards them to the service via an in-memory
    /// channel. If the web server sends `FCGI_ABORT_REQUEST` the body stream
    /// signals an `io::ErrorKind::ConnectionAborted` error to the service and the
    /// connection is closed after the response is written.
    pub async fn serve_connection<IO>(&self, stream: IO) -> Result<(), Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: Service<FastCgiRequest, Output = FastCgiResponse, Error: Into<BoxError>>,
    {
        // Apply read/write idle timeouts (if any) at the IO layer once so we
        // don't have to thread them through every record-reading call site.
        let timeout_io = rama_core::io::timeout::TimeoutIo::new(stream)
            .maybe_with_read_timeout(self.options.read_timeout)
            .maybe_with_write_timeout(self.options.write_timeout);
        let (read_half, mut write_half) = tokio::io::split(timeout_io);
        let mut rh = read_half;

        loop {
            let Some(begin) =
                conn::read_begin_and_params(&mut rh, &mut write_half, &self.options).await?
            else {
                tracing::debug!("fastcgi server: client closed connection");
                return Ok(());
            };
            let (request, reader_return_rx, mut task_guard) =
                self.spawn_body_reader(rh, begin).await;
            let keep_conn = request.keep_conn;
            let request_id = request.request_id;

            let response = match self.inner.serve(request).await {
                Ok(r) => r,
                Err(err) => {
                    // Politely tell the peer the application gave up so it
                    // doesn't sit on a half-written response stream.
                    if let Err(io_err) =
                        conn::write_service_failure_end_request(&mut write_half, request_id).await
                    {
                        tracing::debug!(
                            ?io_err,
                            rid = request_id,
                            "fastcgi server: failed to write END_REQUEST after inner-service error"
                        );
                    }
                    return Err(Error::service(err.into()));
                }
            };

            conn::write_response(&mut write_half, request_id, response, &self.options)
                .await
                .map_err(Error::io)?;

            let (was_aborted, returned_rh) =
                await_body_reader(&mut task_guard, reader_return_rx).await?;
            if was_aborted || !keep_conn {
                return Ok(());
            }
            rh = returned_rh;
        }
    }

    /// Build the [`FastCgiRequest`] handed to the inner service: spawn a
    /// background task that streams `FCGI_STDIN` (and `FCGI_DATA` for the
    /// Filter role) into mpsc-backed bodies, returning the read half of the
    /// stream once the streams are exhausted.
    async fn spawn_body_reader<IO>(
        &self,
        rh: ReadHalf<IO>,
        begin: conn::BeginParams,
    ) -> (
        FastCgiRequest,
        oneshot::Receiver<io::Result<(ReadHalf<IO>, bool)>>,
        Option<AbortOnDrop<()>>,
    )
    where
        IO: AsyncRead + AsyncWrite + Send + 'static,
    {
        let conn::BeginParams {
            request_id,
            role,
            keep_conn,
            params,
        } = begin;

        let (stdin_tx, stdin_rx) = mpsc::channel::<Result<Bytes, io::Error>>(16);
        let (data_tx, data_rx) = if role == Role::Filter {
            let (tx, rx) = mpsc::channel::<Result<Bytes, io::Error>>(16);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let (reader_return_tx, reader_return_rx) =
            oneshot::channel::<io::Result<(ReadHalf<IO>, bool)>>();

        let options_for_task = self.options.clone();
        let handle = tokio::spawn(async move {
            let result =
                conn::read_body_records(rh, request_id, stdin_tx, data_tx, options_for_task).await;
            if reader_return_tx.send(result).is_err() {
                tracing::debug!(
                    rid = request_id,
                    "fastcgi server: reader_return channel dropped before body-reader task delivered \
                     its result (parent future was cancelled)"
                );
            }
        });

        let stdin = FastCgiBody::from_channel(stdin_rx);
        let data = data_rx
            .map(FastCgiBody::from_channel)
            .unwrap_or_else(FastCgiBody::empty);

        let request = FastCgiRequest {
            request_id,
            role,
            keep_conn,
            params,
            stdin,
            data,
        };
        (request, reader_return_rx, Some(AbortOnDrop::new(handle)))
    }
}

/// Wait for the spawned body-reader task to finish, returning whether the
/// peer aborted the request and the read half so it can be reused for a
/// subsequent request on a keep-alive connection.
async fn await_body_reader<IO>(
    task_guard: &mut Option<AbortOnDrop<()>>,
    reader_return_rx: oneshot::Receiver<io::Result<(ReadHalf<IO>, bool)>>,
) -> Result<(bool, ReadHalf<IO>), Error> {
    if let Some(guard) = task_guard.take()
        && let Some(join_handle) = guard.disarm()
        && let Err(err) = join_handle.await
    {
        tracing::debug!(?err, "fastcgi server: body-reader task ended abnormally");
    }
    let (returned_rh, was_aborted) = reader_return_rx
        .await
        .map_err(|_recv_err| {
            Error::io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fastcgi server: body-reader task panicked or was aborted",
            ))
        })?
        .map_err(Error::io)?;
    Ok((was_aborted, returned_rh))
}

// ---------------------------------------------------------------------------
// Service<IO> impl
// ---------------------------------------------------------------------------

impl<S, IO> Service<IO> for FastCgiServer<S>
where
    S: Service<FastCgiRequest, Output = FastCgiResponse, Error: Into<BoxError>>,
    IO: Io + Unpin + Send + 'static,
{
    type Output = ();
    type Error = Error;

    #[inline]
    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        self.serve_connection(stream).await
    }
}
