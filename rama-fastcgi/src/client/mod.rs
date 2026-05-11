//! FastCGI client implementation for Rama.
//!
//! [`FastCgiClient`] wraps an inner connector service that establishes the IO stream,
//! then sends a request using FastCGI framing and returns the application's stdout as bytes.
//!
//! This is the "web server" side of the FastCGI protocol — the piece that translates
//! incoming requests into FastCGI framing and forwards them to a backend application.

mod error;
mod options;
mod proto;
mod types;

pub use error::ClientError;
pub use options::ClientOptions;
pub use proto::{send_on, send_on_with_options};
pub use types::{FastCgiClientRequest, FastCgiClientResponse};

use tokio::io::{AsyncRead, AsyncWrite};

use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
};
use rama_net::client::EstablishedClientConnection;
use rama_utils::macros::define_inner_service_accessors;

/// FastCGI client that wraps an inner connector service.
///
/// The inner service `S` establishes the IO connection; `FastCgiClient` then runs
/// the FastCGI protocol framing over it and returns the response.
///
/// For one-shot use on an already-established stream, see [`send_on`].
#[derive(Debug, Clone)]
pub struct FastCgiClient<S> {
    inner: S,
    options: ClientOptions,
}

impl<S> FastCgiClient<S> {
    /// Create a new [`FastCgiClient`] with the given inner connector and
    /// [`ClientOptions::default()`].
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            options: ClientOptions::default(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Replace the [`ClientOptions`] used for sending requests.
        pub fn options(mut self, options: ClientOptions) -> Self {
            self.options = options;
            self
        }
    }

    /// Get a reference to the current [`ClientOptions`].
    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<FastCgiClientRequest> for FastCgiClient<S>
where
    S: Service<
            FastCgiClientRequest,
            Output = EstablishedClientConnection<IO, FastCgiClientRequest>,
            Error: Into<BoxError>,
        >,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = FastCgiClientResponse;
    type Error = BoxError;

    async fn serve(&self, req: FastCgiClientRequest) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input: req, conn } = self
            .inner
            .serve(req)
            .await
            .context("establish FastCGI connection")?;
        // Apply read/write timeouts (if any) at the IO layer.
        let mut conn = Box::pin(
            rama_core::io::timeout::TimeoutIo::new(conn)
                .maybe_with_read_timeout(self.options.read_timeout)
                .maybe_with_write_timeout(self.options.write_timeout),
        );
        send_on_with_options(&mut conn, 1, req, false, &self.options)
            .await
            .context("send FastCGI request")
    }
}
