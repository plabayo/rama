//! FastCGI client implementation for Rama.
//!
//! [`FastCgiClient`] wraps an inner connector service that establishes the IO stream,
//! then sends a request using FastCGI framing and returns the application's stdout as bytes.
//!
//! This is the "web server" side of the FastCGI protocol — the piece that translates
//! incoming requests into FastCGI framing and forwards them to a backend application.

mod error;
mod proto;
mod types;

pub use error::ClientError;
pub use proto::send_on;
pub use types::{FastCgiClientRequest, FastCgiClientResponse};

use tokio::io::{AsyncRead, AsyncWrite};

use rama_core::{Service, error::BoxError};
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
}

impl<S> FastCgiClient<S> {
    /// Create a new [`FastCgiClient`] with the given inner connector.
    pub fn new(inner: S) -> Self {
        Self { inner }
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
        let EstablishedClientConnection {
            input: req,
            mut conn,
        } = self.inner.serve(req).await.map_err(Into::into)?;
        send_on(&mut conn, 1, req, false)
            .await
            .map_err(Into::into)
    }
}
