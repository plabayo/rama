//! HTTP-to-FastCGI client types.

use tokio::io::{AsyncRead, AsyncWrite};

use rama_core::{Service, error::BoxError};
use rama_http_types::{Request, Response};
use rama_net::client::EstablishedClientConnection;
use rama_utils::macros::define_inner_service_accessors;

use crate::client::{FastCgiClientRequest, FastCgiClientResponse, send_on};

use super::convert::{fastcgi_response_to_http, http_request_to_fastcgi};

/// A connector that translates HTTP requests into FastCGI connections.
///
/// Wraps an inner FastCGI connector `S`. When called with an HTTP [`Request`], it
/// collects the body, maps HTTP metadata to CGI environment variables, and passes
/// the resulting [`FastCgiClientRequest`] to the inner connector.
///
/// The returned [`EstablishedClientConnection`] carries the IO stream ready for
/// use with [`send_on`][crate::client::send_on] or inside [`FastCgiHttpClient`].
#[derive(Debug, Clone)]
pub struct FastCgiHttpClientConnector<S> {
    inner: S,
}

impl<S> FastCgiHttpClientConnector<S> {
    /// Create a new [`FastCgiHttpClientConnector`] wrapping `inner`.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<Request> for FastCgiHttpClientConnector<S>
where
    S: Service<
        FastCgiClientRequest,
        Output = EstablishedClientConnection<IO, FastCgiClientRequest>,
        Error: Into<BoxError>,
    >,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = EstablishedClientConnection<IO, FastCgiClientRequest>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let fcgi_req = http_request_to_fastcgi(req).await?;
        self.inner.serve(fcgi_req).await.map_err(Into::into)
    }
}

/// HTTP-to-FastCGI client.
///
/// Wraps an inner FastCGI connector `S` — the same type that
/// [`FastCgiClient`][crate::client::FastCgiClient] accepts — and provides a
/// fully HTTP-native interface:
///
/// 1. Collects the HTTP request body.
/// 2. Maps HTTP metadata to CGI environment variables.
/// 3. Connects to the backend via the inner connector.
/// 4. Runs the FastCGI exchange.
/// 5. Parses the CGI stdout into an HTTP [`Response`].
#[derive(Debug, Clone)]
pub struct FastCgiHttpClient<S> {
    inner: S,
}

impl<S> FastCgiHttpClient<S> {
    /// Create a new [`FastCgiHttpClient`] wrapping the given connector.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<Request> for FastCgiHttpClient<S>
where
    S: Service<
        FastCgiClientRequest,
        Output = EstablishedClientConnection<IO, FastCgiClientRequest>,
        Error: Into<BoxError>,
    >,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let fcgi_req = http_request_to_fastcgi(req).await?;
        let EstablishedClientConnection {
            input: fcgi_req,
            mut conn,
        } = self.inner.serve(fcgi_req).await.map_err(Into::into)?;
        let fcgi_resp: FastCgiClientResponse = send_on(&mut conn, 1, fcgi_req, false)
            .await
            .map_err(BoxError::from)?;
        Ok(fastcgi_response_to_http(fcgi_resp))
    }
}
