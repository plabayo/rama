//! FastCGI application service that wraps an HTTP service.

use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
};
use rama_http_types::{Request, Response};
use rama_utils::macros::define_inner_service_accessors;

use crate::server::{FastCgiRequest, FastCgiResponse};

use super::convert::{fastcgi_request_to_http, http_response_to_fastcgi};

/// A FastCGI application service that wraps an inner HTTP service.
///
/// Converts each incoming [`FastCgiRequest`] into an HTTP [`Request`] by
/// reconstructing the method, URI, version, and headers from CGI environment
/// variables, calls the inner service, and serialises the returned HTTP
/// [`Response`] back to CGI stdout format for [`FastCgiServer`][crate::server::FastCgiServer].
///
/// This lets you deploy any existing HTTP handler as a FastCGI application
/// (e.g. behind nginx or Apache) without modifying the handler.
///
/// # Role handling
///
/// - **Responder**: full HTTP request/response conversion.
/// - **Authorizer**: the request body is empty; the HTTP response status code
///   is what the web server uses for allow/deny (200 = allowed). Response
///   headers prefixed with `Variable-` are forwarded to the downstream
///   application by the web server.
/// - **Filter**: the `FCGI_DATA` stream is not exposed through the HTTP
///   adapter; only the params and stdin are converted. Services that need
///   the raw data stream should implement `Service<FastCgiRequest>` directly.
#[derive(Debug, Clone)]
pub struct FastCgiHttpService<S> {
    inner: S,
}

impl<S> FastCgiHttpService<S> {
    /// Create a new [`FastCgiHttpService`] wrapping the given HTTP service.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> Service<FastCgiRequest> for FastCgiHttpService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = FastCgiResponse;
    type Error = BoxError;

    async fn serve(&self, req: FastCgiRequest) -> Result<Self::Output, Self::Error> {
        let http_req = fastcgi_request_to_http(req)
            .await
            .context("FastCgiHttpService: convert FastCGI request to HTTP")?;
        let http_resp = self
            .inner
            .serve(http_req)
            .await
            .map_err(Into::into)
            .context("FastCgiHttpService: inner HTTP service")?;
        http_response_to_fastcgi(http_resp)
            .await
            .context("FastCgiHttpService: serialise HTTP response to FastCGI")
    }
}
