use std::fmt;

use crate::service::web::response::{Headers, IntoResponse};
use crate::utils::request_uri;
use crate::{Body, Request, Response, StatusCode, StreamingBody};
use rama_core::Service;
use rama_core::bytes::Bytes;
use rama_error::BoxError;
use rama_http_headers::Location;
use rama_net::http::uri::UriMatchReplace;
use rama_utils::macros::define_inner_service_accessors;

/// Middleware to redirect a request using dynamic [`Uri`] derived
/// from the input request or a static one.
///
/// If no match is found it is instead the inner service which
/// instead makes serves the request and produces a response.
///
/// [`Uri`]: crate::Uri
pub struct UriMatchRedirectService<R, S> {
    status_code: StatusCode,
    match_replace: R,
    inner: S,
}

impl<R, S> fmt::Debug for UriMatchRedirectService<R, S>
where
    R: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UriMatchRedirectService")
            .field("status_code", &self.status_code)
            .field("match_replace", &self.match_replace)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<R, S> Clone for UriMatchRedirectService<R, S>
where
    R: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            status_code: self.status_code,
            match_replace: self.match_replace.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<R, S> UriMatchRedirectService<R, S> {
    /// Creates a new "see other" (303) [`UriMatchRedirectService`]
    /// with the given [`UriMatchReplace`] implementation to optionally redirect
    /// early returning instead of serving using the inner [`Service`].
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[inline]
    pub fn to(match_replace: R, service: S) -> Self {
        Self::new(StatusCode::SEE_OTHER, match_replace, service)
    }

    /// Creates a new "moved permanently" (301) [`UriMatchRedirectService`]
    /// with the given [`UriMatchReplace`] implementation to optionally redirect
    /// early returning instead of serving using the inner [`Service`].
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[inline]
    pub fn moved(match_replace: R, service: S) -> Self {
        Self::new(StatusCode::MOVED_PERMANENTLY, match_replace, service)
    }

    /// Creates a new "found" (302) [`UriMatchRedirectService`]
    /// with the given [`UriMatchReplace`] implementation to optionally redirect
    /// early returning instead of serving using the inner [`Service`].
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[inline]
    pub fn found(match_replace: R, service: S) -> Self {
        Self::new(StatusCode::FOUND, match_replace, service)
    }

    /// Creates a new "temporary redirect" (307) [`UriMatchRedirectService`]
    /// with the given [`UriMatchReplace`] implementation to optionally redirect
    /// early returning instead of serving using the inner [`Service`].
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[inline]
    pub fn temporary(match_replace: R, service: S) -> Self {
        Self::new(StatusCode::TEMPORARY_REDIRECT, match_replace, service)
    }

    /// Creates a new "temporary redirect" (307) [`UriMatchRedirectService`]
    /// with the given [`UriMatchReplace`] implementation to optionally redirect
    /// early returning instead of serving using the inner [`Service`].
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[inline]
    pub fn permanent(match_replace: R, service: S) -> Self {
        Self::new(StatusCode::PERMANENT_REDIRECT, match_replace, service)
    }

    pub(super) fn new(status_code: StatusCode, match_replace: R, service: S) -> Self {
        Self {
            status_code,
            match_replace,
            inner: service,
        }
    }
}

impl<R, S> UriMatchRedirectService<R, S> {
    define_inner_service_accessors!();

    /// Shared reference to the used [`UriMatchReplace`]
    #[must_use]
    pub fn match_replace_ref(&self) -> &R {
        &self.match_replace
    }

    /// Exclusive reference to the used [`UriMatchReplace`]
    #[must_use]
    pub fn match_replace_mut(&mut self) -> &mut R {
        &mut self.match_replace
    }
}

impl<ReqBody, ResBody, R, S> Service<Request<ReqBody>> for UriMatchRedirectService<R, S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    R: UriMatchReplace + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let full_uri = request_uri(&req);
        if let Some(uri) = self.match_replace.match_replace_uri(&full_uri) {
            return Ok((
                Headers::single(Location::from(uri.as_ref())),
                self.status_code,
            )
                .into_response());
        }

        let resp = self.inner.serve(req).await?;
        Ok(resp.map(Body::new))
    }
}
