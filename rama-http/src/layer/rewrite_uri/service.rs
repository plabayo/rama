use std::fmt;

use crate::Request;
use crate::utils::request_uri;
use rama_core::{Service, telemetry::tracing};
use rama_net::http::uri::{UriMatchError, UriMatchReplace};
use rama_utils::macros::define_inner_service_accessors;

// TODO: in future we can move this outside of rama-http
// and make it work on any request that is identified
// by a `Uri`.

/// Service which allows you to replace a [`Uri`]
/// using a [`UriMatchReplace`] to match and replace the incoming request [`Uri`].
///
/// [`Uri`]: crate::Uri
pub struct RewriteUriService<R, S> {
    match_replace: R,
    inner: S,
}

impl<R, S> fmt::Debug for RewriteUriService<R, S>
where
    R: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RewriteUriService")
            .field("match_replace", &self.match_replace)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<R, S> Clone for RewriteUriService<R, S>
where
    R: Clone,
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            match_replace: self.match_replace.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<R, S> RewriteUriService<R, S> {
    /// Creates a new `RewriteUriService` wrapping the `service`.
    pub fn new(match_replace: R, service: S) -> Self {
        Self {
            match_replace,
            inner: service,
        }
    }
}

impl<R, S> RewriteUriService<R, S> {
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

impl<ReqBody, R, S> Service<Request<ReqBody>> for RewriteUriService<R, S>
where
    S: Service<Request<ReqBody>>,
    R: UriMatchReplace + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let full_uri = request_uri(&req);
        if let Ok(uri) = self
            .match_replace
            .match_replace_uri(full_uri)
            .inspect_err(|err| match err {
                UriMatchError::NoMatch(uri) => {
                    tracing::trace!("no match found for uri: {uri}; ignore")
                }
                UriMatchError::Unexpected(err) => {
                    tracing::trace!("unexpected error while trying to match uri: {err}; ignore")
                }
            })
        {
            *req.uri_mut() = uri.into_owned()
        }
        self.inner.serve(req).await
    }
}
