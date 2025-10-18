use std::fmt;

use super::RewriteUriService;
use rama_core::Layer;

pub struct RewriteUriLayer<R> {
    match_replace: R,
}

impl<R: fmt::Debug> fmt::Debug for RewriteUriLayer<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RewriteUriLayer")
            .field("match_replace", &self.match_replace)
            .finish()
    }
}

impl<R: Clone> Clone for RewriteUriLayer<R> {
    fn clone(&self) -> Self {
        Self {
            match_replace: self.match_replace.clone(),
        }
    }
}

impl<R: Clone, S> Layer<S> for RewriteUriLayer<R> {
    type Service = RewriteUriService<R, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RewriteUriService::new(self.match_replace.clone(), inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        RewriteUriService::new(self.match_replace, inner)
    }
}

impl<R> RewriteUriLayer<R> {
    /// Creates a new [`RewriteUriLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn new(match_replace: R) -> Self {
        Self { match_replace }
    }
}
