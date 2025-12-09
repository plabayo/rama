use super::RewriteUriService;
use rama_core::Layer;

#[derive(Debug, Clone)]
pub struct RewriteUriLayer<R> {
    match_replace: R,
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
