use super::UriMatchRedirectService;
use crate::StatusCode;
use rama_core::Layer;

#[derive(Debug, Clone)]
pub struct UriMatchRedirectLayer<R> {
    status_code: StatusCode,
    match_replace: R,
}

impl<R: Clone, S> Layer<S> for UriMatchRedirectLayer<R> {
    type Service = UriMatchRedirectService<R, S>;

    fn layer(&self, inner: S) -> Self::Service {
        UriMatchRedirectService::new(self.status_code, self.match_replace.clone(), inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        UriMatchRedirectService::new(self.status_code, self.match_replace, inner)
    }
}

impl<R> UriMatchRedirectLayer<R> {
    /// Creates a new "see other" (303) [`UriMatchRedirectLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn to(match_replace: R) -> Self {
        Self {
            status_code: StatusCode::SEE_OTHER,
            match_replace,
        }
    }

    /// Creates a new "moved permanently" (301) [`UriMatchRedirectLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn moved(match_replace: R) -> Self {
        Self {
            status_code: StatusCode::MOVED_PERMANENTLY,
            match_replace,
        }
    }

    /// Creates a new "found" (302) [`UriMatchRedirectLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn found(match_replace: R) -> Self {
        Self {
            status_code: StatusCode::FOUND,
            match_replace,
        }
    }

    /// Creates a new "temporary redirect" (307) [`UriMatchRedirectLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn temporary(match_replace: R) -> Self {
        Self {
            status_code: StatusCode::TEMPORARY_REDIRECT,
            match_replace,
        }
    }

    /// Creates a new "permanent redirect" (308) [`UriMatchRedirectLayer`]
    /// with the given [`UriMatchReplace`] implementation.
    ///
    /// [`UriMatchReplace`]: rama_net::http::uri::UriMatchReplace
    #[must_use]
    pub fn permanent(match_replace: R) -> Self {
        Self {
            status_code: StatusCode::PERMANENT_REDIRECT,
            match_replace,
        }
    }
}
