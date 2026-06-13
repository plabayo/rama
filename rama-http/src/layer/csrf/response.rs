use super::ProtectionError;
use crate::{Response, StatusCode};

/// Builds the response returned by [`Csrf`] when a request fails CSRF protection.
///
/// Implemented for any `Fn(ProtectionError) -> Response<B> + Clone + Send + Sync + 'static`, so a
/// closure can be passed directly to
/// [`CsrfLayer::with_rejection_response`](super::CsrfLayer::with_rejection_response).
///
/// [`Csrf`]: super::Csrf
pub trait ResponseForProtectionError<B>: Clone + Send + Sync + 'static {
    /// Builds the response from the rejection error.
    fn response_for_protection_error(&self, error: ProtectionError) -> Response<B>;
}

impl<F, B> ResponseForProtectionError<B> for F
where
    F: Fn(ProtectionError) -> Response<B> + Clone + Send + Sync + 'static,
{
    fn response_for_protection_error(&self, error: ProtectionError) -> Response<B> {
        self(error)
    }
}

/// Default [`ResponseForProtectionError`] used by [`CsrfLayer::new`](super::CsrfLayer::new).
///
/// Produces a `403 Forbidden` response with an empty body. The originating [`ProtectionError`] is
/// attached to the response's extensions by [`Csrf`] itself, so it is present regardless of which
/// builder produced the response.
///
/// [`Csrf`]: super::Csrf
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct DefaultResponseForProtectionError;

impl<B: Default> ResponseForProtectionError<B> for DefaultResponseForProtectionError {
    fn response_for_protection_error(&self, _error: ProtectionError) -> Response<B> {
        let mut response = Response::new(B::default());
        *response.status_mut() = StatusCode::FORBIDDEN;
        response
    }
}
