//! Service that redirects all requests.

use crate::Request;
use crate::{HeaderValue, Response, StatusCode, Uri, header};
use rama_core::{Context, Service};
use std::{
    convert::{Infallible, TryFrom},
    fmt,
    marker::PhantomData,
};

/// Service that redirects all requests.
pub struct Redirect<ResBody> {
    status_code: StatusCode,
    location: HeaderValue,
    // Covariant over ResBody, no dropping of ResBody
    _marker: PhantomData<fn() -> ResBody>,
}

impl<ResBody> Redirect<ResBody> {
    /// Create a new [`Redirect`] that uses a [`302 TFound`][mdn] status code.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/302
    pub fn found(uri: &Uri) -> Self {
        Self::with_status_code(StatusCode::FOUND, uri)
    }

    /// Create a new [`Redirect`] that uses a [`307 Temporary Redirect`][mdn] status code.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/307
    pub fn temporary(uri: &Uri) -> Self {
        Self::with_status_code(StatusCode::TEMPORARY_REDIRECT, uri)
    }

    /// Create a new [`Redirect`] that uses a [`308 Permanent Redirect`][mdn] status code.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/308
    pub fn permanent(uri: &Uri) -> Self {
        Self::with_status_code(StatusCode::PERMANENT_REDIRECT, uri)
    }

    /// Create a new [`Redirect`] that uses the given status code.
    ///
    /// # Panics
    ///
    /// - If `status_code` isn't a [redirection status code][mdn] (3xx).
    /// - If `uri` isn't a valid [`HeaderValue`].
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#redirection_messages
    pub fn with_status_code(status_code: StatusCode, uri: &Uri) -> Self {
        assert!(
            status_code.is_redirection(),
            "not a redirection status code"
        );

        Self {
            status_code,
            location: HeaderValue::try_from(uri.to_string())
                .expect("URI isn't a valid header value"),
            _marker: PhantomData,
        }
    }
}

impl<State, Body, ResBody> Service<State, Request<Body>> for Redirect<ResBody>
where
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Infallible;

    async fn serve(
        &self,
        _ctx: Context<State>,
        _req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let mut res = Response::default();
        *res.status_mut() = self.status_code;
        res.headers_mut()
            .insert(header::LOCATION, self.location.clone());
        Ok(res)
    }
}

impl<ResBody> fmt::Debug for Redirect<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("status_code", &self.status_code)
            .field("location", &self.location)
            .finish()
    }
}

impl<ResBody> Clone for Redirect<ResBody> {
    fn clone(&self) -> Self {
        Self {
            status_code: self.status_code,
            location: self.location.clone(),
            _marker: PhantomData,
        }
    }
}
