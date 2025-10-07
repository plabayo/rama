//! Service that redirects all requests.

use crate::Request;
use crate::service::web::response;
use crate::{Response, header};
use rama_core::Service;
use std::{convert::Infallible, fmt, marker::PhantomData};

/// Service that redirects all requests.
pub struct Redirect<ResBody> {
    resp: response::Redirect,
    // Covariant over ResBody, no dropping of ResBody
    _marker: PhantomData<fn() -> ResBody>,
}

impl<ResBody> Redirect<ResBody> {
    /// Create a new [`Redirect`] that uses a [`303 See Other`][mdn] status code.
    ///
    /// This redirect instructs the client to change the method to GET for the subsequent request
    /// to the given location, which is useful after successful form submission, file upload or when
    /// you generally don't want the redirected-to page to observe the original request method and
    /// body (if non-empty). If you want to preserve the request method and body,
    /// [`Redirect::temporary`] should be used instead.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
    pub fn to(loc: impl response::redirect::IntoRedirectLoc) -> Self {
        Self {
            resp: response::Redirect::to(loc),
            _marker: PhantomData,
        }
    }

    /// Create a new found (301) redirect response.
    ///
    /// Used if a resource is permanently moved.
    ///
    /// Use [`Self::permanent`] in case you wish to respect the original HTTP Method.
    pub fn moved(loc: impl response::redirect::IntoRedirectLoc) -> Self {
        Self {
            resp: response::Redirect::moved(loc),
            _marker: PhantomData,
        }
    }

    /// Create a new found (302) redirect.
    ///
    /// Can be useful in flows where the resource was legit and found,
    /// but a pre-requirement such as authentication wasn't met.
    pub fn found(loc: impl response::redirect::IntoRedirectLoc) -> Self {
        Self {
            resp: response::Redirect::found(loc),
            _marker: PhantomData,
        }
    }

    /// Create a new temporary (307) redirect.
    pub fn temporary(loc: impl response::redirect::IntoRedirectLoc) -> Self {
        Self {
            resp: response::Redirect::temporary(loc),
            _marker: PhantomData,
        }
    }

    /// Create a new permanent (308) redirect.
    pub fn permanent(loc: impl response::redirect::IntoRedirectLoc) -> Self {
        Self {
            resp: response::Redirect::permanent(loc),
            _marker: PhantomData,
        }
    }
}

impl<Body, ResBody> Service<Request<Body>> for Redirect<ResBody>
where
    Body: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Infallible;

    async fn serve(&self, _req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let mut res = Response::default();
        *res.status_mut() = self.resp.status_code();
        res.headers_mut()
            .insert(&header::LOCATION, self.resp.location().clone());
        Ok(res)
    }
}

impl<ResBody> fmt::Debug for Redirect<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redirect")
            .field("response", &self.resp)
            .finish()
    }
}

impl<ResBody> Clone for Redirect<ResBody> {
    fn clone(&self) -> Self {
        Self {
            resp: self.resp.clone(),
            _marker: PhantomData,
        }
    }
}
