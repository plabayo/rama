//! Message conversions (request, response, and their parts).

use rama_core::extensions::{Extensions, ExtensionsRef as _};
use rama_http_types::{Request, Response, request, response};

use super::TryIntoRamaHttp;
use crate::HyperExtensions;

impl<T> TryIntoRamaHttp for http::Request<T> {
    type Output = Request<T>;
    type Error = rama_http_types::Error;

    fn try_into_rama_http(self) -> Result<Request<T>, rama_http_types::Error> {
        let (mut parts, body) = self.into_parts();
        // Pull any previously-stashed rama extensions back out; stash the
        // remaining http extensions so a later rama → http hop restores them.
        let rama_extensions = parts.extensions.remove::<Extensions>().unwrap_or_default();
        rama_extensions.insert(HyperExtensions(parts.extensions));

        let mut req = Request::new(body);
        *req.method_mut() = parts.method.try_into_rama_http()?;
        *req.uri_mut() = parts.uri.try_into_rama_http()?;
        *req.version_mut() = parts.version.try_into_rama_http()?;
        *req.headers_mut() = parts.headers.try_into_rama_http()?;
        req.extensions().extend(&rama_extensions);
        Ok(req)
    }
}

impl<T> TryIntoRamaHttp for http::Response<T> {
    type Output = Response<T>;
    type Error = rama_http_types::Error;

    fn try_into_rama_http(self) -> Result<Response<T>, rama_http_types::Error> {
        let (mut parts, body) = self.into_parts();
        let rama_extensions = parts.extensions.remove::<Extensions>().unwrap_or_default();
        rama_extensions.insert(HyperExtensions(parts.extensions));

        let mut res = Response::new(body);
        *res.status_mut() = parts.status.try_into_rama_http()?;
        *res.version_mut() = parts.version.try_into_rama_http()?;
        *res.headers_mut() = parts.headers.try_into_rama_http()?;
        res.extensions().extend(&rama_extensions);
        Ok(res)
    }
}

impl TryIntoRamaHttp for http::request::Parts {
    type Output = request::Parts;
    type Error = rama_http_types::Error;

    fn try_into_rama_http(self) -> Result<request::Parts, rama_http_types::Error> {
        // `request::Parts::new` is private + non-exhaustive, so route through a
        // `Request<()>` and split it back out.
        Ok(http::Request::from_parts(self, ())
            .try_into_rama_http()?
            .into_parts()
            .0)
    }
}

impl TryIntoRamaHttp for http::response::Parts {
    type Output = response::Parts;
    type Error = rama_http_types::Error;

    fn try_into_rama_http(self) -> Result<response::Parts, rama_http_types::Error> {
        Ok(http::Response::from_parts(self, ())
            .try_into_rama_http()?
            .into_parts()
            .0)
    }
}
