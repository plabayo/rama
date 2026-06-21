//! Message conversions (request, response, and their parts).

use rama_http_types::{Request, Response, request, response};

use super::TryIntoHyperiumHttp;
use crate::HyperExtensions;

impl<T> TryIntoHyperiumHttp for Request<T> {
    type Output = http::Request<T>;
    type Error = http::Error;

    fn try_into_hyperium_http(self) -> Result<http::Request<T>, http::Error> {
        let (parts, body) = self.into_parts();

        let mut hyper_extensions = parts
            .extensions
            .get_ref::<HyperExtensions>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default();
        hyper_extensions.insert(parts.extensions);

        let mut req = http::Request::new(body);
        *req.method_mut() = parts.method.try_into_hyperium_http()?;
        *req.uri_mut() = parts.uri.try_into_hyperium_http()?;
        *req.version_mut() = parts.version.try_into_hyperium_http()?;
        *req.headers_mut() = parts.headers.try_into_hyperium_http()?;
        *req.extensions_mut() = hyper_extensions;
        Ok(req)
    }
}

impl<T> TryIntoHyperiumHttp for Response<T> {
    type Output = http::Response<T>;
    type Error = http::Error;

    fn try_into_hyperium_http(self) -> Result<http::Response<T>, http::Error> {
        let (parts, body) = self.into_parts();

        let mut hyper_extensions = parts
            .extensions
            .get_ref::<HyperExtensions>()
            .map(|ext| ext.0.clone())
            .unwrap_or_default();
        hyper_extensions.insert(parts.extensions);

        let mut res = http::Response::new(body);
        *res.status_mut() = parts.status.try_into_hyperium_http()?;
        *res.version_mut() = parts.version.try_into_hyperium_http()?;
        *res.headers_mut() = parts.headers.try_into_hyperium_http()?;
        *res.extensions_mut() = hyper_extensions;
        Ok(res)
    }
}

impl TryIntoHyperiumHttp for request::Parts {
    type Output = http::request::Parts;
    type Error = http::Error;

    fn try_into_hyperium_http(self) -> Result<http::request::Parts, http::Error> {
        // `http::request::Parts` can't be built directly, so route through a
        // `Request<()>` and split it back out.
        Ok(Request::from_parts(self, ())
            .try_into_hyperium_http()?
            .into_parts()
            .0)
    }
}

impl TryIntoHyperiumHttp for response::Parts {
    type Output = http::response::Parts;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::response::Parts, http::Error> {
        Ok(Response::from_parts(self, ())
            .try_into_hyperium_http()?
            .into_parts()
            .0)
    }
}
