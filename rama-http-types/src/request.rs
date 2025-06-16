use crate::{
    body::Body,
    dep::http::{Extensions, HeaderMap, HeaderValue, Method, Uri, Version, request::Parts},
};

/// Type alias for [`HttpRequest`] whose body type
/// defaults to [`Body`], the most common body type used with rama.
///
/// [`HttpRequest`]: crate::dep::http::Request
pub type Request<T = Body> = http::Request<T>;

/// [`HttpRequestParts`] is used in places where we don't need the [`ReqBody`] of the [`HttpRequest`]
///
/// In those places we need to support using [`HttpRequest`] and [`Parts`]. By using
/// this trait we can support both types behind a single generic that implements this trait.
///
/// [`ReqBody`]: crate::dep::http_body::Body
/// [`HttpRequest`]: crate::dep::http::Request
pub trait HttpRequestParts {
    fn method(&self) -> &Method;
    fn method_mut(&mut self) -> &mut Method;
    fn uri(&self) -> &Uri;
    fn uri_mut(&mut self) -> &mut Uri;
    fn version(&self) -> Version;
    fn version_mut(&mut self) -> &mut Version;
    fn headers(&self) -> &HeaderMap<HeaderValue>;
    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue>;
    fn extensions(&self) -> &Extensions;
    fn extensions_mut(&mut self) -> &mut Extensions;
}

impl<Body> HttpRequestParts for http::Request<Body> {
    fn method(&self) -> &Method {
        self.method()
    }

    fn method_mut(&mut self) -> &mut Method {
        self.method_mut()
    }

    fn uri(&self) -> &Uri {
        self.uri()
    }

    fn uri_mut(&mut self) -> &mut Uri {
        self.uri_mut()
    }

    fn version(&self) -> Version {
        self.version()
    }

    fn version_mut(&mut self) -> &mut Version {
        self.version_mut()
    }

    fn headers(&self) -> &HeaderMap<HeaderValue> {
        self.headers()
    }

    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue> {
        self.headers_mut()
    }

    fn extensions(&self) -> &Extensions {
        self.extensions()
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        self.extensions_mut()
    }
}

impl HttpRequestParts for Parts {
    fn method(&self) -> &Method {
        &self.method
    }

    fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    fn version(&self) -> Version {
        self.version
    }

    fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    fn headers(&self) -> &HeaderMap<HeaderValue> {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut HeaderMap<HeaderValue> {
        &mut self.headers
    }

    fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}
