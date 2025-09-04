use super::{dep::hyperium, request, response};
use crate::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
use rama_core::context::Extensions;
use std::str::FromStr;

#[derive(Default, Clone)]
struct RamaExtensions(Extensions);
#[derive(Default, Clone)]
struct HttpUpstreamExtensions(hyperium::http::Extensions);

impl<T> From<hyperium::http::request::Request<T>> for request::Request<T> {
    fn from(value: hyperium::http::request::Request<T>) -> Self {
        let (parts, body) = value.into_parts();
        Self::from_parts(parts.into(), body)
    }
}

impl<T> From<request::Request<T>> for hyperium::http::request::Request<T> {
    fn from(value: request::Request<T>) -> Self {
        let (mut parts, body) = value.into_parts();

        let headers = hyperium::http::HeaderMap::from(parts.headers);

        let mut extensions_new = parts
            .extensions
            .remove::<HttpUpstreamExtensions>()
            .map_or_else(hyperium::http::Extensions::new, |ext| ext.0);

        extensions_new.insert(RamaExtensions(parts.extensions));

        let mut builder = hyperium::http::request::Builder::new()
            .method(hyperium::http::Method::from(parts.method))
            .uri(hyperium::http::Uri::from(parts.uri))
            .version(hyperium::http::Version::from(parts.version));

        *builder.headers_mut().unwrap() = headers;
        *builder.extensions_mut().unwrap() = extensions_new;

        builder.body(body).unwrap()
    }
}

impl From<hyperium::http::request::Parts> for request::Parts {
    fn from(mut value: hyperium::http::request::Parts) -> Self {
        let mut extensions_new = value
            .extensions
            .remove::<RamaExtensions>()
            .map_or_else(Extensions::new, |ext| ext.0);

        extensions_new.insert(HttpUpstreamExtensions(value.extensions));

        Self {
            method: value.method.into(),
            uri: value.uri.into(),
            version: value.version.into(),
            headers: value.headers.into(),
            extensions: extensions_new,
        }
    }
}

impl From<request::Parts> for hyperium::http::request::Parts {
    fn from(value: request::Parts) -> Self {
        // not possible to directly create upstream parts so we have to be creative
        let request = request::Request::from_parts(value, ());
        let request = hyperium::http::request::Request::from(request);
        let (parts, _) = request.into_parts();
        parts
    }
}

impl<T> From<hyperium::http::response::Response<T>> for response::Response<T> {
    fn from(value: hyperium::http::response::Response<T>) -> Self {
        let (parts, body) = value.into_parts();
        Self::from_parts(parts.into(), body)
    }
}

impl<T> From<response::Response<T>> for hyperium::http::response::Response<T> {
    fn from(value: response::Response<T>) -> Self {
        let (mut parts, body) = value.into_parts();

        let headers = hyperium::http::HeaderMap::from(parts.headers);

        let mut builder = hyperium::http::response::Builder::new()
            .status(hyperium::http::StatusCode::from(parts.status))
            .version(hyperium::http::Version::from(parts.version));

        let mut extensions_new = parts
            .extensions
            .remove::<HttpUpstreamExtensions>()
            .map_or_else(hyperium::http::Extensions::new, |ext| ext.0);

        extensions_new.insert(RamaExtensions(parts.extensions));

        *builder.headers_mut().unwrap() = headers;
        *builder.extensions_mut().unwrap() = extensions_new;

        builder.body(body).unwrap()
    }
}

impl From<hyperium::http::response::Parts> for response::Parts {
    fn from(mut value: hyperium::http::response::Parts) -> Self {
        let mut extensions_new = value
            .extensions
            .remove::<RamaExtensions>()
            .map_or_else(Extensions::new, |ext| ext.0);

        extensions_new.insert(HttpUpstreamExtensions(value.extensions));

        Self {
            status: value.status.into(),
            version: value.version.into(),
            headers: value.headers.into(),
            extensions: extensions_new,
        }
    }
}

impl From<response::Parts> for hyperium::http::response::Parts {
    fn from(value: response::Parts) -> Self {
        // not possible to directly create upstream parts so we have to be creative
        let response = response::Response::from_parts(value, ());
        let response = hyperium::http::response::Response::from(response);
        let (parts, _) = response.into_parts();
        parts
    }
}

impl From<hyperium::http::Method> for Method {
    fn from(value: hyperium::http::Method) -> Self {
        Self::from_str(value.as_str()).unwrap()
    }
}

impl From<Method> for hyperium::http::Method {
    fn from(value: Method) -> Self {
        Self::from_str(value.as_str()).unwrap()
    }
}

impl From<hyperium::http::StatusCode> for StatusCode {
    fn from(value: hyperium::http::StatusCode) -> Self {
        Self::from_u16(value.as_u16()).unwrap()
    }
}

impl From<StatusCode> for hyperium::http::StatusCode {
    fn from(value: StatusCode) -> Self {
        Self::from_u16(value.as_u16()).unwrap()
    }
}

impl From<hyperium::http::Version> for Version {
    fn from(value: hyperium::http::Version) -> Self {
        match value {
            hyperium::http::Version::HTTP_09 => Self::HTTP_09,
            hyperium::http::Version::HTTP_10 => Self::HTTP_10,
            hyperium::http::Version::HTTP_11 => Self::HTTP_11,
            hyperium::http::Version::HTTP_2 => Self::HTTP_2,
            hyperium::http::Version::HTTP_3 => Self::HTTP_3,
            _ => unreachable!("unreachable"),
        }
    }
}

impl From<Version> for hyperium::http::Version {
    fn from(value: Version) -> Self {
        match value {
            Version::HTTP_09 => Self::HTTP_09,
            Version::HTTP_10 => Self::HTTP_10,
            Version::HTTP_11 => Self::HTTP_11,
            Version::HTTP_2 => Self::HTTP_2,
            Version::HTTP_3 => Self::HTTP_3,
            _ => unreachable!("unreachable"),
        }
    }
}

impl From<hyperium::http::Uri> for Uri {
    fn from(value: hyperium::http::Uri) -> Self {
        Self::from_str(&value.to_string()).unwrap()
    }
}

impl From<Uri> for hyperium::http::Uri {
    fn from(value: Uri) -> Self {
        Self::from_str(&value.to_string()).unwrap()
    }
}

impl From<hyperium::http::HeaderMap<hyperium::http::HeaderValue>> for HeaderMap<HeaderValue> {
    fn from(value: hyperium::http::HeaderMap<hyperium::http::HeaderValue>) -> Self {
        let mut map = Self::with_capacity(value.len());
        for (key, value) in value.into_iter() {
            if let Some(key) = key {
                map.insert(HeaderName::from(key), HeaderValue::from(value));
            }
        }

        map
    }
}

impl From<HeaderMap<HeaderValue>> for hyperium::http::HeaderMap<hyperium::http::HeaderValue> {
    fn from(value: HeaderMap<HeaderValue>) -> Self {
        let mut map = Self::with_capacity(value.len());
        for (key, value) in value.into_iter() {
            if let Some(key) = key {
                map.insert(
                    hyperium::http::HeaderName::from(key),
                    hyperium::http::HeaderValue::from(value),
                );
            }
        }

        map
    }
}

impl From<hyperium::http::HeaderName> for HeaderName {
    fn from(value: hyperium::http::HeaderName) -> Self {
        Self::from_str(value.as_ref()).unwrap()
    }
}

impl From<HeaderName> for hyperium::http::HeaderName {
    fn from(value: HeaderName) -> Self {
        Self::from_str(value.as_ref()).unwrap()
    }
}

impl From<hyperium::http::HeaderValue> for HeaderValue {
    fn from(value: hyperium::http::HeaderValue) -> Self {
        Self::from_bytes(value.as_bytes()).unwrap()
    }
}

impl From<HeaderValue> for hyperium::http::HeaderValue {
    fn from(value: HeaderValue) -> Self {
        Self::from_bytes(value.as_bytes()).unwrap()
    }
}
