use crate::{HeaderMap, Request, Response, header::AsHeaderName};

/// Utility trait for getting header values from a request or response.
pub trait HeaderValueGetter {
    /// Get a header value as a string.
    fn header_str<K>(&self, key: K) -> Result<&str, HeaderValueErr>
    where
        K: AsHeaderName + Copy;

    /// Get a header value as a byte slice.
    fn header_bytes<K>(&self, key: K) -> Result<&[u8], HeaderValueErr>
    where
        K: AsHeaderName + Copy;
}

impl<Body> HeaderValueGetter for Request<Body> {
    fn header_str<K>(&self, key: K) -> Result<&str, HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        self.headers().header_str(key)
    }

    fn header_bytes<K>(&self, key: K) -> Result<&[u8], HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        self.headers().header_bytes(key)
    }
}

impl<Body> HeaderValueGetter for Response<Body> {
    fn header_str<K>(&self, key: K) -> Result<&str, HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        self.headers().header_str(key)
    }

    fn header_bytes<K>(&self, key: K) -> Result<&[u8], HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        self.headers().header_bytes(key)
    }
}

impl HeaderValueGetter for HeaderMap {
    fn header_str<K>(&self, key: K) -> Result<&str, HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        match self.get(key) {
            Some(value) => value
                .to_str()
                .map_err(|_| HeaderValueErr::HeaderInvalid(key.as_str().to_owned())),
            None => Err(HeaderValueErr::HeaderMissing(key.as_str().to_owned())),
        }
    }

    fn header_bytes<K>(&self, key: K) -> Result<&[u8], HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        match self.get(key) {
            Some(value) => Ok(value.as_bytes()),
            None => Err(HeaderValueErr::HeaderMissing(key.as_str().to_owned())),
        }
    }
}

/// Error type for header value getters.
#[derive(Debug)]
pub enum HeaderValueErr {
    /// The header was missing.
    HeaderMissing(String),
    /// The header was invalid.
    HeaderInvalid(String),
}

impl std::fmt::Display for HeaderValueErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValueErr::HeaderMissing(key) => write!(f, "header missing: {key}"),
            HeaderValueErr::HeaderInvalid(key) => write!(f, "header invalid: {key}"),
        }
    }
}

impl std::error::Error for HeaderValueErr {}
