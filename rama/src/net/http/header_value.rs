use crate::net::http::{header::AsHeaderName, HeaderMap, Request, Response};

pub trait HeaderValueGetter {
    fn header_str<K>(&self, key: K) -> Result<&str, HeaderValueErr>
    where
        K: AsHeaderName + Copy;

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
                .map_err(|_| HeaderValueErr::HeaderInvalid(key.as_str().to_string())),
            None => Err(HeaderValueErr::HeaderMissing(key.as_str().to_string())),
        }
    }

    fn header_bytes<K>(&self, key: K) -> Result<&[u8], HeaderValueErr>
    where
        K: AsHeaderName + Copy,
    {
        match self.get(key) {
            Some(value) => Ok(value.as_bytes()),
            None => Err(HeaderValueErr::HeaderMissing(key.as_str().to_string())),
        }
    }
}

#[derive(Debug)]
pub enum HeaderValueErr {
    HeaderMissing(String),
    HeaderInvalid(String),
}

impl std::fmt::Display for HeaderValueErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderValueErr::HeaderMissing(key) => write!(f, "header missing: {}", key),
            HeaderValueErr::HeaderInvalid(key) => write!(f, "header invalid: {}", key),
        }
    }
}

impl std::error::Error for HeaderValueErr {}
