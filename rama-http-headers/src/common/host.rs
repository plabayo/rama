use std::convert::TryFrom;
use std::fmt;
use std::net::IpAddr;

use rama_core::bytes::Bytes;
use rama_http_types::dep::http::uri;
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address;

use crate::{Error, Header};

/// The `Host` header.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd)]
pub struct Host {
    host: address::Host,
    port: Option<u16>,
}

impl Host {
    /// Get the [`address::Host`], such as example.domain.
    pub fn host(&self) -> &address::Host {
        &self.host
    }

    /// Get the optional port number.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Consume self into its parts: `(host, ?port)`
    pub fn into_parts(self) -> (address::Host, Option<u16>) {
        (self.host, self.port)
    }
}

impl Header for Host {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::HOST
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let auth = values
            .next()
            .and_then(|val| uri::Authority::try_from(val.as_bytes()).ok())
            .ok_or_else(Error::invalid)?;
        let host = address::Host::try_from(auth.host()).map_err(|_| Error::invalid())?;
        let port = auth.port_u16();
        Ok(Self { host, port })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.to_string();
        let bytes = Bytes::from_owner(s);
        let val = HeaderValue::from_maybe_shared(bytes).expect("Authority is a valid HeaderValue");

        values.extend(::std::iter::once(val));
    }
}

impl From<address::Host> for Host {
    fn from(host: address::Host) -> Host {
        Host { host, port: None }
    }
}

impl From<address::Authority> for Host {
    fn from(auth: address::Authority) -> Host {
        let (host, port) = auth.into_parts();
        Host {
            host,
            port: Some(port),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.port {
            Some(port) => match &self.host {
                address::Host::Address(IpAddr::V6(ip)) => write!(f, "[{ip}]:{port}"),
                host => write!(f, "{host}:{port}"),
            },
            None => self.host.fmt(f),
        }
    }
}
