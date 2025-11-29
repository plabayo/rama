use std::convert::TryFrom;
use std::fmt;

use rama_core::{bytes::Bytes, telemetry::tracing};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address::{self, HostWithOptPort};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// The `Host` header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Host(pub HostWithOptPort);

impl TypedHeader for Host {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::HOST
    }
}

impl HeaderDecode for Host {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let addr = values
            .next()
            .and_then(|val| HostWithOptPort::try_from(val.as_bytes()).ok())
            .ok_or_else(Error::invalid)?;
        Ok(Self(addr))
    }
}

impl HeaderEncode for Host {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.to_string();
        let bytes = Bytes::from_owner(s);

        match HeaderValue::from_maybe_shared(bytes) {
            Ok(value) => values.extend(::std::iter::once(value)),
            Err(err) => {
                tracing::debug!(
                    "failed to encode stringified authority (host w/ opt port) as header value: {err}"
                );
            }
        }
    }
}

impl From<address::Host> for Host {
    #[inline(always)]
    fn from(host: address::Host) -> Self {
        Self(host.into())
    }
}

impl From<Host> for address::Host {
    #[inline(always)]
    fn from(value: Host) -> Self {
        value.0.host
    }
}

impl From<HostWithOptPort> for Host {
    #[inline(always)]
    fn from(addr: HostWithOptPort) -> Self {
        Self(addr)
    }
}

impl From<Host> for HostWithOptPort {
    #[inline(always)]
    fn from(host: Host) -> Self {
        host.0
    }
}

impl From<address::HostWithPort> for Host {
    #[inline(always)]
    fn from(addr: address::HostWithPort) -> Self {
        Self(addr.into())
    }
}

impl fmt::Display for Host {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
