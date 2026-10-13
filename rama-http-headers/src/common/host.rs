use std::convert::TryFrom;
use std::fmt;

use rama_core::{bytes::Bytes, telemetry::tracing};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address::{self, Authority, HostWithOptPort};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util::single_value};

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
        // Several lines are refused, as received requests are (RFC 9112 §3.2).
        let value = single_value(values)?;
        let addr = HostWithOptPort::try_from(value.as_bytes()).map_err(|_err| Error::invalid())?;
        Ok(Self(addr))
    }
}

impl HeaderEncode for Host {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let s = self.to_string();
        let bytes = Bytes::from(s);

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

impl From<Host> for Authority {
    #[inline(always)]
    fn from(host: Host) -> Self {
        Self::new(host.0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_converts_into_authority_without_reparsing() {
        let host = Host(HostWithOptPort::try_from("example.com:8080").unwrap());
        let authority = Authority::from(host.clone());
        assert!(authority.user_info.is_none());
        assert_eq!(authority.address, host.0);
    }
}
