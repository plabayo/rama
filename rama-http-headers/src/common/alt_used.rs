use std::fmt;

use rama_core::{bytes::Bytes, telemetry::tracing};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::address::{AuthorityRef, HostWithOptPort, HostWithPort};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// The alternative service used for a request ([RFC 7838 §5](https://www.rfc-editor.org/rfc/rfc7838.html#section-5)).
///
/// Identifies the alternative host and optional port. The origin remains in `Host`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AltUsed(pub HostWithOptPort);

impl TypedHeader for AltUsed {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::ALT_USED
    }
}

impl HeaderDecode for AltUsed {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let value = values.next().ok_or_else(Error::invalid)?;
        if values.next().is_some() {
            return Err(Error::invalid());
        }
        let authority =
            AuthorityRef::parse_strict(value.as_bytes()).map_err(|_error| Error::invalid())?;
        if authority.userinfo().is_some() {
            return Err(Error::invalid());
        }
        Ok(Self(HostWithOptPort {
            host: authority.host().into_owned(),
            port: authority.port(),
        }))
    }
}

impl HeaderEncode for AltUsed {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        match HeaderValue::from_maybe_shared(Bytes::from_owner(self.to_string())) {
            Ok(value) => values.extend(std::iter::once(value)),
            Err(error) => tracing::debug!("failed to encode Alt-Used authority: {error}"),
        }
    }
}

impl From<HostWithOptPort> for AltUsed {
    fn from(value: HostWithOptPort) -> Self {
        Self(value)
    }
}

impl From<HostWithPort> for AltUsed {
    fn from(value: HostWithPort) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for AltUsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMapExt;
    use rama_http_types::HeaderMap;

    #[test]
    fn alternative_authority_round_trip() {
        for authority in [
            "alternate.example.net",
            "alternate.example.net:8443",
            "[2001:db8::1]:443",
            "example.net:",
        ] {
            let value = HeaderValue::from_str(authority).unwrap();
            let decoded = AltUsed::decode(&mut std::iter::once(&value)).unwrap();
            let mut headers = HeaderMap::new();
            headers.typed_insert(decoded.clone());
            assert_eq!(headers.typed_get::<AltUsed>(), Some(decoded));
            assert_eq!(headers[AltUsed::name()], authority);
        }
    }

    #[test]
    fn malformed_and_duplicate_authorities() {
        for authority in [
            "",
            "user@example.net",
            "::1",
            "[::1",
            "example.net/path",
            "example.net:65536",
            "example.net:abc",
        ] {
            let value = HeaderValue::from_str(authority).unwrap();
            assert!(
                AltUsed::decode(&mut std::iter::once(&value)).is_err(),
                "{authority:?}"
            );
        }
        let value = HeaderValue::from_static("example.net");
        AltUsed::decode(&mut [&value, &value].into_iter()).unwrap_err();
    }
}
