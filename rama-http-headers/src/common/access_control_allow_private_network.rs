use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Access-Control-Allow-Private-Network` header, as documented in
/// [this draft of WICG](https://wicg.github.io/private-network-access/).
///
/// Not an official standard but widely used.
/// This CORS header to allow a public origin make a cross site request
/// to a server hosted on a private network (e.g. behind a firewall).
///
/// # ABNF
///
/// ```text
/// Access-Control-Allow-Private-Network: "Access-Control-Allow-Private-Network" ":" "true"
/// ```
///
/// Since there is only one acceptable field value, the header struct does not accept
/// any values at all. Setting an empty `AccessControlAllowPrivateNetwork` header is
/// sufficient. See the examples below.
///
/// # Example values
/// * "true"
///
/// # Examples
///
/// ```
/// use rama_http_headers::AccessControlAllowPrivateNetwork;
///
/// let allow_creds = AccessControlAllowPrivateNetwork::default();
/// ```
#[derive(Default, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct AccessControlAllowPrivateNetwork;

impl AccessControlAllowPrivateNetwork {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for AccessControlAllowPrivateNetwork {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::ACCESS_CONTROL_ALLOW_PRIVATE_NETWORK
    }
}

impl HeaderDecode for AccessControlAllowPrivateNetwork {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|value| if value == "true" { Some(Self) } else { None })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for AccessControlAllowPrivateNetwork {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(HeaderValue::from_static("true")));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

    #[test]
    fn allow_private_network_is_case_sensitive() {
        let allow_header = test_decode::<AccessControlAllowPrivateNetwork>(&["true"]);
        assert!(allow_header.is_some());

        let allow_header = test_decode::<AccessControlAllowPrivateNetwork>(&["True"]);
        assert!(allow_header.is_none());
    }
}
