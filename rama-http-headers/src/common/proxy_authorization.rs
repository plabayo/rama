use rama_http_types::{HeaderName, HeaderValue};

use super::authorization::{Authorization, Credentials};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Proxy-Authorization` header, defined in [RFC7235](https://tools.ietf.org/html/rfc7235#section-4.4)
///
/// The `Proxy-Authorization` header field allows a user agent to authenticate
/// itself with an HTTP proxy -- usually, but not necessarily, after
/// receiving a 407 (Proxy Authentication Required) response and the
/// `Proxy-Authenticate` header. Its value consists of credentials containing
/// the authentication information of the user agent for the realm of the
/// resource being requested.
///
/// # ABNF
///
/// ```text
/// Proxy-Authorization = credentials
/// ```
///
/// # Example values
/// * `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`
/// * `Bearer fpKL54jvWmEGVoRdCNjG`
///
/// # Examples
///
#[derive(Clone, PartialEq, Debug)]
pub struct ProxyAuthorization<C: Credentials>(pub C);

impl<C: Credentials> TypedHeader for ProxyAuthorization<C> {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::PROXY_AUTHORIZATION
    }
}

impl<C: Credentials> HeaderDecode for ProxyAuthorization<C> {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        Authorization::decode(values).map(|auth| Self(auth.0))
    }
}

impl<C: Credentials> HeaderEncode for ProxyAuthorization<C> {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(self.0.encode().map(|mut value| {
            value.set_sensitive(true);
            debug_assert!(
                value.as_bytes().starts_with(C::SCHEME.as_bytes()),
                "Credentials::encode should include its scheme: scheme = {:?}, encoded = {:?}",
                C::SCHEME,
                value,
            );
            value
        }));
    }
}

#[cfg(test)]
mod tests {
    use rama_http_types::{HeaderMap, header::PROXY_AUTHORIZATION};
    use rama_net::user::{Basic, Bearer};

    use crate::HeaderMapExt as _;

    use super::ProxyAuthorization;

    #[test]
    fn encoded_proxy_credentials_are_sensitive_and_wire_correct() {
        let mut headers = HeaderMap::new();
        headers.typed_insert(ProxyAuthorization(
            Basic::try_from("proxy-user:proxy-password").unwrap(),
        ));
        let value = headers.get(PROXY_AUTHORIZATION).unwrap();
        assert_eq!(value, "Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==");
        assert!(value.is_sensitive());
        assert!(!format!("{headers:?}").contains("cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA"));

        headers.typed_insert(ProxyAuthorization(
            Bearer::try_from("private-proxy-token").unwrap(),
        ));
        let value = headers.get(PROXY_AUTHORIZATION).unwrap();
        assert_eq!(value, "Bearer private-proxy-token");
        assert!(value.is_sensitive());
        assert!(!format!("{headers:?}").contains("private-proxy-token"));
    }
}
