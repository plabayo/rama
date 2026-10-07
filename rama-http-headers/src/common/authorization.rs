//! Authorization header and types.

use std::ops::{Deref, DerefMut};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

use rama_core::extensions::Extensions;
use rama_core::telemetry::tracing;
use rama_core::username::{UsernameLabelParser, parse_username};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::user::{Basic, Bearer, RawToken, UserId};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Authorization` header, defined in [RFC7235](https://tools.ietf.org/html/rfc7235#section-4.2)
///
/// The `Authorization` header field allows a user agent to authenticate
/// itself with an origin server -- usually, but not necessarily, after
/// receiving a 401 (Unauthorized) response.  Its value consists of
/// credentials containing the authentication information of the user
/// agent for the realm of the resource being requested.
///
/// # ABNF
///
/// ```text
/// Authorization = credentials
/// ```
///
/// # Example values
/// * `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`
/// * `Bearer fpKL54jvWmEGVoRdCNjG`
///
/// # Examples
///
/// ```
/// use rama_http_headers::Authorization;
/// use rama_net::user::credentials::{basic, bearer};
///
/// let basic = Authorization::new(basic!("Aladdin", "open sesame"));
/// let bearer = Authorization::new(bearer!("some-opaque-token"));
/// ```
///
#[derive(Clone, PartialEq, Debug)]
pub struct Authorization<C>(pub C);

impl<C> Authorization<C> {
    /// Create a new authorization header.
    pub fn new(credentials: C) -> Self {
        Self(credentials)
    }

    pub fn credentials(&self) -> &C {
        &self.0
    }

    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C> AsRef<C> for Authorization<C> {
    fn as_ref(&self) -> &C {
        &self.0
    }
}

impl<C> Deref for Authorization<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> DerefMut for Authorization<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<C: Credentials> TypedHeader for Authorization<C> {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::AUTHORIZATION
    }
}

impl<C: Credentials> HeaderDecode for Authorization<C> {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // Credentials are one value (RFC 9110 §11.6.2, §11.7.2): a second line, which an upstream
        // could read instead, makes the field invalid.
        let val = crate::util::single_value(values)?;
        Some(&val)
            .and_then(|val| {
                // Scheme-less credential types (e.g. `RawToken`) declare an
                // empty `SCHEME` and treat the whole header value as the
                // token. Skip the `<scheme> SP …` prefix check entirely so
                // those types don't have to lie about their shape.
                if C::SCHEME.is_empty() {
                    return C::decode(val).map(Authorization);
                }
                strip_scheme(val.as_bytes(), C::SCHEME)?;
                C::decode(val).map(Authorization)
            })
            .ok_or_else(Error::invalid)
    }
}

impl<C: Credentials> HeaderEncode for Authorization<C> {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(encode_credentials(&self.0));
    }
}

/// Encode credentials as a sensitive header value.
pub(super) fn encode_credentials<C: Credentials>(credentials: &C) -> Option<HeaderValue> {
    let mut value = credentials.encode()?;
    value.set_sensitive(true);
    let has_scheme = value
        .as_bytes()
        .get(..C::SCHEME.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(C::SCHEME.as_bytes()));
    if !has_scheme {
        tracing::debug!(
            "Credentials::encode should include its scheme: scheme = {:?}",
            C::SCHEME
        );
    }
    Some(value)
}

/// Strip a case-insensitive `<scheme> SP` prefix, returning what follows.
fn strip_scheme<'a>(value: &'a [u8], scheme: &str) -> Option<&'a [u8]> {
    let (prefix, rest) = value.split_at_checked(scheme.len())?;
    let rest = rest.strip_prefix(b" ")?;
    prefix
        .eq_ignore_ascii_case(scheme.as_bytes())
        .then_some(rest)
}

/// Strip the scheme and any extra SP, returning non-empty credentials.
fn strip_scheme_and_spaces<'a>(value: &'a [u8], scheme: &str) -> Option<&'a [u8]> {
    let mut rest = strip_scheme(value, scheme)?;
    while let Some(tail) = rest.strip_prefix(b" ") {
        rest = tail;
    }
    (!rest.is_empty()).then_some(rest)
}

/// Credentials to be used in the `Authorization` header.
pub trait Credentials: Sized {
    /// The scheme identify the format of these credentials.
    ///
    /// This is the static string that always prefixes the actual credentials,
    /// like `"Basic"` in basic authorization.
    const SCHEME: &'static str;

    /// Try to decode the credentials from the `HeaderValue`.
    ///
    /// The `SCHEME` will be the first part of the `value`.
    fn decode(value: &HeaderValue) -> Option<Self>;

    /// Encode the credentials to a `HeaderValue`.
    ///
    /// The `SCHEME` must be the first part of the `value`.
    fn encode(&self) -> Option<HeaderValue>;
}

impl Credentials for Basic {
    const SCHEME: &'static str = "Basic";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let Some(bytes) = strip_scheme_and_spaces(value.as_bytes(), Self::SCHEME) else {
            tracing::trace!("Basic credentials failed to decode: invalid scheme or missing token");
            return None;
        };

        let bytes = ENGINE
            .decode(bytes)
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: base64 decode: {err:?}");
            })
            .ok()?;

        let decoded = String::from_utf8(bytes)
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: utf8 validation: {err:?}");
            })
            .ok()?;

        decoded
            .parse()
            .inspect_err(|err| {
                tracing::trace!("Basic credentials failed to decode: str parse: {err:?}");
            })
            .ok()
    }

    fn encode(&self) -> Option<HeaderValue> {
        let mut encoded = format!("{} ", Self::SCHEME);
        ENGINE.encode_string(self.to_string(), &mut encoded);
        HeaderValue::try_from(encoded)
            .inspect_err(|err| {
                tracing::debug!("failed to encode basic value as header value: {err}");
            })
            .ok()
    }
}

impl Credentials for Bearer {
    const SCHEME: &'static str = "Bearer";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let Some(bytes) = strip_scheme_and_spaces(value.as_bytes(), Self::SCHEME) else {
            tracing::trace!("Bearer credentials failed to decode: invalid scheme or missing token");
            return None;
        };

        let s = std::str::from_utf8(bytes)
            .inspect_err(|err| {
                tracing::trace!("Bearer credentials failed to decode: {err:?}");
            })
            .ok()?;

        Self::try_from(s.to_owned())
            .inspect_err(|err| {
                tracing::trace!("Bearer credentials failed to decode: {err:?}");
            })
            .ok()
    }

    fn encode(&self) -> Option<HeaderValue> {
        HeaderValue::try_from(format!("{} {}", Self::SCHEME, self.token()))
            .inspect_err(|err| {
                tracing::debug!("failed to encode bearer auth as header value: {err}");
            })
            .ok()
    }
}

impl Credentials for RawToken {
    /// Scheme-less: the entire `Authorization` header value is the token,
    /// with no leading `Bearer ` / `Basic ` prefix.
    const SCHEME: &'static str = "";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let s = std::str::from_utf8(value.as_bytes())
            .inspect_err(|err| {
                tracing::trace!("RawToken credentials failed to decode: {err:?}");
            })
            .ok()?;
        Self::try_from(s.to_owned())
            .inspect_err(|err| {
                tracing::trace!("RawToken credentials failed to decode: {err}");
            })
            .ok()
    }

    fn encode(&self) -> Option<HeaderValue> {
        HeaderValue::try_from(self.token().to_owned())
            .inspect_err(|err| {
                tracing::debug!("failed to encode raw token as header value: {err}");
            })
            .ok()
    }
}

/// The `Authority` trait is used to determine if a set of [`Credentials`] are authorized.
pub trait Authority<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, credentials: C) -> impl Future<Output = Option<Extensions>> + Send + '_;
}

/// A synchronous version of [`Authority`], to be used for primitive implementations.
pub trait AuthoritySync<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, ext: &Extensions, credentials: &C) -> bool;
}

impl<A, C, L> Authority<C, L> for A
where
    A: AuthoritySync<C, L>,
    C: Credentials + Send + 'static,
    L: 'static,
{
    async fn authorized(&self, credentials: C) -> Option<Extensions> {
        let ext = Extensions::new();
        if self.authorized(&ext, &credentials) {
            Some(ext)
        } else {
            None
        }
    }
}

impl<T: UsernameLabelParser> AuthoritySync<Self, T> for Basic {
    fn authorized(&self, ext: &Extensions, credentials: &Self) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.password() {
            return false;
        }

        let parser_ext = Extensions::new();
        let username = match parse_username(&parser_ext, T::default(), username) {
            Ok(t) => t,
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                return if self == credentials {
                    ext.insert(UserId::Username(username.to_owned()));
                    true
                } else {
                    false
                };
            }
        };

        if username != self.username() {
            return false;
        }

        ext.extend(&parser_ext);
        ext.insert(UserId::Username(username));
        true
    }
}

impl<C, L, T, const N: usize> AuthoritySync<C, L> for [T; N]
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

impl<C, L, T> AuthoritySync<C, L> for Vec<T>
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

#[cfg(test)]
mod tests {
    use rama_http_types::header::HeaderMap;
    use rama_net::user::credentials::bearer;
    use rama_utils::str::non_empty_str;

    use super::{Authorization, Basic, Bearer, Credentials, HeaderValue};
    use crate::common::{test_decode, test_encode};
    use crate::{HeaderDecode, HeaderMapExt};

    /// Credentials are one value: a second line, equal or not, makes either header invalid.
    #[test]
    fn credentials_appear_once() {
        let basic = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        assert!(test_decode::<Authorization<Basic>>(&[basic]).is_some());
        for lines in [&[basic, basic][..], &[basic, "Basic b3RoZXI6dXNlcg=="]] {
            assert!(
                test_decode::<Authorization<Basic>>(lines).is_none(),
                "{lines:?}"
            );
            assert!(
                test_decode::<crate::ProxyAuthorization<Basic>>(lines).is_none(),
                "{lines:?}"
            );
        }
    }

    fn decode_bytes<C: Credentials>(value: &str) -> Option<Authorization<C>> {
        let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
        Authorization::decode(&mut std::iter::once(&value)).ok()
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Passthrough(HeaderValue);

    impl Credentials for Passthrough {
        const SCHEME: &'static str = "Digest";

        fn decode(value: &HeaderValue) -> Option<Self> {
            Some(Self(value.clone()))
        }

        fn encode(&self) -> Option<HeaderValue> {
            Some(self.0.clone())
        }
    }

    #[test]
    fn encode_of_case_folded_scheme_does_not_panic() {
        let auth: Authorization<Passthrough> = test_decode(&["digest username=\"a\""]).unwrap();
        let headers = test_encode(auth);
        assert_eq!(headers["authorization"], "digest username=\"a\"");
        assert!(headers["authorization"].is_sensitive());
    }

    #[test]
    fn decode_rejects_short_and_boundary_values() {
        for value in [
            "",
            "B",
            "Basi",
            "Basic",
            "Basic ",
            "Basic   ",
            "Basicé",
            "Basé QWxh",
            "é",
            "Basic\tQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "BasicXQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "Basic é",
            "Basic ====",
            "Basic Og==",
            "Basic OnB3",
            "Basic /zph",
        ] {
            assert!(decode_bytes::<Basic>(value).is_none(), "{value:?}");
        }
        for value in [
            "",
            "B",
            "Bearer",
            "Bearer ",
            "Bearer   ",
            "Beareré",
            "Bearé tok",
            "Bearer é",
            "Bearer a b",
            "BearerXtoken",
        ] {
            assert!(decode_bytes::<Bearer>(value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn credentials_decode_requires_scheme_separator() {
        for value in [
            "BasicXQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "Basic\tQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "Basi\u{e9}QWxh",
            "Basic",
        ] {
            let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
            assert!(Basic::decode(&value).is_none(), "{value:?}");
        }
        for value in ["BearerXtoken", "Bearer\ttoken", "Beare\u{e9}tok", "Bearer"] {
            let value = HeaderValue::from_bytes(value.as_bytes()).unwrap();
            assert!(Bearer::decode(&value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn basic_decode_splits_on_first_colon_only() {
        let auth: Authorization<Basic> = test_decode(&["Basic YWxhZGRpbg=="]).unwrap();
        assert_eq!(auth.0.username(), "aladdin");
        assert_eq!(auth.0.password(), None);

        let auth: Authorization<Basic> = test_decode(&["Basic YTpiOmM="]).unwrap();
        assert_eq!(auth.0.username(), "a");
        assert_eq!(auth.0.password(), Some("b:c"));
    }

    #[test]
    fn basic_encode() {
        let auth = Authorization::new(Basic::new(
            non_empty_str!("Aladdin"),
            non_empty_str!("open sesame"),
        ));
        let headers = test_encode(auth);

        assert_eq!(
            headers["authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        );
    }

    #[test]
    fn basic_username_encode() {
        let auth = Authorization::new(Basic::new_insecure(non_empty_str!("Aladdin")));
        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Basic QWxhZGRpbjo=",);
    }

    #[test]
    fn basic_roundtrip() {
        let auth = Authorization::new(Basic::new(
            non_empty_str!("Aladdin"),
            non_empty_str!("open sesame"),
        ));
        let mut h = HeaderMap::new();
        h.typed_insert(&auth);
        assert_eq!(h.typed_get(), Some(auth));
    }

    #[test]
    fn basic_decode() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), Some("open sesame"));
    }

    #[test]
    fn basic_decode_case_insensitive() {
        let auth: Authorization<Basic> =
            test_decode(&["basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), Some("open sesame"));
    }

    #[test]
    fn basic_decode_extra_whitespaces() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), Some("open sesame"));
    }

    #[test]
    fn basic_decode_no_password() {
        let auth: Authorization<Basic> = test_decode(&["Basic QWxhZGRpbjo="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), None);
    }

    #[test]
    fn bearer_encode() {
        let auth = Authorization::new(bearer!("fpKL54jvWmEGVoRdCNjG"));

        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Bearer fpKL54jvWmEGVoRdCNjG",);
    }

    #[test]
    fn bearer_decode() {
        let auth: Authorization<Bearer> = test_decode(&["Bearer fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }

    #[test]
    fn bearer_decode_case_insensitive() {
        let auth: Authorization<Bearer> = test_decode(&["bearer fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }

    #[test]
    fn bearer_decode_extra_whitespaces() {
        let auth: Authorization<Bearer> = test_decode(&["Bearer   fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(auth.0.token().as_bytes(), b"fpKL54jvWmEGVoRdCNjG");
    }

    /// Regression: `RawToken` is a scheme-less credential — the header
    /// value is the token, no `Bearer ` / `Basic ` prefix. This pins both
    /// the encoded form (bare token) and the empty-scheme escape hatch in
    /// `Authorization::decode`.
    #[test]
    fn regression_authorization_raw_token_roundtrip() {
        use rama_net::user::RawToken;

        let token = RawToken::try_from("fpKL54jvWmEGVoRdCNjG").unwrap();
        let auth = Authorization::new(token.clone());

        // Encode: header value is the bare token, no scheme prefix.
        let headers = test_encode(auth);
        assert_eq!(headers["authorization"], "fpKL54jvWmEGVoRdCNjG");

        // Decode: the same bare value round-trips back.
        let decoded: Authorization<RawToken> = test_decode(&["fpKL54jvWmEGVoRdCNjG"]).unwrap();
        assert_eq!(decoded.0, token);
    }

    /// Regression: a `RawToken` header may contain characters that
    /// `Bearer` rejects (`,`, `:`, `=`, SP) because real-world API keys
    /// do.
    #[test]
    fn regression_authorization_raw_token_accepts_loose_alphabet() {
        use rama_net::user::RawToken;

        let decoded: Authorization<RawToken> =
            test_decode(&["sk-live_abc=xyz,scope:read"]).unwrap();
        assert_eq!(decoded.0.token(), "sk-live_abc=xyz,scope:read");
    }
}

//bench_header!(raw, Authorization<String>, { vec![b"foo bar baz".to_vec()] });
//bench_header!(basic, Authorization<Basic>, { vec![b"Basic QWxhZGRpbjpuIHNlc2FtZQ==".to_vec()] });
//bench_header!(bearer, Authorization<Bearer>, { vec![b"Bearer fpKL54jvWmEGVoRdCNjG".to_vec()] });

#[cfg(test)]
mod test_auth {
    use super::*;
    use rama_core::username::{UsernameLabels, UsernameOpaqueLabelParser};
    use rama_net::user::credentials::basic;

    #[tokio::test]
    async fn basic_authorization() {
        let auth = basic!("Aladdin", "open sesame");
        let auths = vec![basic!("foo", "bar"), auth.clone()];
        let ext = Authority::<_, ()>::authorized(&auths, auth).await.unwrap();
        let user: &UserId = ext.get_ref().unwrap();
        assert_eq!(user, "Aladdin");
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let auths = vec![basic!("foo", "bar"), basic!("john", "secret")];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(
            &auths,
            basic!("john-green-red", "secret"),
        )
        .await
        .unwrap();

        let c: &UserId = ext.get_ref().unwrap();
        assert_eq!(c, "john");

        let labels: &UsernameLabels = ext.get_ref().unwrap();
        assert_eq!(&labels.0, &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_not_found() {
        let auth = basic!("john", "secret");
        let auths = vec![basic!("foo", "bar"), auth.clone()];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get_ref().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get_ref::<UsernameLabels>().is_none());
    }
}
