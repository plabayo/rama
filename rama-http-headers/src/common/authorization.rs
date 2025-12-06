//! Authorization header and types.

use std::ops::{Deref, DerefMut};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;

use rama_core::extensions::Extensions;
use rama_core::telemetry::tracing;
use rama_core::username::{UsernameLabelParser, parse_username};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::user::{Basic, Bearer, UserId};

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
        values
            .next()
            .and_then(|val| {
                let slice = val.as_bytes();
                if slice.len() > C::SCHEME.len()
                    && slice[C::SCHEME.len()] == b' '
                    && slice[..C::SCHEME.len()].eq_ignore_ascii_case(C::SCHEME.as_bytes())
                {
                    C::decode(val).map(Authorization)
                } else {
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl<C: Credentials> HeaderEncode for Authorization<C> {
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
        let value = value.as_ref();

        if value.len() <= Self::SCHEME.len() + 1 {
            tracing::trace!(
                "Basic credentials failed to decode: invalid scheme length in basic str"
            );
            return None;
        }
        if !value[..Self::SCHEME.len()].eq_ignore_ascii_case(Self::SCHEME.as_bytes()) {
            tracing::trace!("Basic credentials failed to decode: invalid scheme in basic str");
            return None;
        }

        let bytes = &value[Self::SCHEME.len() + 1..];
        let Some(non_space_pos) = bytes.iter().position(|b| *b != b' ') else {
            tracing::trace!(
                "Basic credentials failed to decode: missing space separator in basic str"
            );
            return None;
        };

        let bytes = &bytes[non_space_pos..];

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
        let value = value.as_ref();

        if value.len() <= Self::SCHEME.len() + 1 {
            tracing::trace!("Bearer credentials failed to decode: invalid bearer scheme length");
            return None;
        }
        if !value[..Self::SCHEME.len()].eq_ignore_ascii_case(Self::SCHEME.as_bytes()) {
            tracing::trace!("Bearer credentials failed to decode: invalid bearer scheme");
            return None;
        }

        let bytes = &value[Self::SCHEME.len() + 1..];

        let Some(non_space_pos) = bytes.iter().position(|b| *b != b' ') else {
            tracing::trace!("Bearer credentials failed to decode: no token found");
            return None;
        };

        let bytes = &bytes[non_space_pos..];

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

/// The `Authority` trait is used to determine if a set of [`Credential`]s are authorized.
///
/// [`Credential`]: rama_http_headers::authorization::Credentials
pub trait Authority<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, credentials: C) -> impl Future<Output = Option<Extensions>> + Send + '_;
}

/// A synchronous version of [`Authority`], to be used for primitive implementations.
pub trait AuthoritySync<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool;
}

impl<A, C, L> Authority<C, L> for A
where
    A: AuthoritySync<C, L>,
    C: Credentials + Send + 'static,
    L: 'static,
{
    async fn authorized(&self, credentials: C) -> Option<Extensions> {
        let mut ext = Extensions::new();
        if self.authorized(&mut ext, &credentials) {
            Some(ext)
        } else {
            None
        }
    }
}

impl<T: UsernameLabelParser> AuthoritySync<Self, T> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Self) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.password() {
            return false;
        }

        let mut parser_ext = Extensions::new();
        let username = match parse_username(&mut parser_ext, T::default(), username) {
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

        ext.extend(parser_ext);
        ext.insert(UserId::Username(username));
        true
    }
}

impl<C, L, T, const N: usize> AuthoritySync<C, L> for [T; N]
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

impl<C, L, T> AuthoritySync<C, L> for Vec<T>
where
    C: Credentials + Send + 'static,
    T: AuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

#[cfg(test)]
mod tests {
    use rama_http_types::header::HeaderMap;
    use rama_net::user::credentials::bearer;
    use rama_utils::str::non_empty_str;

    use super::super::{test_decode, test_encode};
    use super::{Authorization, Basic, Bearer};
    use crate::HeaderMapExt;

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
        let user: &UserId = ext.get().unwrap();
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

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        let labels: &UsernameLabels = ext.get().unwrap();
        assert_eq!(&labels.0, &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_not_found() {
        let auth = basic!("john", "secret");
        let auths = vec![basic!("foo", "bar"), auth.clone()];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get::<UsernameLabels>().is_none());
    }
}
