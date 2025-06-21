//! Authorization header and types.

use std::borrow::Cow;

use rama_core::context::Extensions;
use rama_core::telemetry::tracing;
use rama_core::username::{UsernameLabelParser, parse_username};
use rama_http_types::{HeaderName, HeaderValue};
use rama_net::user::credentials::{BASIC_SCHEME, BEARER_SCHEME};
use rama_net::user::{Basic, Bearer, UserId};

use crate::{Error, Header};

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
///
/// let basic = Authorization::basic("Aladdin", "open sesame");
/// let bearer = Authorization::bearer("some-opaque-token").unwrap();
/// ```
///
#[derive(Clone, PartialEq, Debug)]
pub struct Authorization<C: Credentials>(pub C);

impl Authorization<Basic> {
    /// Create a `Basic` authorization header.
    pub fn basic(
        username: impl Into<Cow<'static, str>>,
        password: impl Into<Cow<'static, str>>,
    ) -> Self {
        Authorization(Basic::new(username, password))
    }

    /// Create a `Basic` authorization header with only a username.
    pub fn basic_username(username: impl Into<Cow<'static, str>>) -> Self {
        Authorization(Basic::unprotected(username))
    }

    /// View the decoded username.
    pub fn username(&self) -> &str {
        self.0.username()
    }

    /// View the decoded password.
    pub fn password(&self) -> &str {
        self.0.password()
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "bearer token is not a valid header value"]
    pub struct InvalidHttpBearerToken;
}

impl Authorization<Bearer> {
    /// Try to create a `Bearer` authorization header.
    pub fn bearer(token: impl Into<Cow<'static, str>>) -> Result<Self, InvalidHttpBearerToken> {
        Ok(Authorization(Bearer::try_from_clear_str(token).map_err(
            |err| {
                tracing::debug!("invalid bearer http bearer token: {err:?}");
                InvalidHttpBearerToken
            },
        )?))
    }

    /// View the token part as a `&str`.
    pub fn token(&self) -> &str {
        self.0.token()
    }
}

impl<C: Credentials> Header for Authorization<C> {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::AUTHORIZATION
    }

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

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut value = self.0.encode();
        value.set_sensitive(true);
        debug_assert!(
            value.as_bytes().starts_with(C::SCHEME.as_bytes()),
            "Credentials::encode should include its scheme: scheme = {:?}, encoded = {:?}",
            C::SCHEME,
            value,
        );

        values.extend(::std::iter::once(value));
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
    fn encode(&self) -> HeaderValue;
}

impl Credentials for Basic {
    const SCHEME: &'static str = BASIC_SCHEME;

    fn decode(value: &HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?;
        Self::try_from_header_str(value).ok()
    }

    fn encode(&self) -> HeaderValue {
        self.as_header_value()
    }
}

impl Credentials for Bearer {
    const SCHEME: &'static str = BEARER_SCHEME;

    fn decode(value: &HeaderValue) -> Option<Self> {
        Self::try_from_header_str(value.to_str().ok()?).ok()
    }

    fn encode(&self) -> HeaderValue {
        self.as_header_value()
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

impl<T: UsernameLabelParser> AuthoritySync<Basic, T> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
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

    use super::super::{test_decode, test_encode};
    use super::{Authorization, Basic, Bearer};
    use crate::HeaderMapExt;

    #[test]
    fn basic_encode() {
        let auth = Authorization::basic("Aladdin", "open sesame");
        let headers = test_encode(auth);

        assert_eq!(
            headers["authorization"],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        );
    }

    #[test]
    fn basic_username_encode() {
        let auth = Authorization::basic_username("Aladdin");
        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Basic QWxhZGRpbjo=",);
    }

    #[test]
    fn basic_roundtrip() {
        let auth = Authorization::basic("Aladdin", "open sesame");
        let mut h = HeaderMap::new();
        h.typed_insert(auth.clone());
        assert_eq!(h.typed_get(), Some(auth));
    }

    #[test]
    fn basic_encode_no_password() {
        let auth = Authorization::basic("Aladdin", "");
        let headers = test_encode(auth);

        assert_eq!(headers["authorization"], "Basic QWxhZGRpbjo=",);
    }

    #[test]
    fn basic_decode() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_case_insensitive() {
        let auth: Authorization<Basic> =
            test_decode(&["basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_extra_whitespaces() {
        let auth: Authorization<Basic> =
            test_decode(&["Basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ=="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "open sesame");
    }

    #[test]
    fn basic_decode_no_password() {
        let auth: Authorization<Basic> = test_decode(&["Basic QWxhZGRpbjo="]).unwrap();
        assert_eq!(auth.0.username(), "Aladdin");
        assert_eq!(auth.0.password(), "");
    }

    #[test]
    fn bearer_encode() {
        let auth = Authorization::bearer("fpKL54jvWmEGVoRdCNjG").unwrap();

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

    #[tokio::test]
    async fn basic_authorization() {
        let auth = Basic::new("Aladdin", "open sesame");
        let auths = vec![Basic::new("foo", "bar"), auth.clone()];
        let ext = Authority::<_, ()>::authorized(&auths, auth).await.unwrap();
        let user: &UserId = ext.get().unwrap();
        assert_eq!(user, "Aladdin");
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let auths = vec![Basic::new("foo", "bar"), Basic::new("john", "secret")];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(
            &auths,
            Basic::new("john-green-red", "secret"),
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
        let auth = Basic::new("john", "secret");
        let auths = vec![Basic::new("foo", "bar"), auth.clone()];

        let ext = Authority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get::<UsernameLabels>().is_none());
    }
}
