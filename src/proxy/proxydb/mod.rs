use crate::http::{RequestContext, Version};
use base64::Engine;
use serde::Deserialize;
use std::{future::Future, str::FromStr};

mod internal;
pub use internal::{Proxy, ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind};

mod str;
#[doc(inline)]
pub use str::StringFilter;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone)]
/// The credentials to use to authenticate with the proxy.
pub enum ProxyCredentials {
    /// Basic authentication
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc7617> for more information.
    Basic {
        /// The username to use to authenticate with the proxy.
        username: String,
        /// The optional password to use to authenticate with the proxy,
        /// in combination with the username.
        password: Option<String>,
    },
    /// Bearer token authentication, token content is opaque for the proxy facilities.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc6750> for more information.
    Bearer(String),
}

impl ProxyCredentials {
    /// Get the username from the credentials, if any.
    pub fn username(&self) -> Option<&str> {
        match self {
            ProxyCredentials::Basic { username, .. } => Some(username),
            ProxyCredentials::Bearer(_) => None,
        }
    }

    /// Get the password from the credentials, if any.
    pub fn password(&self) -> Option<&str> {
        match self {
            ProxyCredentials::Basic { password, .. } => password.as_deref(),
            ProxyCredentials::Bearer(_) => None,
        }
    }

    /// Get the bearer token from the credentials, if any.
    pub fn bearer(&self) -> Option<&str> {
        match self {
            ProxyCredentials::Bearer(token) => Some(token),
            ProxyCredentials::Basic { .. } => None,
        }
    }
}

impl std::fmt::Display for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyCredentials::Basic { username, password } => match password {
                Some(password) => write!(
                    f,
                    "Basic {}",
                    BASE64.encode(format!("{}:{}", username, password))
                ),
                None => write!(f, "Basic {}", BASE64.encode(username)),
            },
            ProxyCredentials::Bearer(token) => write!(f, "Bearer {}", token),
        }
    }
}

#[derive(Debug)]
/// The error that can be returned when parsing a proxy credentials string.
#[non_exhaustive]
pub struct InvalidProxyCredentialsString;

impl FromStr for ProxyCredentials {
    type Err = InvalidProxyCredentialsString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ' ');

        match parts.next() {
            Some("Basic") => {
                let encoded = parts.next().ok_or(InvalidProxyCredentialsString)?;
                let decoded = BASE64
                    .decode(encoded)
                    .map_err(|_| InvalidProxyCredentialsString)?;
                let decoded =
                    String::from_utf8(decoded).map_err(|_| InvalidProxyCredentialsString)?;
                let mut parts = decoded.splitn(2, ':');

                let username = parts
                    .next()
                    .ok_or(InvalidProxyCredentialsString)?
                    .to_owned();
                let password = parts.next().map(str::to_owned);

                Ok(ProxyCredentials::Basic { username, password })
            }
            Some("Bearer") => {
                let token = parts.next().ok_or(InvalidProxyCredentialsString)?;
                Ok(ProxyCredentials::Bearer(token.to_owned()))
            }
            _ => Err(InvalidProxyCredentialsString),
        }
    }
}

impl std::fmt::Display for InvalidProxyCredentialsString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid proxy credentials string")
    }
}

impl std::error::Error for InvalidProxyCredentialsString {}

#[derive(Debug, Default, Clone, Deserialize, PartialEq)]
/// Filter to select a specific kind of proxy.
///
/// If the `id` is specified the other fields are used
/// as a validator to see if the only possible matching proxy
/// matches these fields.
///
/// If the `id` is not specified, the other fields are used
/// to select a random proxy from the pool.
///
/// Filters can be combined to make combinations with special meaning.
/// E.g. `datacenter:true, residential:true` is essentially an ISP proxy.
///
/// ## Usage
///
/// - Use [`HeaderConfigLayer`] to have this proxy filter be given by the [`Request`] headers,
///   which will add the extracted and parsed [`ProxyFilter`] to the [`Context`]'s [`Extensions`].
/// - Or extract yourself from the username/token validated in the [`ProxyAuthLayer`]
///   to add it manually to the [`Context`]'s [`Extensions`].
///
/// [`HeaderConfigLayer`]: crate::http::layer::header_config::HeaderConfigLayer
/// [`Request`]: crate::http::Request
/// [`ProxyAuthLayer`]: crate::http::layer::proxy_auth::ProxyAuthLayer
/// [`Context`]: crate::service::Context
/// [`Extensions`]: crate::service::context::Extensions
pub struct ProxyFilter {
    /// The ID of the proxy to select.
    pub id: Option<String>,

    /// The ID of the pool from which to select the proxy.
    pub pool_id: Option<StringFilter>,

    /// The country of the proxy.
    pub country: Option<StringFilter>,

    /// The city of the proxy.
    pub city: Option<StringFilter>,

    /// Set explicitly to `true` to select a datacenter proxy.
    pub datacenter: Option<bool>,

    /// Set explicitly to `true` to select a residential proxy.
    pub residential: Option<bool>,

    /// Set explicitly to `true` to select a mobile proxy.
    pub mobile: Option<bool>,

    /// The mobile carrier desired.
    pub carrier: Option<StringFilter>,
}

/// The trait to implement to provide a proxy database to other facilities,
/// such as connection pools, to provide a proxy based on the given
/// [`RequestContext`] and [`ProxyFilter`].
pub trait ProxyDB: Send + Sync + 'static {
    /// The error type that can be returned by the proxy database
    ///
    /// Examples are generic I/O issues or
    /// even more common if no proxy match could be found.
    type Error;

    /// Get a [`Proxy`] based on the given [`RequestContext`] and [`ProxyFilter`],
    /// or return an error in case no [`Proxy`] could be returned.
    fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_;
}

/// A fast in-memory ProxyDatabase that is the default choice for Rama.
#[derive(Debug)]
pub struct MemoryProxyDB {
    data: internal::ProxyDB,
}

impl MemoryProxyDB {
    /// Create a new in-memory proxy database with the given proxies.
    pub fn try_from_rows(proxies: Vec<Proxy>) -> Result<Self, MemoryProxyDBError> {
        Ok(MemoryProxyDB {
            data: internal::ProxyDB::from_rows(proxies).map_err(|err| match err.kind() {
                internal::ProxyDBErrorKind::DuplicateKey => MemoryProxyDBError::duplicate(),
            })?,
        })
    }

    /// Create a new in-memory proxy database with the given proxies from an iterator.
    pub fn try_from_iter<I>(proxies: I) -> Result<Self, MemoryProxyDBError>
    where
        I: IntoIterator<Item = Proxy>,
    {
        Ok(MemoryProxyDB {
            data: internal::ProxyDB::from_iter(proxies).map_err(|err| match err.kind() {
                internal::ProxyDBErrorKind::DuplicateKey => MemoryProxyDBError::duplicate(),
            })?,
        })
    }
}

impl ProxyDB for MemoryProxyDB {
    type Error = MemoryProxyDBError;

    async fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        match &filter.id {
            Some(id) => match self.data.get_by_id(id) {
                None => Err(MemoryProxyDBError::not_found()),
                Some(proxy) => {
                    if proxy.is_match(&ctx, &filter) {
                        Ok(proxy.clone())
                    } else {
                        Err(MemoryProxyDBError::mismatch())
                    }
                }
            },
            None => {
                let mut query = self.data.query();

                if let Some(pool_id) = filter.pool_id {
                    query.pool_id(pool_id);
                }
                if let Some(country) = filter.country {
                    query.country(country);
                }
                if let Some(city) = filter.city {
                    query.city(city);
                }

                if let Some(value) = filter.datacenter {
                    query.datacenter(value);
                }
                if let Some(value) = filter.residential {
                    query.residential(value);
                }
                if let Some(value) = filter.mobile {
                    query.mobile(value);
                }

                if ctx.http_version == Version::HTTP_3 {
                    query.udp(true);
                    query.socks5(true);
                } else {
                    // TODO: is there ever a need to allow non-http/3
                    // reqs to request socks5??? Probably yes,
                    // e.g. non-http protocols, but we need to
                    // implement that somehow then. As such... TODO
                    query.tcp(true);
                }

                match query.execute().map(|result| result.any()).cloned() {
                    None => Err(MemoryProxyDBError::not_found()),
                    Some(proxy) => Ok(proxy),
                }
            }
        }
    }
}

/// The error type that can be returned by [`MemoryProxyDB`] when no proxy match could be found.
#[derive(Debug)]
pub struct MemoryProxyDBError {
    kind: MemoryProxyDBErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The kind of error that [`MemoryProxyDBError`] represents.
pub enum MemoryProxyDBErrorKind {
    /// No proxy match could be found.
    NotFound,
    /// A proxy looked up by key had a config that did not match the given filters/requirements.
    Mismatch,
    /// A proxy with the same key already exists in the database.
    Duplicate,
}

impl std::fmt::Display for MemoryProxyDBError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            MemoryProxyDBErrorKind::NotFound => write!(f, "No proxy match could be found"),
            MemoryProxyDBErrorKind::Mismatch => write!(
                f,
                "Proxy config did not match the given filters/requirements"
            ),
            MemoryProxyDBErrorKind::Duplicate => write!(
                f,
                "A proxy with the same key already exists in the database"
            ),
        }
    }
}

impl std::error::Error for MemoryProxyDBError {}

impl MemoryProxyDBError {
    fn not_found() -> Self {
        MemoryProxyDBError {
            kind: MemoryProxyDBErrorKind::NotFound,
        }
    }

    fn mismatch() -> Self {
        MemoryProxyDBError {
            kind: MemoryProxyDBErrorKind::Mismatch,
        }
    }

    fn duplicate() -> Self {
        MemoryProxyDBError {
            kind: MemoryProxyDBErrorKind::Duplicate,
        }
    }

    /// Returns the kind of error that [`MemoryProxyDBError`] represents.
    pub fn kind(&self) -> MemoryProxyDBErrorKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_credentials_from_str_basic() {
        let credentials: ProxyCredentials = "Basic dXNlcm5hbWU6cGFzc3dvcmQ=".parse().unwrap();
        assert_eq!(credentials.username().unwrap(), "username");
        assert_eq!(credentials.password().unwrap(), "password");
    }

    #[test]
    fn test_proxy_credentials_from_str_bearer() {
        let credentials: ProxyCredentials = "Bearer bar".parse().unwrap();
        assert_eq!(credentials.bearer().unwrap(), "bar");
    }

    #[test]
    fn test_proxy_credentials_from_str_invalid() {
        let credentials: Result<ProxyCredentials, _> = "Invalid".parse();
        assert!(credentials.is_err());
    }

    #[test]
    fn test_proxy_credentials_display_basic() {
        let credentials = ProxyCredentials::Basic {
            username: "username".to_owned(),
            password: Some("password".to_owned()),
        };
        assert_eq!(credentials.to_string(), "Basic dXNlcm5hbWU6cGFzc3dvcmQ=");
    }

    #[test]
    fn test_proxy_credentials_display_basic_no_password() {
        let credentials = ProxyCredentials::Basic {
            username: "username".to_owned(),
            password: None,
        };
        assert_eq!(credentials.to_string(), "Basic dXNlcm5hbWU=");
    }

    #[test]
    fn test_proxy_credentials_display_bearer() {
        let credentials = ProxyCredentials::Bearer("foo".to_owned());
        assert_eq!(credentials.to_string(), "Bearer foo");
    }
}
