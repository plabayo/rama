use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use ahash::HashSet;
use rama_net::uri::Uri;

use super::ConfigError;

/// A normalized origin used for structural matching.
///
/// Two origins are equal when their scheme security (`http` vs `https`), their host (compared
/// case-insensitively) and their port match — where an implicit port is resolved to the scheme's
/// default (`80` for `http`, `443` for `https`). This mirrors how rama treats URIs elsewhere
/// rather than the byte-exact comparison used by the Go reference.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct CsrfOrigin {
    secure: bool,
    host: Box<str>,
    port: u16,
}

impl CsrfOrigin {
    /// Build a [`CsrfOrigin`] from a scheme, host, and optional explicit port.
    ///
    /// Returns `None` for any scheme other than `http`/`https`, since such an origin can never
    /// be sent by a browser as a same-origin request to an HTTP server.
    pub(crate) fn from_parts(scheme: &str, host: &str, port: Option<u16>) -> Option<Self> {
        let secure = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return None;
        };
        Some(Self {
            secure,
            host: host.to_ascii_lowercase().into_boxed_str(),
            port: port.unwrap_or(default_port(secure)),
        })
    }

    /// Whether this origin's authority (host + resolved port) equals the given effective host.
    ///
    /// The effective host carries no scheme, so this origin's scheme resolves the default port
    /// on the host side too.
    pub(crate) fn matches_host(&self, host: &str, port: Option<u16>) -> bool {
        self.host.as_ref().eq_ignore_ascii_case(host)
            && self.port == port.unwrap_or(default_port(self.secure))
    }
}

const fn default_port(secure: bool) -> u16 {
    if secure { 443 } else { 80 }
}

/// Parse and validate a trusted-origin configuration string into a [`CsrfOrigin`].
///
/// The input must be a bare origin of the form `scheme://host[:port]` with an `http`/`https`
/// scheme and no userinfo, path, query, or fragment. Parsing uses [`rama_net::uri::Uri`], so IDN
/// hosts are canonicalized to their ASCII (punycode) form — matching what browsers send.
pub(crate) fn parse_trusted_origin(input: &str) -> Result<CsrfOrigin, ConfigError> {
    let uri = Uri::parse_canonical(input).map_err(|err| ConfigError::InvalidOrigin {
        origin: input.into(),
        message: err.to_string().into_boxed_str(),
    })?;

    // An origin is `scheme://host[:port]` only — reject any userinfo, query, fragment, or a
    // non-root path. (A bare `scheme://host` parses with an empty or `/` path.)
    let has_path = uri
        .path()
        .is_some_and(|path| !path.is_empty() && path != "/");
    if uri.userinfo().is_some() || uri.query().is_some() || uri.fragment().is_some() || has_path {
        return Err(ConfigError::InvalidOriginComponents {
            origin: input.into(),
        });
    }

    let scheme = uri.scheme_str().unwrap_or_default();
    let host = uri.host_str();

    match host {
        Some(host) => CsrfOrigin::from_parts(scheme, &host, uri.port_u16()).ok_or_else(|| {
            ConfigError::OpaqueOrigin {
                origin: input.into(),
            }
        }),
        None => Err(ConfigError::OpaqueOrigin {
            origin: input.into(),
        }),
    }
}

/// The set of trusted origins, shared cheaply across clones of the middleware.
#[derive(Clone, Default)]
pub(crate) struct Origins(Arc<HashSet<CsrfOrigin>>);

impl Origins {
    pub(crate) fn contains(&self, origin: &CsrfOrigin) -> bool {
        self.0.contains(origin)
    }

    pub(crate) fn insert(&mut self, origin: CsrfOrigin) {
        Arc::make_mut(&mut self.0).insert(origin);
    }
}

impl Debug for Origins {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.iter()).finish()
    }
}
