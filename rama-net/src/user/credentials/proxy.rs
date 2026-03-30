use std::fmt;

use super::{Basic, Bearer};

#[derive(Debug, Clone)]
/// Extension wrapper that can be used by
/// Deep Protocol Inspection (DPI) services which
/// processed an exchanged [`ProxyCredential`].
pub struct DpiProxyCredential(pub ProxyCredential);

#[derive(Debug, Clone, PartialEq, Eq)]
/// Proxy credentials.
pub enum ProxyCredential {
    /// [`Basic`]` credentials.
    Basic(Basic),
    /// [`Bearer`] credentials.
    Bearer(Bearer),
}

impl From<Basic> for ProxyCredential {
    fn from(basic: Basic) -> Self {
        Self::Basic(basic)
    }
}

impl From<Bearer> for ProxyCredential {
    fn from(bearer: Bearer) -> Self {
        Self::Bearer(bearer)
    }
}

impl fmt::Display for ProxyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic(basic) => basic.fmt(f),
            Self::Bearer(bearer) => bearer.fmt(f),
        }
    }
}
