use std::fmt;

use super::{Basic, Bearer};

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
            ProxyCredential::Basic(basic) => basic.fmt(f),
            ProxyCredential::Bearer(bearer) => bearer.fmt(f),
        }
    }
}
