use std::str::FromStr;

use crate::error::OpaqueError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Kind of fowarder to use, to help you forward the client Ip information.
///
/// Useful in case your service is behind a load balancer.
pub enum ForwardKind {
    /// [`Forwarded`] header.
    ///
    /// [`Forwarded`]: crate::net::forwarded::Forwarded
    Forwarded,
    /// [`X-Forwarded-For`] header.
    ///
    /// [`X-Forwarded-For`]: crate::http::headers::XForwardedFor
    XForwardedFor,
    /// [`X-Client-Ip`] header.
    ///
    /// [`X-Client-Ip`]: crate::http::headers::XClientIp
    XClientIp,
    /// [`Client-Ip`] header.
    ///
    /// [`Client-Ip`]: crate::http::headers::ClientIp
    ClientIp,
    /// [`X-Real-Ip`] header.
    ///
    /// [`X-Real-Ip`]: crate::http::headers::XRealIp
    XRealIp,
    /// [`Cf-Connecting-Ip`] header.
    ///
    /// [`Cf-Connecting-Ip`]: crate::http::headers::CFConnectingIp
    CFConnectingIp,
    /// [`True-Client-Ip`] header.
    ///
    /// [`True-Client-Ip`]: crate::http::headers::TrueClientIp
    TrueClientIp,
    /// [`HaProxy`] protocol (transport layer).
    ///
    /// [`HaProxy`]: crate::proxy::pp
    HaProxy,
}

impl<'a> TryFrom<&'a str> for ForwardKind {
    type Error = OpaqueError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match_ignore_ascii_case_str! {
            match(value) {
                "forwarded" => Ok(Self::Forwarded),
                "x-forwarded-for" => Ok(Self::XForwardedFor),
                "x-client-ip" => Ok(Self::XClientIp),
                "x-real-ip" => Ok(Self::XRealIp),
                "cf-connecting-ip" => Ok(Self::CFConnectingIp),
                "true-client-ip" => Ok(Self::TrueClientIp),
                "haproxy" => Ok(Self::HaProxy),
                _ => Err(OpaqueError::from_display(format!("unknown forward kind: {value})"))),
            }
        }
    }
}

impl TryFrom<String> for ForwardKind {
    type Error = OpaqueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl FromStr for ForwardKind {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}
