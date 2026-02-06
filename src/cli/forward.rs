use crate::error::BoxError;
use rama_core::error::ErrorExt as _;
use rama_utils::macros::match_ignore_ascii_case_str;
use std::str::FromStr;

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
    /// [`X-Forwarded-For`]: crate::http::headers::forwarded::XForwardedFor
    XForwardedFor,
    /// [`X-Client-Ip`] header.
    ///
    /// [`X-Client-Ip`]: crate::http::headers::forwarded::XClientIp
    XClientIp,
    /// [`Client-Ip`] header.
    ///
    /// [`Client-Ip`]: crate::http::headers::forwarded::ClientIp
    ClientIp,
    /// [`X-Real-Ip`] header.
    ///
    /// [`X-Real-Ip`]: crate::http::headers::forwarded::XRealIp
    XRealIp,
    /// [`Cf-Connecting-Ip`] header.
    ///
    /// [`Cf-Connecting-Ip`]: crate::http::headers::forwarded::CFConnectingIp
    CFConnectingIp,
    /// [`True-Client-Ip`] header.
    ///
    /// [`True-Client-Ip`]: crate::http::headers::forwarded::TrueClientIp
    TrueClientIp,
    /// [`HaProxy`] protocol (transport layer).
    ///
    /// [`HaProxy`]: crate::proxy::haproxy
    HaProxy,
}

impl<'a> TryFrom<&'a str> for ForwardKind {
    type Error = BoxError;

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
                _ => Err(BoxError::from("unknown forward kind").context_str_field("str", value)),
            }
        }
    }
}

impl TryFrom<String> for ForwardKind {
    type Error = BoxError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl FromStr for ForwardKind {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}
