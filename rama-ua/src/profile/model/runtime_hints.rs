use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorExt as _};
use rama_core::extensions::Extension;
use rama_utils::macros::match_ignore_ascii_case_str;
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(ua))]
/// The initiator of the (http) Request.
///
/// It is used to determine the request initiator for the to be emulated http request,
/// and can either be attempted to be detected or manually injected into the [`Extensions`],
/// or implicitly via a layer service to extract that info from a custom http header.
///
/// [`ProfileEmulateLayer`] uses it to select the captured request flow to replay;
/// without it a top-level navigation is assumed.
///
/// [`Extensions`]: rama_core::extensions::Extensions
/// [`ProfileEmulateLayer`]: crate::layer::emulate::ProfileEmulateLayer
pub enum RequestInitiator {
    /// normal navigate, expexted by all [`super::ua::UserAgentProfile`] to be implemented
    Navigate,
    /// form action, considered optional (e.g. native non-browser user-agents typically don't support this)
    Form,
    /// XML Http Request (Original Ajax tech in browsers), to fetch content from (Js) scripts,
    /// considered optional (e.g. a very modern non-browser user-agent might support only the more
    /// modern Fetch API without backwards compatibility for the older XMLHttpRequest API)
    Xhr,
    /// Fetch API ("Modern" async-able approach to fetch content from (Js) scripts),
    /// optional and for example not supported by user-agents that are only capable of
    /// handling regular navigate requests or do not support more than one request type.
    Fetch,
    /// WebSocket Upgrade Request
    Ws,
}

impl RequestInitiator {
    /// Get the string representation of the request initiator.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Navigate => "navigate",
            Self::Form => "form",
            Self::Xhr => "xhr",
            Self::Fetch => "fetch",
            Self::Ws => "ws",
        }
    }
}

impl fmt::Display for RequestInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

use rama_utils::macros::serde_str::impl_serde_str;

impl_serde_str!(as_str RequestInitiator);

impl FromStr for RequestInitiator {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "navigate" => Ok(Self::Navigate),
                "form" => Ok(Self::Form),
                "xhr" => Ok(Self::Xhr),
                "fetch" => Ok(Self::Fetch),
                "ws" => Ok(Self::Ws),
                _ => Err(BoxError::from_static_str("invalid request initiator").context_str_field("str", s)),
            }
        }
    }
}
