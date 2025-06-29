use std::fmt;

use rama_http::headers;
use smallvec::{SmallVec, smallvec};
use smol_str::SmolStr;

#[derive(Debug, Clone)]
/// Utility type containing sub protocols as advertised by the client,
/// and which the server has to match if defined.
pub struct SubProtocols(pub(super) SmallVec<[SmolStr; 3]>);

impl fmt::Display for SubProtocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        headers::util::csv::fmt_comma_delimited(&mut *f, self.0.iter())
    }
}

impl SubProtocols {
    #[inline]
    /// Create a new [`SubProtocols`] object from the given protocol
    pub fn new(protocol: impl Into<SmolStr>) -> Self {
        Self(smallvec![protocol.into()])
    }

    /// returns true if the given sub protocol is found in this [`SubProtocols`]
    pub fn contains(&self, sub_protocol: impl AsRef<str>) -> Option<AcceptedSubProtocol> {
        let sub_protocol = sub_protocol.as_ref().trim();
        for protocol in self.0.iter() {
            if protocol.as_str().eq_ignore_ascii_case(sub_protocol) {
                return Some(AcceptedSubProtocol(protocol.clone()));
            }
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(AsRef::as_ref)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocol, appending it to any existing sub protocol(s).
        pub fn additional_sub_protocol(mut self, protocol: impl Into<SmolStr>) -> Self {
            self.0.push(protocol.into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocols, appending it to any existing sub protocol(s).
        pub fn additional_sub_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
            self.0.extend(protocols.into_iter().map(Into::into));
            self
        }
    }
}

impl<Item: Into<SmolStr>> From<Item> for SubProtocols {
    fn from(protocol: Item) -> Self {
        Self(smallvec![protocol.into()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Utility type containing the accepted Web Socket sub protocol.
pub struct AcceptedSubProtocol(SmolStr);

impl fmt::Display for AcceptedSubProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AcceptedSubProtocol {
    /// View the [`AcceptedSubProtocol`] as a `str` reference.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl AsRef<str> for AcceptedSubProtocol {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl PartialEq<str> for AcceptedSubProtocol {
    fn eq(&self, other: &str) -> bool {
        self.0.as_str() == other
    }
}

impl PartialEq<AcceptedSubProtocol> for str {
    fn eq(&self, other: &AcceptedSubProtocol) -> bool {
        self == other.as_str()
    }
}
