//! Client handshake offers and optional isolation within TLS resumption policy.

use super::TlsPoolComponent;
use rama_core::extensions::Extension;
use rama_utils::str::arcstr::ArcStr;

/// Session offer for a new TLS connection, independent of ticket retention.
///
/// Install this extension in a client TLS configuration. It neither carries a
/// session nor changes reuse of an established connection. A backend must reject
/// a mode it cannot support rather than silently changing the offer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
pub enum ClientHandshake {
    /// Offer a compatible cached session when the backend has one.
    #[default]
    Auto,
    /// Do not offer a cached session; newly issued tickets may still be retained.
    Full,
    /// Require a compatible stored session before emitting handshake output.
    /// The peer can still decline its offer and perform a full handshake.
    Resumed,
}

/// Stable emulation profile identity for TLS session resumption.
///
/// This adds an isolation boundary to the server and security-policy scope. It
/// never replaces verification, trust, credentials, ALPN or version checks.
/// Keep this identity fixed across the profile's connection draws; including
/// a drawn extension order prevents otherwise compatible sessions from resuming.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsSessionProfileScope(pub ArcStr);

impl TlsPoolComponent for TlsSessionProfileScope {
    type Identity = ArcStr;

    fn pool_component_identity(&self) -> Self::Identity {
        self.0.clone()
    }
}
