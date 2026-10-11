//! Optional profile identity in addition to mandatory TLS resumption policy.

use super::TlsPoolComponent;
use rama_core::extensions::Extension;
use rama_utils::str::arcstr::ArcStr;

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
