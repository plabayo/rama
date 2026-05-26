use std::sync::Arc;

use arc_swap::ArcSwap;
use rama::bytes::Bytes;
use rama::net::tls::keylog::KeyLogToggle;

use crate::tls::DemoTlsMitmRelay;

/// Live-updatable proxy settings, atomically swapped via [`SharedState`].
///
/// These settings can be changed at runtime through the XPC server without
/// restarting the proxy. All other configuration (TLS relay, timeouts, CA) is
/// static and requires a restart to change.
///
/// `tls_keylog_toggle` is shared via its internal `Arc<AtomicBool>` — every
/// `LiveSettings` snapshot points at the same switch, so swapping snapshots
/// neither flips it nor disconnects it from the in-flight handshakes that
/// captured the sink.
pub(crate) struct LiveSettings {
    pub html_badge_enabled: bool,
    pub html_badge_label: String,
    pub exclude_domains: Vec<String>,
    pub ca_crt_pem: Bytes,
    pub tls_mitm_relay: DemoTlsMitmRelay,
    pub tls_keylog_toggle: KeyLogToggle,
}

pub(crate) type SharedState = Arc<ArcSwap<LiveSettings>>;
