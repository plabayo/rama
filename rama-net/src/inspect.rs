//! Transport observations shared by protocol-specific inspectors.

use rama_core::extensions::Extension;
use rama_inspect::Observations;
use serde::{Deserialize, Serialize};

use crate::{Protocol, address::SocketAddress};

/// Correlates transport metadata across protocol layers on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension, Serialize, Deserialize)]
#[extension(tags(net))]
pub struct ConnectionId(pub u64);

/// A transport connection; protocol owners attach their observations separately.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSummary {
    pub id: u64,
    pub display_id: u64,
    pub label: Option<String>,
    pub started_at: jiff::Timestamp,
    pub local_address: Option<SocketAddress>,
    pub peer_address: Option<SocketAddress>,
    pub ingress_protocol: Protocol,
    pub active: bool,
    pub ended_at: Option<jiff::Timestamp>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    #[serde(skip)]
    pub metadata: Observations,
}
