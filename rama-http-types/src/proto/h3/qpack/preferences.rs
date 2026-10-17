//! QPACK encoding preferences that leave peer limits and local budgets intact.

use rama_core::extensions::Extension;

/// Per-connection encoding choices, independent of local resource budgets.
///
/// As a client connection extension these override only the selected choices
/// in the connector's fixed encoder configuration. Peer SETTINGS still limit
/// dynamic compression. Absent fields retain the fixed configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Extension)]
pub struct EncoderPreferences {
    /// Desired dynamic-table capacity; zero keeps fields statically encoded.
    /// The actual capacity is clamped to the peer's advertised maximum.
    pub target_capacity: Option<u64>,
    /// Permit Huffman encoding when it saves bytes; plain encoding wins ties.
    pub huffman: Option<bool>,
    /// Keep the first field section static/literal, then use the normal dynamic policy.
    pub defer_dynamic_first_section: Option<bool>,
}
