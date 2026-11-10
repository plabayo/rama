//! The stored layout of a compiled set. Ids that follow from stored bytes are not
//! stored, and a repeated value names the stored copy that holds its bytes.

use rama_core::{bytes::Bytes, error::BoxError};
use serde::{Deserialize, Serialize};

use super::compact::{CompiledCapture, CompiledField, CompiledHeaders};
use crate::profile::{
    analysis::{
        capture::{CaptureOrderPath, NetworkHintVariant},
        order::{
            AnalyzedOrderElement, AnalyzedOrderWeight, ObservedReservedPlacement,
            OrderAnalysisDisposition, PinnedOrderElement,
        },
        profile::AnalyzedProfileComponents,
    },
    evidence::counts::ObservationLosses,
    format::canonical::{CanonicalDomain, ValueId},
    model::identity::{ConnectionContext, FlowKey, ProfileKey},
};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireSet {
    pub(super) classifier_revision: u16,
    /// Distinct header fields of every profile.
    pub(super) fields: Vec<CompiledField>,
    /// Distinct header captures, naming positions in `fields`.
    pub(super) headers: Vec<CompiledHeaders>,
    pub(super) profiles: Vec<WireProfile>,
}

/// A profile without its id, which is the digest of its key.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireProfile {
    pub(super) format_version: u16,
    pub(super) classifier_revision: u16,
    pub(super) key: ProfileKey,
    pub(super) current_day: u32,
    pub(super) horizon: u32,
    pub(super) components: AnalyzedProfileComponents,
    pub(super) scopes: Vec<WireScope>,
}

/// A scope without its id or the ids its context repeats from the profile, flow and structure.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireScope {
    pub(super) authorized: bool,
    pub(super) connection: ConnectionContext,
    pub(super) revision: u16,
    pub(super) flow: Option<FlowKey>,
    pub(super) structure: WireValue,
    pub(super) observations: WireObservations,
}

/// The observations selection and replay read; other counters stay in archives.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireObservations {
    pub(super) classifier_revision: u16,
    pub(super) domain: CanonicalDomain,
    pub(super) total: u64,
    pub(super) losses: ObservationLosses,
    /// Positions in `variants`.
    pub(super) sample_values: Vec<u32>,
    pub(super) variants: Vec<WireVariant>,
    pub(super) orders: Vec<WireOrder>,
    pub(super) network_hints: Box<[NetworkHintVariant]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireVariant {
    pub(super) value: WireCapture,
    pub(super) weight: AnalyzedOrderWeight,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WireCapture {
    Canonical(WireValue),
    /// The canonical bytes of a compact capture are not stored, so its id is.
    Compact {
        id: ValueId,
        capture: CompiledCapture,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WireValue {
    /// The first copy of a value; its id is the digest of these bytes.
    Bytes(Bytes),
    /// The value stored as the n-th `Bytes` of the set, in [`for_each_value`] order.
    Stored(u32),
    /// A slot of a stored joint capture, sharing the joint's buffer.
    Slot { joint: u32, slot: u32 },
}

/// Order evidence of the paths replay reads: only the rule derived for it.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireOrder {
    pub(super) path: CaptureOrderPath,
    pub(super) derived: Option<WireRule>,
    pub(super) disposition: OrderAnalysisDisposition,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum WireRule {
    Mixture {
        modes: Box<[WireMode]>,
    },
    Sorted {
        elements: Box<[AnalyzedOrderElement]>,
    },
    Relative {
        literals: Box<[AnalyzedOrderElement]>,
        placements: Box<[ObservedReservedPlacement]>,
    },
    Shuffled {
        elements: Box<[AnalyzedOrderElement]>,
        pinned: Box<[PinnedOrderElement]>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct WireMode {
    pub(super) sample_indices: Box<[usize]>,
    pub(super) sample_size: usize,
    pub(super) derived: Option<WireRule>,
    pub(super) disposition: OrderAnalysisDisposition,
}

/// Whether a value may hold the slots other values refer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ValueRole {
    Joint,
    Other,
}

/// Visit every value of `set` in one fixed order, which numbers the stored values.
pub(super) fn for_each_value(
    set: &mut WireSet,
    mut visit: impl FnMut(ValueRole, &mut WireValue) -> Result<(), BoxError>,
) -> Result<(), BoxError> {
    for profile in &mut set.profiles {
        for scope in &mut profile.scopes {
            visit(ValueRole::Other, &mut scope.structure)?;
            let role = if scope.observations.domain == CanonicalDomain::Joint {
                ValueRole::Joint
            } else {
                ValueRole::Other
            };
            for variant in &mut scope.observations.variants {
                match &mut variant.value {
                    WireCapture::Canonical(value) => visit(role, value)?,
                    WireCapture::Compact { capture, .. } => {
                        for value in capture.values_mut() {
                            visit(ValueRole::Other, value)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
