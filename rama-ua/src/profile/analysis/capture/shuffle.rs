//! Merge variants whose TLS extension order the client shuffles per connection.

use std::collections::BTreeSet;

use rama_tls::ExtensionId;

use super::{CaptureOrderPath, CountedCaptureAnalysis, merge::merge_rewritten};
use crate::profile::{
    analysis::order::{DerivedOrderRule, OrderAnalysisConfig},
    capture::{
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
};

fn tls_limits(config: OrderAnalysisConfig) -> TlsCaptureLimits {
    TlsCaptureLimits {
        elements: config.maximum_elements,
        bytes: config.maximum_bytes,
    }
}

fn joint_limits(config: OrderAnalysisConfig) -> JointCaptureLimits {
    JointCaptureLimits {
        value_bytes: config.maximum_bytes,
        bytes: config.maximum_bytes,
        ..JointCaptureLimits::default()
    }
}

fn is_tls_slot(kind: CapturedSlotKind) -> bool {
    matches!(kind, CapturedSlotKind::TcpTls | CapturedSlotKind::QuicTls)
}

/// The TLS ClientHello retained in a joint tuple, if any.
pub(super) fn joint_tls(
    value: &CanonicalValue,
    config: OrderAnalysisConfig,
) -> Result<Option<TlsCapture>, ProfileDataError> {
    let joint = JointCapture::from_canonical(value, joint_limits(config))?;
    joint
        .slots
        .iter()
        .find(|slot| is_tls_slot(slot.kind))
        .map(|slot| TlsCapture::from_canonical(&slot.value, tls_limits(config)))
        .transpose()
}

/// Extensions in ID order, with a pre-shared key kept last as TLS requires.
fn sort_extensions(capture: &mut TlsCapture) {
    let psk = u16::from(ExtensionId::PRE_SHARED_KEY);
    capture
        .extensions
        .sort_by_key(|extension| (extension.id == psk, extension.id));
}

/// The value with its TLS extensions in one fixed order.
fn without_extension_order(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    config: OrderAnalysisConfig,
) -> Result<CanonicalValue, ProfileDataError> {
    match domain {
        CanonicalDomain::Tls => {
            let mut capture = TlsCapture::from_canonical(value, tls_limits(config))?;
            sort_extensions(&mut capture);
            capture.canonical(tls_limits(config))
        }
        CanonicalDomain::Joint => {
            let mut joint = JointCapture::from_canonical(value, joint_limits(config))?;
            for slot in &mut joint.slots {
                if is_tls_slot(slot.kind) {
                    let mut capture = TlsCapture::from_canonical(&slot.value, tls_limits(config))?;
                    sort_extensions(&mut capture);
                    slot.value = capture.canonical(tls_limits(config))?;
                }
            }
            joint.canonical(joint_limits(config))
        }
        _ => Ok(value.clone()),
    }
}

impl CountedCaptureAnalysis {
    /// Whether the client shuffles its TLS extension order per connection.
    pub fn shuffles_tls_extensions(&self) -> bool {
        self.orders.iter().any(|order| {
            order.path == CaptureOrderPath::TlsExtensions
                && matches!(
                    order.evidence.derived,
                    Some(DerivedOrderRule::Shuffled { .. })
                )
        })
    }

    /// `value` as this analysis reads it, so a value captured elsewhere compares to its variants.
    pub fn read_extension_order(
        &self,
        value: &CanonicalValue,
        config: OrderAnalysisConfig,
    ) -> Result<CanonicalValue, ProfileDataError> {
        if self.shuffles_tls_extensions() {
            without_extension_order(value, self.domain, config)
        } else {
            Ok(value.clone())
        }
    }
}

/// Merge variants that differ only in a shuffled TLS extension order.
pub(super) fn merge_shuffled_extension_orders(
    analysis: &mut CountedCaptureAnalysis,
    config: OrderAnalysisConfig,
    preserved: &BTreeSet<ValueId>,
) -> Result<(), ProfileDataError> {
    if !analysis.shuffles_tls_extensions() {
        return Ok(());
    }
    let domain = analysis.domain;
    merge_rewritten(analysis, config, preserved, |value| {
        without_extension_order(value, domain, config)
    })
}
