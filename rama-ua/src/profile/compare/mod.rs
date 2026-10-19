//! Retained tuple membership and bounded field diagnostics for complete captures.
//!
//! A complete retained tuple must match after the explicitly selected projection.
//! Literal mode retains every fact; replay mode excludes only the events and
//! connection-local references documented by its policy. Order-only rules never
//! authorize mixing fields from different variants. A mismatch can still be valid under an unimplemented generator;
//! this API does not claim population or distribution equivalence.

#[cfg(feature = "tls")]
use crate::profile::capture::tls::TlsCaptureLimits;
use crate::profile::{
    capture::{
        headers::HeaderCapturePolicy,
        http2::H2CaptureLimits,
        http3::{H3SequenceCaptureLimits, bootstrap::H3BootstrapLimits},
        joint::JointCaptureLimits,
        order::OrderCaptureLimits,
        quic::QuicFlightCaptureLimits,
    },
    format::{
        canonical::{CanonicalValue, ProfileDataError, ValueId},
        decoded::{CaptureDecodeLimits, DecodedCapture},
    },
};
use rama_utils::octets::mib;
pub mod mode;

use mode::ComparisonMode;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy)]
pub struct CaptureComparisonLimits {
    pub bytes: usize,
    pub candidates: usize,
    pub work: usize,
    pub differences: usize,
}

impl Default for CaptureComparisonLimits {
    fn default() -> Self {
        Self {
            bytes: 65536,
            candidates: 4096,
            work: mib(16),
            differences: 64,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CaptureFieldDifference {
    /// JSON pointer into the decoded capture. Array indices retain wire order.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RetainedCaptureComparison {
    pub work_units: usize,
    /// Equality after the explicitly selected projection.
    pub matched: bool,
    pub mode: ComparisonMode,
    pub observed: ValueId,
    /// The matching variant, or the first retained variant used for diagnostics.
    pub reference: ValueId,
    pub differences: Vec<CaptureFieldDifference>,
    pub truncated: bool,
}

/// Compare an observation with whole retained tuples, then diagnose the first
/// reference if no tuple matches. Counts and derived rules are not compared.
/// Both canonical bytes and digest are validated before matching. The selected
/// mode controls only documented exclusions; reported identities always refer to
/// the original captures, including when their comparison projections differ.
pub fn compare_retained_captures(
    reference: &[CanonicalValue],
    observed: &CanonicalValue,
    mode: ComparisonMode,
    limits: CaptureComparisonLimits,
) -> Result<RetainedCaptureComparison, ProfileDataError> {
    if reference.is_empty() {
        return Err(ProfileDataError::Incomplete("comparison reference"));
    }
    if reference.len() > limits.candidates || limits.differences == 0 {
        return Err(ProfileDataError::LimitExceeded(
            "comparison candidates or differences",
        ));
    }
    let domain = observed.domain_tag(limits.bytes)?;
    let actual = decode(observed, limits.bytes)?;
    let mut work = limits
        .work
        .checked_sub(observed.bytes.len())
        .ok_or(ProfileDataError::LimitExceeded("comparison work"))?;
    let observed_projection = mode.project(observed, limits.bytes)?;
    let mut first_projection = None;
    let mut matched = None;
    for candidate in reference {
        work = work
            .checked_sub(candidate.bytes.len())
            .and_then(|work| work.checked_sub(observed.bytes.len()))
            .ok_or(ProfileDataError::LimitExceeded("comparison work"))?;
        if candidate.validated_domain(limits.bytes)? != domain {
            return Err(ProfileDataError::Invalid("comparison capture domain"));
        }
        let projected = mode.project(candidate, limits.bytes)?;
        if projected.bytes == observed_projection.bytes {
            matched = Some(candidate.id);
        }
        if first_projection.is_none() {
            first_projection = Some(projected);
        }
    }
    if let Some(reference) = matched {
        return Ok(RetainedCaptureComparison {
            work_units: limits.work - work,
            matched: true,
            mode,
            observed: observed.id,
            reference,
            differences: Vec::new(),
            truncated: false,
        });
    }
    let actual = if mode == ComparisonMode::Literal {
        actual
    } else {
        decode(&observed_projection, limits.bytes)?
    };
    let actual = diagnostic(actual, limits.bytes)?;
    let first_projection =
        first_projection.ok_or(ProfileDataError::Incomplete("comparison reference"))?;
    let expected = diagnostic(decode(&first_projection, limits.bytes)?, limits.bytes)?;
    let mut report = RetainedCaptureComparison {
        work_units: limits.work - work,
        matched: false,
        mode,
        observed: observed.id,
        reference: reference[0].id,
        differences: Vec::new(),
        truncated: false,
    };
    differences(
        Some(&expected),
        Some(&actual),
        "",
        limits.differences,
        &mut report,
    );
    Ok(report)
}

fn json(value: impl Serialize) -> Result<Value, ProfileDataError> {
    #[cfg(test)]
    tests::DIAGNOSTIC_SERIALIZATIONS.with(|count| count.set(count.get() + 1));
    serde_json::to_value(value)
        .map_err(|_error| ProfileDataError::Invalid("comparison decoded value"))
}

fn decode(value: &CanonicalValue, bytes: usize) -> Result<DecodedCapture<'_>, ProfileDataError> {
    let limits = CaptureDecodeLimits {
        bytes,
        headers: HeaderCapturePolicy {
            bytes,
            fields: bytes,
            overrides: Box::default(),
        },
        order: OrderCaptureLimits {
            bytes,
            elements: bytes,
        },
        h2: H2CaptureLimits {
            bytes,
            frames: bytes,
            settings: bytes,
        },
        h3: H3SequenceCaptureLimits {
            bytes,
            ..H3SequenceCaptureLimits::default()
        },
        h3_bootstrap: H3BootstrapLimits {
            bytes,
            ..Default::default()
        },
        quic: QuicFlightCaptureLimits {
            bytes,
            ..QuicFlightCaptureLimits::default()
        },
        joint: JointCaptureLimits {
            value_bytes: bytes,
            ..JointCaptureLimits::default()
        },
        #[cfg(feature = "tls")]
        tls: TlsCaptureLimits {
            bytes,
            elements: bytes,
        },
    };
    let decoded = DecodedCapture::from_canonical(value, &limits)?;
    if matches!(decoded, DecodedCapture::Canonical { .. }) {
        return Err(ProfileDataError::Unsupported("comparison capture domain"));
    }
    if let DecodedCapture::Joint(joint) = &decoded {
        // Exact matches must reject unsupported component domains too. Their
        // field diagnostics used to enforce this before the membership result.
        for slot in &joint.slots {
            decode(&slot.value, bytes)?;
        }
    }
    Ok(decoded)
}

// Only mismatches need a JSON tree. Exact membership still validates all inputs,
// but does not allocate diagnostic objects or serialize their captured fields.
fn diagnostic(value: DecodedCapture<'_>, bytes: usize) -> Result<Value, ProfileDataError> {
    match value {
        DecodedCapture::Headers(value) => json(value),
        DecodedCapture::Order(value) => json(value),
        DecodedCapture::H2(value) => json(value),
        DecodedCapture::H3(value) => json(value),
        DecodedCapture::H3Bootstrap(value) => json(value),
        DecodedCapture::PseudoHeaders(value) => json(value),
        DecodedCapture::Runtime(value) => json(value),
        DecodedCapture::Quic(value) => json(value),
        #[cfg(feature = "tls")]
        DecodedCapture::Tls(value) => json(value),
        DecodedCapture::Joint(joint) => {
            let mut slots = serde_json::Map::new();
            for slot in joint.slots.iter() {
                slots.insert(
                    format!("{:?}", slot.kind),
                    diagnostic(decode(&slot.value, bytes)?, bytes)?,
                );
            }
            Ok(
                serde_json::json!({"level": joint.level, "completeness": joint.completeness, "slots": slots}),
            )
        }
        DecodedCapture::Canonical { .. } => {
            Err(ProfileDataError::Unsupported("comparison capture domain"))
        }
    }
}

fn differences(
    expected: Option<&Value>,
    actual: Option<&Value>,
    path: &str,
    maximum: usize,
    report: &mut RetainedCaptureComparison,
) {
    if expected == actual {
        return;
    }
    if report.differences.len() == maximum {
        report.truncated = true;
        return;
    }
    match (expected, actual) {
        (Some(Value::Object(expected)), Some(Value::Object(actual))) => {
            let keys: std::collections::BTreeSet<_> =
                expected.keys().chain(actual.keys()).collect();
            for key in keys {
                let key_path = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                differences(
                    expected.get(key),
                    actual.get(key),
                    &key_path,
                    maximum,
                    report,
                );
            }
        }
        (Some(Value::Array(expected)), Some(Value::Array(actual))) => {
            for index in 0..expected.len().max(actual.len()) {
                differences(
                    expected.get(index),
                    actual.get(index),
                    &format!("{path}/{index}"),
                    maximum,
                    report,
                );
            }
        }
        _ => report.differences.push(CaptureFieldDifference {
            path: path.to_owned(),
            reference: expected.cloned(),
            observed: actual.cloned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind},
        order::OrderNamespace,
    };
    use crate::profile::capture::{joint::JointCapture, order::OrderedProtocolCapture};
    std::thread_local! {
        pub(super) static DIAGNOSTIC_SERIALIZATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    #[test]
    fn literal_membership_does_not_materialize_field_diagnostics() {
        let value = settings(&[(33, 17)]);
        DIAGNOSTIC_SERIALIZATIONS.with(|count| count.set(0));
        assert!(compare(std::slice::from_ref(&value), &value).matched);
        assert_eq!(DIAGNOSTIC_SERIALIZATIONS.with(|count| count.get()), 0);
        assert!(!compare(&[value], &settings(&[(33, 29)])).matched);
        assert!(DIAGNOSTIC_SERIALIZATIONS.with(|count| count.get()) > 0);
    }

    fn settings(fields: &[(u64, u64)]) -> CanonicalValue {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            fields.iter().map(|(id, value)| (*id, value.to_be_bytes())),
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap()
    }

    fn compare(reference: &[CanonicalValue], actual: &CanonicalValue) -> RetainedCaptureComparison {
        compare_retained_captures(
            reference,
            actual,
            ComparisonMode::Literal,
            CaptureComparisonLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn retained_comparison_preserves_fields_values_order_and_correlations() {
        let one = settings(&[(33, 17), (64, 29)]);
        let two = settings(&[(33, 29), (64, 17)]);
        assert!(compare(&[one.clone(), two.clone()], &two).matched);
        for actual in [
            settings(&[(33, 17), (64, 17)]),
            settings(&[(64, 29), (33, 17)]),
            settings(&[(95, 17), (64, 29)]),
            settings(&[(33, 17)]),
        ] {
            let result = compare(&[one.clone(), two.clone()], &actual);
            assert!(!result.matched);
            assert!(!result.differences.is_empty());
        }
    }

    #[test]
    fn retained_comparison_does_not_cross_product_connection_components() {
        let joint = |setting, parameter| {
            let quic = OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::QuicParameter,
                [(4, [parameter])],
                OrderCaptureLimits::default(),
            )
            .unwrap()
            .canonical(OrderCaptureLimits::default())
            .unwrap();
            JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![
                    CapturedSlot {
                        kind: CapturedSlotKind::QuicParameters,
                        value: quic,
                    },
                    CapturedSlot {
                        kind: CapturedSlotKind::Http3Settings,
                        value: settings(&[(33, setting)]),
                    },
                ]
                .into(),
            }
            .canonical(JointCaptureLimits::default())
            .unwrap()
        };
        let reference = [joint(17, 1), joint(29, 2)];
        assert!(compare(&reference, &reference[1]).matched);
        let report = compare(&reference, &joint(17, 2));
        assert!(!report.matched);
        assert!(
            report
                .differences
                .iter()
                .any(|difference| difference.path.starts_with("/slots/QuicParameters/"))
        );
    }

    #[test]
    fn retained_comparison_rejects_invalid_empty_structural_and_over_budget_inputs() {
        let one = settings(&[(33, 17)]);
        compare_retained_captures(
            &[],
            &one,
            ComparisonMode::Literal,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        let mut invalid = one.clone();
        invalid.id.0[0] ^= 1;
        compare_retained_captures(
            &[one.clone(), invalid.clone()],
            &one,
            ComparisonMode::Literal,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        compare_retained_captures(
            std::slice::from_ref(&one),
            &invalid,
            ComparisonMode::Literal,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        let structure = OrderedProtocolCapture::from_canonical(&one, OrderCaptureLimits::default())
            .unwrap()
            .structural(OrderCaptureLimits::default())
            .unwrap();
        compare_retained_captures(
            std::slice::from_ref(&structure),
            &structure,
            ComparisonMode::Literal,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        for limits in [
            CaptureComparisonLimits {
                bytes: one.bytes.len() - 1,
                ..Default::default()
            },
            CaptureComparisonLimits {
                candidates: 0,
                ..Default::default()
            },
            CaptureComparisonLimits {
                work: 0,
                ..Default::default()
            },
            CaptureComparisonLimits {
                differences: 0,
                ..Default::default()
            },
        ] {
            compare_retained_captures(
                std::slice::from_ref(&one),
                &one,
                ComparisonMode::Literal,
                limits,
            )
            .unwrap_err();
        }
    }

    #[test]
    fn retained_comparison_reports_bounded_field_paths_without_hiding_failure() {
        let one = settings(&[(33, 17), (64, 29)]);
        let two = settings(&[(33, 18), (64, 30)]);
        let report = compare_retained_captures(
            &[one],
            &two,
            ComparisonMode::Literal,
            CaptureComparisonLimits {
                differences: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!report.matched);
        assert!(report.truncated);
        assert_eq!(report.differences.len(), 1);
        assert!(report.differences[0].path.starts_with("/fields/0/value/"));
    }
}
