//! Literal membership and bounded field diagnostics for complete captures.
//!
//! This is the conservative comparison boundary: a complete retained variant
//! must match. Order-only rules never authorize mixing fields from different
//! variants. A mismatch can still be valid under an unimplemented generator;
//! this API does not claim population or distribution equivalence.

use super::*;
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
            work: 16 * 1024 * 1024,
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
    pub literal_match: bool,
    pub observed: ValueId,
    /// The matching variant, or the first retained variant used for diagnostics.
    pub reference: ValueId,
    pub differences: Vec<CaptureFieldDifference>,
    pub truncated: bool,
}

/// Compare an observation with whole retained tuples, then diagnose the first
/// reference if no tuple matches. Counts and derived rules are not compared.
/// Both canonical bytes and digest are validated before matching.
pub fn compare_retained_captures(
    reference: &[CanonicalValue],
    observed: &CanonicalValue,
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
    let domain = observed.validated_domain(limits.bytes)?;
    let actual = decode(observed, domain, limits.bytes)?;
    let mut work = limits
        .work
        .checked_sub(observed.bytes.len())
        .ok_or(ProfileDataError::LimitExceeded("comparison work"))?;
    let mut matched = None;
    for candidate in reference {
        work = work
            .checked_sub(candidate.bytes.len())
            .and_then(|work| work.checked_sub(observed.bytes.len()))
            .ok_or(ProfileDataError::LimitExceeded("comparison work"))?;
        if candidate.validated_domain(limits.bytes)? != domain {
            return Err(ProfileDataError::Invalid("comparison capture domain"));
        }
        if candidate.bytes == observed.bytes {
            matched = Some(candidate.id);
        }
    }
    if let Some(reference) = matched {
        return Ok(RetainedCaptureComparison {
            work_units: limits.work - work,
            literal_match: true,
            observed: observed.id,
            reference,
            differences: Vec::new(),
            truncated: false,
        });
    }
    let expected = decode(&reference[0], domain, limits.bytes)?;
    let mut report = RetainedCaptureComparison {
        work_units: limits.work - work,
        literal_match: false,
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
    serde_json::to_value(value)
        .map_err(|_error| ProfileDataError::Invalid("comparison decoded value"))
}

fn decode(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    bytes: usize,
) -> Result<Value, ProfileDataError> {
    match domain {
        CanonicalDomain::Headers => json(HeaderCapture::from_canonical(
            value,
            &HeaderCapturePolicy {
                bytes,
                fields: bytes,
                overrides: Box::default(),
            },
        )?),
        CanonicalDomain::Order => json(OrderedProtocolCapture::from_canonical(
            value,
            OrderCaptureLimits {
                bytes,
                elements: bytes,
            },
        )?),
        CanonicalDomain::H2 => json(H2Capture::from_canonical(
            value,
            H2CaptureLimits {
                bytes,
                frames: bytes,
                settings: bytes,
            },
        )?),
        CanonicalDomain::PseudoHeaders => json(PseudoHeaderCapture::from_canonical(value, bytes)?),
        CanonicalDomain::RuntimeMetadata => {
            json(RuntimeProfileCapture::from_canonical(value, bytes)?)
        }
        #[cfg(feature = "tls")]
        CanonicalDomain::Tls => json(TlsCapture::from_canonical(
            value,
            TlsCaptureLimits {
                bytes,
                elements: bytes,
            },
        )?),
        CanonicalDomain::QuicFlight => json(QuicFlightCapture::from_canonical(
            value,
            QuicFlightCaptureLimits {
                bytes,
                ..QuicFlightCaptureLimits::default()
            },
        )?),
        CanonicalDomain::H3Sequence => json(H3ClientSequenceCapture::from_canonical(
            value,
            H3SequenceCaptureLimits {
                bytes,
                ..H3SequenceCaptureLimits::default()
            },
        )?),
        CanonicalDomain::Joint => {
            let joint = JointCapture::from_canonical(
                value,
                JointCaptureLimits {
                    value_bytes: bytes,
                    ..JointCaptureLimits::default()
                },
            )?;
            let mut slots = serde_json::Map::new();
            for slot in joint.slots.iter() {
                slots.insert(
                    format!("{:?}", slot.kind),
                    decode(&slot.value, slot.value.validated_domain(bytes)?, bytes)?,
                );
            }
            Ok(
                serde_json::json!({"level": joint.level, "completeness": joint.completeness, "slots": slots}),
            )
        }
        _ => Err(ProfileDataError::Unsupported("comparison capture domain")),
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
        compare_retained_captures(reference, actual, CaptureComparisonLimits::default()).unwrap()
    }
    #[test]
    fn retained_comparison_preserves_fields_values_order_and_correlations() {
        let one = settings(&[(33, 17), (64, 29)]);
        let two = settings(&[(33, 29), (64, 17)]);
        assert!(compare(&[one.clone(), two.clone()], &two).literal_match);
        for actual in [
            settings(&[(33, 17), (64, 17)]),
            settings(&[(64, 29), (33, 17)]),
            settings(&[(95, 17), (64, 29)]),
            settings(&[(33, 17)]),
        ] {
            let result = compare(&[one.clone(), two.clone()], &actual);
            assert!(!result.literal_match);
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
        assert!(compare(&reference, &reference[1]).literal_match);
        let report = compare(&reference, &joint(17, 2));
        assert!(!report.literal_match);
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
        compare_retained_captures(&[], &one, CaptureComparisonLimits::default()).unwrap_err();
        let mut invalid = one.clone();
        invalid.id.0[0] ^= 1;
        compare_retained_captures(
            &[one.clone(), invalid.clone()],
            &one,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        compare_retained_captures(
            std::slice::from_ref(&one),
            &invalid,
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
            compare_retained_captures(std::slice::from_ref(&one), &one, limits).unwrap_err();
        }
    }
    #[test]
    fn retained_comparison_reports_bounded_field_paths_without_hiding_failure() {
        let one = settings(&[(33, 17), (64, 29)]);
        let two = settings(&[(33, 18), (64, 30)]);
        let report = compare_retained_captures(
            &[one],
            &two,
            CaptureComparisonLimits {
                differences: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!report.literal_match);
        assert!(report.truncated);
        assert_eq!(report.differences.len(), 1);
        assert!(report.differences[0].path.starts_with("/fields/0/value/"));
    }
}
