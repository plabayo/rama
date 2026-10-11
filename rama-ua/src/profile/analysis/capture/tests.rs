use super::*;
#[cfg(feature = "tls")]
use crate::profile::{AnalyzedOrderElement, TlsCaptureTransport, TlsCapturedExtension};
use crate::profile::{
    CaptureLevel, CapturedSlot, CapturedSlotKind, DerivedOrderRule, HeaderOccurrence,
    HeaderValueSource, JointCapture, JointCaptureLimits, ObservationId, OrderAnalysisDisposition,
    ProfileBucketLimits, ProfileCaptureCompleteness, RequestBinding,
};
use rama_http::{HeaderName, Version};

fn bucket(values: &[CanonicalValue], domain: CanonicalDomain) -> CountedObservationBucket {
    let mut result = CountedObservationBucket::new(
        domain,
        ValueId([7; 32]),
        [8; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for (index, value) in values.iter().enumerate() {
        result
            .observe(
                ObservationId {
                    run: [9; 16],
                    sequence: index as u64 + 1,
                },
                value,
            )
            .unwrap();
    }
    result
}

fn headers(names: &[&str], marker: u8) -> CanonicalValue {
    HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_11,
        fields: names
            .iter()
            .map(|name| HeaderOccurrence {
                name: HeaderName::from_bytes(name.as_bytes()).unwrap(),
                occurrence: 0,
                sensitive: false,
                representation: None,
                value: if *name == "cookie" {
                    HeaderValueSource::Request(RequestBinding::Cookie)
                } else {
                    HeaderValueSource::Profile(vec![marker].into())
                },
            })
            .collect(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap()
}

#[test]
fn header_analysis_uses_compact_dictionary_and_preserves_value_correlations() {
    let a = headers(&["accept", "cookie", "user-agent"], b'a');
    let b = headers(&["user-agent", "cookie", "accept"], b'b');
    let values: Vec<_> = (0..40)
        .map(|index| if index % 4 == 0 { a.clone() } else { b.clone() })
        .collect();
    let analysis = analyze_capture_bucket(
        &bucket(&values, CanonicalDomain::Headers),
        OrderAnalysisConfig::default(),
    )
    .unwrap();
    assert_eq!(analysis.variants.len(), 2);
    assert_eq!(analysis.counts.total, 40);
    let order = &analysis.orders[0];
    assert!(matches!(
        order.evidence.disposition,
        OrderAnalysisDisposition::Literal
    ));
    assert_eq!(
        order.dictionary,
        vec![
            CaptureOrderElement::Name("accept".into()),
            CaptureOrderElement::Name("cookie".into()),
            CaptureOrderElement::Name("user-agent".into())
        ]
        .into_boxed_slice()
    );
    for variant in &analysis.variants {
        let expected = if variant.value.id == a.id { 10 } else { 30 };
        assert!(
            matches!(variant.weight,AnalyzedOrderWeight::Counted(ObservationWeight::Exact(count)) if count==expected)
        );
        let sequence = order
            .variants
            .iter()
            .find(|order| order.value == variant.value.id)
            .unwrap();
        let decoded =
            HeaderCapture::from_canonical(&variant.value, &HeaderCapturePolicy::default()).unwrap();
        for (field, index) in decoded.fields.iter().zip(&sequence.elements) {
            assert_eq!(
                order.dictionary[usize::from(*index)],
                CaptureOrderElement::Name(field.name.as_str().into())
            );
        }
    }
}

#[cfg(feature = "tls")]
#[test]
fn tls_analysis_uses_the_common_classifier_and_preserves_psk_last() {
    fn permutations(prefix: &mut Vec<u16>, remaining: &mut Vec<u16>, output: &mut Vec<Vec<u16>>) {
        if remaining.is_empty() {
            output.push(prefix.clone());
            return;
        }
        for index in 0..remaining.len() {
            let id = remaining.remove(index);
            prefix.push(id);
            permutations(prefix, remaining, output);
            prefix.pop();
            remaining.insert(index, id);
        }
    }
    let mut permutations_out = Vec::new();
    permutations(
        &mut Vec::new(),
        &mut vec![100, 101, 102, 103, 104],
        &mut permutations_out,
    );
    let values: Vec<_> = permutations_out
        .into_iter()
        .map(|ids| {
            let mut extensions: Vec<_> = ids
                .into_iter()
                .map(|id| TlsCapturedExtension {
                    id,
                    value: TlsCapturedExtensionValue::Literal(Box::default()),
                })
                .collect();
            extensions.push(TlsCapturedExtension {
                id: 41,
                value: TlsCapturedExtensionValue::PreSharedKeys {
                    identities: vec![32].into(),
                    binders: vec![32].into(),
                },
            });
            TlsCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                transport: TlsCaptureTransport::Tcp,
                protocol_version: 0x0303,
                ciphers: vec![0x1301].into(),
                compression: vec![0].into(),
                extensions: extensions.into(),
            }
            .canonical(TlsCaptureLimits::default())
            .unwrap()
        })
        .collect();
    let analysis = analyze_capture_bucket(
        &bucket(&values, CanonicalDomain::Tls),
        OrderAnalysisConfig::default(),
    )
    .unwrap();
    let extensions = analysis
        .orders
        .iter()
        .find(|order| order.path == CaptureOrderPath::TlsExtensions)
        .unwrap();
    let Some(DerivedOrderRule::Shuffled { pinned, .. }) = &extensions.evidence.derived else {
        panic!("TLS shuffle evidence missing")
    };
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].index, 5);
    assert_eq!(
        pinned[0].element,
        AnalyzedOrderElement::Literal {
            id: 41,
            occurrence: 0
        }
    );
    assert_eq!(
        extensions
            .evidence
            .positions
            .iter()
            .map(|position| position.sample_count)
            .sum::<usize>(),
        120 * 6
    );
    assert_eq!(analysis.variants.len(), 120);
}

#[test]
fn joint_analysis_keeps_complete_variants_without_cartesian_products() {
    let policy = JointCaptureLimits::default();
    let make = |names: &[&str], marker| {
        JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: headers(names, marker),
            }]
            .into(),
        }
        .canonical(policy)
        .unwrap()
    };
    let a = make(&["accept", "user-agent"], b'a');
    let b = make(&["user-agent", "accept"], b'b');
    let analysis = analyze_capture_bucket(
        &bucket(&[a.clone(), a.clone(), b.clone()], CanonicalDomain::Joint),
        OrderAnalysisConfig::default(),
    )
    .unwrap();
    assert!(analysis.orders.is_empty());
    assert_eq!(analysis.variants.len(), 2);
    assert!(
        analysis
            .variants
            .iter()
            .all(|variant| variant.value.id == a.id || variant.value.id == b.id)
    );
}

#[test]
fn capture_analysis_rejects_over_budget_inputs_and_identity_domains() {
    let original = bucket(
        &[headers(&["accept", "cookie"], b'a')],
        CanonicalDomain::Headers,
    );
    for config in [
        OrderAnalysisConfig {
            maximum_bytes: original.retained_bytes() - 1,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_elements: 1,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_literals: 0,
            ..OrderAnalysisConfig::default()
        },
    ] {
        analyze_capture_bucket(&original, config).unwrap_err();
    }
    let empty = CountedObservationBucket::new(
        CanonicalDomain::Profile,
        ValueId([0; 32]),
        [0; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    analyze_capture_bucket(&empty, OrderAnalysisConfig::default()).unwrap_err();
}

#[test]
fn sampled_capture_weights_cover_only_the_reservoir_once() {
    let values: Vec<_> = (0..1000)
        .map(|index| {
            OrderedProtocolCapture::capture(
                ProfileCaptureCompleteness::Complete,
                OrderNamespace::Http3Setting,
                [
                    (1, 0_u64.to_be_bytes()),
                    (33 + index * 31, 0_u64.to_be_bytes()),
                ],
                OrderCaptureLimits::default(),
            )
            .unwrap()
            .canonical(OrderCaptureLimits::default())
            .unwrap()
        })
        .collect();
    let analysis = analyze_capture_bucket(
        &bucket(&values, CanonicalDomain::Order),
        OrderAnalysisConfig::default(),
    )
    .unwrap();
    let total: usize = analysis
        .variants
        .iter()
        .map(|variant| match variant.weight {
            AnalyzedOrderWeight::Sample {
                observed,
                sample_size: 256,
                population: 1000,
                history_known: true,
            } => observed,
            _ => panic!("wrong weight domain"),
        })
        .sum();
    assert_eq!(total, 256);
    assert_eq!(analysis.counts.total, 1000);
    assert!(matches!(
        analysis.orders[0].evidence.derived,
        Some(DerivedOrderRule::Relative { .. })
    ));
}

#[test]
fn tls_reserved_range_is_exact_and_does_not_include_lookalikes() {
    for id in [0x0a0a, 0x1a1a, 0xfafa] {
        assert!(CaptureOrderPath::TlsExtensions.reserved(id));
    }
    for id in [0x0a1a, 0x1afa, 0x10000, 0x000a, 0x0a00] {
        assert!(!CaptureOrderPath::TlsExtensions.reserved(id));
    }
    assert!(!CaptureOrderPath::Headers.reserved(0x0a0a));
}

#[test]
fn sampled_capture_weights_preserve_unknown_history() {
    let values: Vec<_> = (0..80)
        .map(|index| headers(&["accept"], 33 + index))
        .collect();
    let original = bucket(&values, CanonicalDomain::Headers);
    let mut snapshot = original.snapshot();
    assert!(snapshot.counts.untracked > 0);
    snapshot.counts.losses.history_known = false;
    let restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Headers,
        ValueId([7; 32]),
        [8; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    let analysis = analyze_capture_bucket(&restored, OrderAnalysisConfig::default()).unwrap();
    assert!(!analysis.variants.is_empty());
    assert!(analysis.variants.iter().all(|variant| matches!(
        variant.weight,
        AnalyzedOrderWeight::Sample {
            history_known: false,
            ..
        }
    )));
}

#[cfg(feature = "tls")]
#[test]
fn absent_tls_extension_path_is_not_an_observed_empty_list() {
    let values: Vec<_> = (0..64)
        .map(|index| {
            let extensions = if index % 2 == 0 {
                vec![TlsCapturedExtension {
                    id: 10,
                    value: TlsCapturedExtensionValue::U16List(vec![29, 23].into()),
                }]
            } else {
                Vec::new()
            };
            TlsCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                transport: TlsCaptureTransport::Tcp,
                protocol_version: 0x0303,
                ciphers: vec![0x1301].into(),
                compression: vec![0].into(),
                extensions: extensions.into(),
            }
            .canonical(TlsCaptureLimits::default())
            .unwrap()
        })
        .collect();
    let analysis = analyze_capture_bucket(
        &bucket(&values, CanonicalDomain::Tls),
        OrderAnalysisConfig::default(),
    )
    .unwrap();
    let path = analysis
        .orders
        .iter()
        .find(|path| path.path == CaptureOrderPath::TlsExtensionValues { extension: 10 })
        .unwrap();
    assert_eq!(path.missing_samples.len(), 32);
    assert!(path.evidence.derived.is_none());
    assert!(matches!(
        path.evidence.disposition,
        OrderAnalysisDisposition::MissingPath
    ));
    assert_eq!(path.variants.len(), 1);
    assert_eq!(path.variants[0].elements.len(), 2);
}
