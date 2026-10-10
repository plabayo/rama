use super::*;
use crate::profile::{
    CanonicalValue, ObservationId, ProfileBucketLimits, ProfileCaptureCompleteness,
    analyze_capture_bucket,
};

fn value(namespace: OrderNamespace, ids: &[u64]) -> CanonicalValue {
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        namespace,
        ids.iter().map(|id| (*id, 0_u64.to_be_bytes())),
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap()
}

fn bucket(orders: &[Vec<u64>], limits: ProfileBucketLimits) -> CountedObservationBucket {
    let mut bucket =
        CountedObservationBucket::new(CanonicalDomain::Order, ValueId([2; 32]), [3; 32], limits)
            .unwrap();
    for (index, ids) in orders.iter().enumerate() {
        bucket
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence: index as u64 + 1,
                },
                &value(OrderNamespace::Http3Setting, ids),
            )
            .unwrap();
    }
    bucket
}

fn analyze(orders: &[Vec<u64>]) -> OrderAnalysis {
    analyze_protocol_order(
        &bucket(orders, ProfileBucketLimits::default()),
        OrderAnalysisConfig::default(),
    )
    .unwrap()
}

#[test]
fn constant_reserved_identifier_stays_literal_with_exact_counts() {
    let result = analyze(&vec![vec![64, 8, 1]; 64]);
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::Literal
    ));
    assert!(result.derived.is_none());
    assert_eq!(result.total, 64);
    assert_eq!(result.observed.len(), 1);
    assert!(matches!(
        result.observed[0].weight,
        AnalyzedOrderWeight::Counted(ObservationWeight::Exact(64))
    ));
    let decoded: Vec<_> = result.observed[0]
        .elements
        .iter()
        .map(|index| result.dictionary[usize::from(*index)].id)
        .collect();
    assert_eq!(decoded, [64, 8, 1]);
}

#[test]
fn reserved_numeric_sorting_is_detected_from_observations() {
    let orders: Vec<_> = (0..64)
        .map(|index| {
            let mut ids = vec![1, 90, 33 + index * 31];
            ids.sort_unstable();
            ids
        })
        .collect();
    let result = analyze(&orders);
    let Some(DerivedOrderRule::Sorted { elements }) = result.derived else {
        panic!("sorted evidence missing")
    };
    assert!(elements.contains(&AnalyzedOrderElement::Reserved { occurrence: 0 }));
    assert!(elements.contains(&AnalyzedOrderElement::Literal {
        id: 90,
        occurrence: 0
    }));
}

#[test]
fn multiple_reserved_placements_remain_joint_and_weighted() {
    let orders: Vec<_> = (0..64)
        .map(|index| {
            let first = 33 + index * 62;
            if index % 4 == 0 {
                vec![first, 8, 1, first + 31]
            } else {
                vec![8, first, first + 31, 1]
            }
        })
        .collect();
    let result = analyze(&orders);
    let Some(DerivedOrderRule::Relative {
        literals,
        placements,
    }) = result.derived
    else {
        panic!("relative evidence missing")
    };
    assert_eq!(
        literals.as_ref(),
        [
            AnalyzedOrderElement::Literal {
                id: 8,
                occurrence: 0
            },
            AnalyzedOrderElement::Literal {
                id: 1,
                occurrence: 0
            }
        ]
    );
    assert_eq!(placements.len(), 2);
    assert_eq!(placements[0].indices.as_ref(), [0, 3]);
    assert_eq!(placements[0].sample_count, 16);
    assert_eq!(placements[1].indices.as_ref(), [1, 2]);
    assert_eq!(placements[1].sample_count, 48);
}

fn permutations() -> Vec<Vec<u64>> {
    fn visit(prefix: &mut Vec<u64>, remaining: &mut Vec<u64>, output: &mut Vec<Vec<u64>>) {
        if remaining.is_empty() {
            let mut order = vec![90];
            order.extend_from_slice(prefix);
            order.push(91);
            output.push(order);
            return;
        }
        for index in 0..remaining.len() {
            let id = remaining.remove(index);
            prefix.push(id);
            visit(prefix, remaining, output);
            prefix.pop();
            remaining.insert(index, id);
        }
    }
    let mut output = Vec::new();
    visit(&mut Vec::new(), &mut vec![1, 2, 3, 4, 5], &mut output);
    output
}

#[test]
fn high_diversity_orders_preserve_both_pinned_ends() {
    let result = analyze(&permutations());
    assert_eq!(result.normalized_distinct_orders, 120);
    let Some(DerivedOrderRule::Shuffled { pinned, .. }) = result.derived else {
        panic!("shuffle evidence missing")
    };
    assert_eq!(pinned.len(), 2);
    assert_eq!(pinned[0].index, 0);
    assert_eq!(
        pinned[0].element,
        AnalyzedOrderElement::Literal {
            id: 90,
            occurrence: 0
        }
    );
    assert_eq!(pinned[1].index, 6);
    assert_eq!(
        pinned[1].element,
        AnalyzedOrderElement::Literal {
            id: 91,
            occurrence: 0
        }
    );
}

#[test]
fn finite_mixture_does_not_become_a_shuffle() {
    let orders: Vec<_> = (0..64)
        .map(|index| {
            if index % 2 == 0 {
                vec![8, 1, 6]
            } else {
                vec![6, 1, 8]
            }
        })
        .collect();
    let result = analyze(&orders);
    assert_eq!(result.normalized_distinct_orders, 2);
    assert!(result.derived.is_none());
    assert_eq!(result.observed.len(), 2);
    assert!(result.observed.iter().all(|order| matches!(
        order.weight,
        AnalyzedOrderWeight::Counted(ObservationWeight::Exact(32))
    )));
}

#[test]
fn incomplete_sample_history_and_retention_never_authorize_generation() {
    let orders = permutations();
    let result = analyze(&orders[..31]);
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::InsufficientSamples
    ));
    assert!(result.derived.is_none());
    let original = bucket(&orders, ProfileBucketLimits::default());
    let mut snapshot = original.snapshot();
    snapshot.counts.losses.history_known = false;
    let restored = CountedObservationBucket::from_snapshot(
        &snapshot,
        CanonicalDomain::Order,
        ValueId([2; 32]),
        [3; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    let result = analyze_protocol_order(&restored, OrderAnalysisConfig::default()).unwrap();
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::UnknownHistory
    ));
    assert!(result.derived.is_none());
    let mut limited = bucket(
        &vec![vec![8, 1]; 32],
        ProfileBucketLimits {
            value_bytes: 100,
            ..ProfileBucketLimits::default()
        },
    );
    limited
        .observe(
            ObservationId {
                run: [1; 16],
                sequence: 33,
            },
            &value(OrderNamespace::Http3Setting, &[1, 2, 3, 4, 5, 6, 7, 8]),
        )
        .unwrap();
    let result = analyze_protocol_order(&limited, OrderAnalysisConfig::default()).unwrap();
    assert_eq!(result.total, 33);
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::IncompleteRetention
    ));
    assert!(result.derived.is_none());
}

#[test]
fn sampled_weights_do_not_double_count_the_tracked_head() {
    let orders: Vec<_> = (0..1000).map(|index| vec![8, 1, 33 + index * 31]).collect();
    let result = analyze(&orders);
    assert_eq!(result.total, 1000);
    assert_eq!(result.retained_samples, 256);
    let mut frequency = 0;
    for observed in &result.observed {
        let AnalyzedOrderWeight::Sample {
            observed,
            sample_size,
            population,
        } = observed.weight
        else {
            panic!("mixed counter and sample weights")
        };
        assert_eq!(sample_size, 256);
        assert_eq!(population, 1000);
        frequency += observed;
    }
    assert_eq!(frequency, 256);
}

#[test]
fn intermittent_presence_retains_disjoint_weighted_modes() {
    let orders: Vec<_> = (0..64)
        .map(|index| {
            if index % 2 == 0 {
                vec![8, 1, 6]
            } else {
                vec![8, 1]
            }
        })
        .collect();
    let result = analyze(&orders);
    let Some(DerivedOrderRule::Mixture { modes }) = result.derived else {
        panic!("presence modes missing")
    };
    assert_eq!(modes.len(), 2);
    for mode in &modes {
        assert_eq!(mode.sample_count, 32);
        assert_eq!(mode.sample_size, 64);
        assert!(mode.evidence.derived.is_none());
    }
}

#[test]
fn duplicate_identifiers_keep_occurrence_identity() {
    let orders: Vec<_> = (0..64)
        .map(|index| vec![8, 33 + index * 31, 8, 1])
        .collect();
    let result = analyze(&orders);
    let Some(DerivedOrderRule::Relative { literals, .. }) = result.derived else {
        panic!("relative evidence missing")
    };
    assert_eq!(
        literals.as_ref(),
        [
            AnalyzedOrderElement::Literal {
                id: 8,
                occurrence: 0
            },
            AnalyzedOrderElement::Literal {
                id: 8,
                occurrence: 1
            },
            AnalyzedOrderElement::Literal {
                id: 1,
                occurrence: 0
            }
        ]
    );
}

#[test]
fn analysis_is_deterministic_after_snapshot_round_trip() {
    let original = bucket(&permutations(), ProfileBucketLimits::default());
    let restored = CountedObservationBucket::from_snapshot(
        &original.snapshot(),
        CanonicalDomain::Order,
        ValueId([2; 32]),
        [3; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(
            &analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap()
        )
        .unwrap(),
        serde_json::to_vec(
            &analyze_protocol_order(&restored, OrderAnalysisConfig::default()).unwrap()
        )
        .unwrap()
    );
}

#[test]
fn analysis_checks_configuration_and_all_resource_budgets() {
    let original = bucket(&permutations(), ProfileBucketLimits::default());
    for config in [
        OrderAnalysisConfig {
            minimum_samples: 0,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            distinct_denominator: 0,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            distinct_numerator: 9,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_samples: 31,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_elements: usize::from(u16::MAX) + 1,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_samples: usize::MAX,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_bytes: original.retained_bytes() - 1,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_samples: 32,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_literals: 1,
            ..OrderAnalysisConfig::default()
        },
        OrderAnalysisConfig {
            maximum_elements: 6,
            ..OrderAnalysisConfig::default()
        },
    ] {
        analyze_protocol_order(&original, config).unwrap_err();
    }
}

#[test]
fn mixed_namespaces_are_rejected() {
    let mut original = bucket(&[vec![8, 1]], ProfileBucketLimits::default());
    original
        .observe(
            ObservationId {
                run: [1; 16],
                sequence: 2,
            },
            &value(OrderNamespace::QuicParameter, &[8, 1]),
        )
        .unwrap();
    analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap_err();
}

#[test]
fn finite_mixture_can_contain_a_generated_mode_without_cross_products() {
    let mut orders = permutations();
    for order in permutations() {
        let mut other = order;
        other.push(92);
        orders.push(other);
    }
    let result = analyze(&orders);
    let Some(DerivedOrderRule::Mixture { modes }) = result.derived else {
        panic!("mixture missing")
    };
    assert_eq!(modes.len(), 2);
    for mode in &modes {
        assert_eq!(mode.sample_count, 120);
        assert_eq!(mode.sample_size, 240);
        assert!(matches!(
            mode.evidence.derived,
            Some(DerivedOrderRule::Shuffled { .. })
        ));
    }
}

#[test]
fn too_many_presence_modes_stay_literal() {
    let orders: Vec<_> = (0..64).map(|index| vec![100 + index, 1]).collect();
    let result = analyze(&orders);
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::UnstableElements
    ));
    assert!(result.derived.is_none());
}

#[test]
fn constant_quic_reserved_parameter_is_preserved_beside_varying_grease() {
    let mut original = CountedObservationBucket::new(
        CanonicalDomain::Order,
        ValueId([2; 32]),
        [3; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for index in 0..64 {
        let value = value(
            OrderNamespace::QuicParameter,
            &[0xff02de1a, 27 + index * 31, 1],
        );
        original
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence: index + 1,
                },
                &value,
            )
            .unwrap();
    }
    let result = analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap();
    let Some(DerivedOrderRule::Relative { literals, .. }) = result.derived else {
        panic!("relative evidence missing")
    };
    assert!(literals.contains(&AnalyzedOrderElement::Literal {
        id: 0xff02de1a,
        occurrence: 0
    }));
    assert_eq!(literals.len(), 2);
}

#[test]
fn mixture_membership_uses_the_shared_sample_axis_without_overlap() {
    let mut orders = permutations();
    for order in permutations() {
        let mut extra = order;
        extra.push(92);
        orders.push(extra);
    }
    let original = bucket(&orders, ProfileBucketLimits::default());
    let result = analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap();
    let Some(DerivedOrderRule::Mixture { modes }) = result.derived else {
        panic!("mixture missing")
    };
    let snapshot = original.snapshot();
    let mut covered = BTreeSet::new();
    for mode in &modes {
        assert_eq!(mode.sample_indices.len(), mode.sample_count);
        let has_extra = mode.elements.contains(&AnalyzedOrderElement::Literal {
            id: 92,
            occurrence: 0,
        });
        for &index in &mode.sample_indices {
            assert!(covered.insert(index));
            let value = snapshot
                .values
                .iter()
                .find(|value| value.id == result.sample_values[index])
                .unwrap();
            let capture =
                OrderedProtocolCapture::from_canonical(value, OrderCaptureLimits::default())
                    .unwrap();
            assert_eq!(capture.fields.iter().any(|field| field.id == 92), has_extra);
        }
    }
    assert_eq!(covered.len(), 240);
}

#[test]
fn reserved_version_moves_by_insertion_without_reordering_semantic_versions() {
    let mut original = CountedObservationBucket::new(
        CanonicalDomain::Order,
        ValueId([2; 32]),
        [3; 32],
        ProfileBucketLimits::default(),
    )
    .unwrap();
    for index in 0..64_u64 {
        let grease = 0x0a0a0a0a + ((index % 16) * 0x10101010);
        let mut ids = vec![1, 0x6b3343cf];
        ids.insert((index % 3) as usize, grease);
        let value = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicVersion,
            ids.into_iter().map(|id| (id, [])),
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        original
            .observe(
                ObservationId {
                    run: [1; 16],
                    sequence: index + 1,
                },
                &value,
            )
            .unwrap();
    }
    let result = analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap();
    let Some(DerivedOrderRule::Relative {
        literals,
        placements,
    }) = result.derived
    else {
        panic!("insertion evidence missing")
    };
    assert_eq!(
        literals.as_ref(),
        [
            AnalyzedOrderElement::Literal {
                id: 1,
                occurrence: 0
            },
            AnalyzedOrderElement::Literal {
                id: 0x6b3343cf,
                occurrence: 0
            }
        ]
    );
    assert_eq!(placements.len(), 3);
    assert_eq!(
        placements
            .iter()
            .map(|placement| placement.sample_count)
            .sum::<usize>(),
        64
    );
}

#[test]
fn held_out_permutations_preserve_learned_elements_and_pins() {
    let orders = permutations();
    let result = analyze(&orders[..96]);
    let Some(DerivedOrderRule::Shuffled { elements, pinned }) = result.derived else {
        panic!("shuffle evidence missing")
    };
    for held_out in &orders[96..] {
        let actual: Vec<_> = held_out
            .iter()
            .map(|id| AnalyzedOrderElement::Literal {
                id: *id,
                occurrence: 0,
            })
            .collect();
        for pin in &pinned {
            assert_eq!(actual[pin.index], pin.element);
        }
        let mut sorted = actual;
        sorted.sort_unstable();
        assert_eq!(sorted.as_slice(), elements.as_ref());
    }
}

#[test]
fn recorded_losses_are_excluded_from_the_sampling_population() {
    let limits = ProfileBucketLimits {
        literal_values: 1,
        value_bytes: 100,
        ..ProfileBucketLimits::default()
    };
    let mut original = bucket(&[vec![1, 8], vec![8, 1]], limits);
    original
        .observe(
            ObservationId {
                run: [1; 16],
                sequence: 3,
            },
            &value(OrderNamespace::Http3Setting, &[1, 2, 3, 4, 5, 6, 7, 8]),
        )
        .unwrap();
    let result = analyze_protocol_order(&original, OrderAnalysisConfig::default()).unwrap();
    assert_eq!(result.total, 3);
    assert!(matches!(
        result.disposition,
        OrderAnalysisDisposition::IncompleteRetention
    ));
    assert!(result.observed.iter().all(|order| matches!(
        order.weight,
        AnalyzedOrderWeight::Sample {
            population: 2,
            sample_size: 2,
            ..
        }
    )));
    let common = analyze_capture_bucket(&original, OrderAnalysisConfig::default()).unwrap();
    assert!(common.variants.iter().all(|variant| matches!(
        variant.weight,
        AnalyzedOrderWeight::Sample {
            population: 2,
            sample_size: 2,
            ..
        }
    )));
}
