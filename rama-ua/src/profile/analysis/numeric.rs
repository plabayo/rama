use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::profile::analysis::{
    capture::AnalyzedCaptureVariant,
    order::{AnalyzedOrderWeight, OrderAnalysisConfig},
};
use crate::profile::{
    capture::quic::{QuicFlightCapture, QuicFlightCaptureLimits},
    evidence::counts::ObservationWeight,
    format::canonical::{CanonicalDomain, ProfileDataError, ValueId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
/// A scalar field extracted from a complete captured protocol variant.
///
/// Paths identify diagnostics only. Replay selects a complete variant and does
/// not draw these scalar values independently.
pub enum CaptureNumericPath {
    /// Byte length of the destination connection ID in the first QUIC packet.
    QuicDestinationIdLength,
    /// Byte length of the source connection ID in the first QUIC packet.
    QuicSourceIdLength,
    /// Byte length of the token in the first QUIC Initial packet.
    QuicTokenLength,
    /// Decoded packet number of the first observed QUIC packet.
    QuicFirstPacketNumber,
    /// Number of bytes used to encode the first QUIC packet number.
    QuicPacketNumberWidth,
    /// UDP payload length of the datagram at `index` in the first flight.
    QuicDatagramLength { index: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// One observed value and the complete variants in which it occurred.
pub struct NumericDistributionValue {
    /// Absence is a distinct observation, not a zero-valued sample.
    pub value: Option<u64>,
    /// Count or reservoir weight inherited from the complete variants.
    pub weight: AnalyzedOrderWeight,
    /// Complete capture variants that contain this value at the selected path.
    pub variants: Box<[ValueId]>,
}

/// A marginal diagnostic over complete variants. Independent draws from different
/// distributions are not authorized: `variants` retains their joint membership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureNumericDistribution {
    /// Scalar field summarized by this diagnostic.
    pub path: CaptureNumericPath,
    /// Observed values with their weights and correlated complete variants.
    pub values: Box<[NumericDistributionValue]>,
}

fn add_weight(
    left: &mut AnalyzedOrderWeight,
    right: &AnalyzedOrderWeight,
) -> Result<(), ProfileDataError> {
    let count = |left: u64, right: u64| {
        left.checked_add(right)
            .ok_or(ProfileDataError::CounterOverflow)
    };
    match (left, right) {
        (
            AnalyzedOrderWeight::Counted(ObservationWeight::Exact(left)),
            AnalyzedOrderWeight::Counted(ObservationWeight::Exact(right)),
        )
        | (
            AnalyzedOrderWeight::Counted(ObservationWeight::UnknownHistory {
                observed: left,
                unassigned: 0,
            }),
            AnalyzedOrderWeight::Counted(ObservationWeight::UnknownHistory {
                observed: right,
                unassigned: 0,
            }),
        ) => *left = count(*left, *right)?,
        (
            AnalyzedOrderWeight::Sample {
                observed: left,
                sample_size: left_size,
                population: left_population,
                history_known: left_history,
            },
            AnalyzedOrderWeight::Sample {
                observed: right,
                sample_size: right_size,
                population: right_population,
                history_known: right_history,
            },
        ) if left_size == right_size
            && left_population == right_population
            && left_history == right_history =>
        {
            *left = left
                .checked_add(*right)
                .ok_or(ProfileDataError::CounterOverflow)?
        }
        _ => return Err(ProfileDataError::Invalid("mixed numeric weight domains")),
    }
    Ok(())
}

pub(super) fn analyze_numeric_variants(
    variants: &[AnalyzedCaptureVariant],
    domain: CanonicalDomain,
    config: OrderAnalysisConfig,
) -> Result<Box<[CaptureNumericDistribution]>, ProfileDataError> {
    if domain != CanonicalDomain::QuicFlight {
        return Ok(Box::default());
    }
    let mut decoded = Vec::new();
    for variant in variants {
        let capture = QuicFlightCapture::from_canonical(
            &variant.value,
            QuicFlightCaptureLimits {
                bytes: config.maximum_bytes,
                ..QuicFlightCaptureLimits::default()
            },
        )?;
        let flight = capture.flight;
        let mut values = BTreeMap::from([
            (
                CaptureNumericPath::QuicDestinationIdLength,
                flight.dcid_len as u64,
            ),
            (
                CaptureNumericPath::QuicSourceIdLength,
                flight.scid_len as u64,
            ),
            (CaptureNumericPath::QuicTokenLength, flight.token_len as u64),
            (
                CaptureNumericPath::QuicFirstPacketNumber,
                flight.first_packet_number,
            ),
            (
                CaptureNumericPath::QuicPacketNumberWidth,
                u64::from(flight.packet_number_len),
            ),
        ]);
        for (index, length) in flight.datagram_sizes.into_iter().enumerate() {
            values.insert(
                CaptureNumericPath::QuicDatagramLength { index },
                length as u64,
            );
        }
        decoded.push(values);
    }
    let paths: BTreeSet<_> = decoded
        .iter()
        .flat_map(|values| values.keys().copied())
        .collect();
    if paths.len() > config.maximum_elements {
        return Err(ProfileDataError::LimitExceeded("numeric analysis paths"));
    }
    let mut distributions = Vec::new();
    for path in paths {
        let mut frequencies = BTreeMap::<Option<u64>, (AnalyzedOrderWeight, Vec<ValueId>)>::new();
        for (variant, decoded) in variants.iter().zip(&decoded) {
            let value = decoded.get(&path).copied();
            match frequencies.get_mut(&value) {
                Some(frequency) => {
                    add_weight(&mut frequency.0, &variant.weight)?;
                    frequency.1.push(variant.value.id);
                }
                None => {
                    frequencies.insert(value, (variant.weight.clone(), vec![variant.value.id]));
                }
            }
        }
        distributions.push(CaptureNumericDistribution {
            path,
            values: frequencies
                .into_iter()
                .map(|(value, (weight, variants))| NumericDistributionValue {
                    value,
                    weight,
                    variants: variants.into(),
                })
                .collect(),
        });
    }
    Ok(distributions.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        analysis::capture::analyze_capture_bucket,
        capture::completeness::ProfileCaptureCompleteness,
        evidence::{
            bucket::{CountedObservationBucket, ProfileBucketLimits},
            ingestion::ObservationId,
        },
    };
    use rama_quic_proto::{
        Version,
        capture::{FirstFlight, ObservedFrame},
        profile::PaddingPlacement,
    };

    #[test]
    fn numeric_distributions_preserve_counts_and_correlated_variant_membership() {
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::QuicFlight,
            ValueId([1; 32]),
            [2; 32],
            ProfileBucketLimits::default(),
        )
        .unwrap();
        for index in 0..64 {
            let rare = index % 4 == 0;
            let number = if rare { 7 } else { 3 };
            let capture = QuicFlightCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                flight: FirstFlight {
                    datagram_sizes: vec![1200],
                    trailing_bytes: vec![0],
                    version: Version::V1,
                    dcid_len: if rare { 20 } else { 8 },
                    scid_len: 0,
                    token_len: 0,
                    first_packet_number: number,
                    packet_number_len: 2,

                    packet_number_lengths: vec![2],
                    frames: vec![vec![
                        ObservedFrame::Crypto {
                            offset: 0,
                            len: 100,
                        },
                        ObservedFrame::Padding { len: 1000 },
                    ]],
                    padding: PaddingPlacement::Frames,
                    coalesced: false,
                    parameters: vec![],
                    chosen_version: None,
                    available_versions: vec![],
                    packet_numbers: vec![number],
                    complete: true,
                },
            }
            .canonical(QuicFlightCaptureLimits::default())
            .unwrap();
            bucket
                .observe(
                    ObservationId {
                        run: [3; 16],
                        sequence: index + 1,
                    },
                    &capture,
                )
                .unwrap();
        }
        let analysis = analyze_capture_bucket(&bucket, OrderAnalysisConfig::default()).unwrap();
        let ids = analysis
            .numeric
            .iter()
            .find(|value| value.path == CaptureNumericPath::QuicDestinationIdLength)
            .unwrap();
        let numbers = analysis
            .numeric
            .iter()
            .find(|value| value.path == CaptureNumericPath::QuicFirstPacketNumber)
            .unwrap();
        assert_eq!(ids.values.len(), 2);
        assert_eq!(numbers.values.len(), 2);
        for (id, number) in ids.values.iter().zip(&numbers.values) {
            assert_eq!(id.variants, number.variants);
            let expected = if id.value == Some(8) { 48 } else { 16 };
            assert!(
                matches!(id.weight,AnalyzedOrderWeight::Counted(ObservationWeight::Exact(count)) if count==expected)
            );
        }
        assert_eq!(ids.values[0].value, Some(8));
        assert_eq!(ids.values[1].value, Some(20));
        assert_eq!(numbers.values[0].value, Some(3));
        assert_eq!(numbers.values[1].value, Some(7));
    }

    #[test]
    fn numeric_weights_reject_mixed_domains_and_overflow() {
        let mut count = AnalyzedOrderWeight::Counted(ObservationWeight::Exact(u64::MAX));
        add_weight(
            &mut count,
            &AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        )
        .unwrap_err();
        let mut count = AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1));
        add_weight(
            &mut count,
            &AnalyzedOrderWeight::Sample {
                observed: 1,
                sample_size: 2,
                population: 3,
                history_known: true,
            },
        )
        .unwrap_err();
        let mut count = AnalyzedOrderWeight::Sample {
            observed: 1,
            sample_size: 2,
            population: 3,
            history_known: true,
        };
        add_weight(
            &mut count,
            &AnalyzedOrderWeight::Sample {
                observed: 1,
                sample_size: 2,
                population: 4,
                history_known: true,
            },
        )
        .unwrap_err();
    }
}
