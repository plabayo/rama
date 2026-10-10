//! One analysis entrypoint for stored and directly imported capture buckets.

use std::collections::{BTreeMap, BTreeSet};

use rama_http::proto::h2::PseudoHeader;
use serde::Serialize;

use super::{
    AnalyzedOrderWeight, CaptureNumericDistribution, OrderAnalysisConfig, OrderRuleEvidence,
    numeric::analyze_numeric_variants,
    order::{analyze_identifiers, sampling_population},
};
use crate::profile::{
    CanonicalDomain, CanonicalValue, CountedObservationBucket, CounterSnapshot, H2Capture,
    H2CaptureLimits, H2CapturedFrame, HeaderCapture, HeaderCapturePolicy, ObservationWeight,
    OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProfileDataError,
    PseudoHeaderCapture, ValueId,
};
#[cfg(feature = "tls")]
use crate::profile::{TlsCapture, TlsCaptureLimits, TlsCapturedExtensionValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CaptureOrderPath {
    Headers,
    PseudoHeaders,
    TlsExtensions,
    TlsCiphers,
    TlsExtensionValues { extension: u16 },
    Http2Settings { frame: usize },
    QuicParameters,
    Http3Settings,
    QuicVersions,
}

impl CaptureOrderPath {
    fn reserved(self, id: u64) -> bool {
        match self {
            Self::TlsExtensions | Self::TlsCiphers | Self::TlsExtensionValues { .. } => {
                id <= u64::from(u16::MAX) && id & 0x0f0f == 0x0a0a && (id >> 8) == (id & 0xff)
            }
            Self::QuicParameters => OrderNamespace::QuicParameter.reserved_candidate(id),
            Self::Http3Settings => OrderNamespace::Http3Setting.reserved_candidate(id),
            Self::QuicVersions => OrderNamespace::QuicVersion.reserved_candidate(id),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CaptureOrderElement {
    Number(u64),
    Name(Box<str>),
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureOrderVariant {
    /// References the complete capture variant and its weight.
    pub value: ValueId,
    pub elements: Box<[u16]>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureOrderAnalysis {
    pub path: CaptureOrderPath,
    pub dictionary: Box<[CaptureOrderElement]>,
    pub variants: Box<[CaptureOrderVariant]>,
    /// Rules for named elements use dictionary offsets; numeric elements use wire IDs.
    pub evidence: OrderRuleEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedCaptureVariant {
    pub value: CanonicalValue,
    pub weight: AnalyzedOrderWeight,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountedCaptureAnalysis {
    pub classifier_revision: u16,
    pub domain: CanonicalDomain,
    pub scope: ValueId,
    pub counts: CounterSnapshot,
    pub retained_samples: usize,
    pub sample_values: Box<[ValueId]>,
    /// Complete values preserve correlations. An order rule alone is not a replay profile.
    pub variants: Box<[AnalyzedCaptureVariant]>,
    pub orders: Box<[CaptureOrderAnalysis]>,
    pub numeric: Box<[CaptureNumericDistribution]>,
}

type Sequences = BTreeMap<CaptureOrderPath, Vec<CaptureOrderElement>>;

fn numbers(ids: impl IntoIterator<Item = u64>) -> Vec<CaptureOrderElement> {
    ids.into_iter().map(CaptureOrderElement::Number).collect()
}

fn sequences(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    config: OrderAnalysisConfig,
) -> Result<Sequences, ProfileDataError> {
    let mut output = BTreeMap::new();
    match domain {
        CanonicalDomain::Headers => {
            let capture = HeaderCapture::from_canonical(
                value,
                &HeaderCapturePolicy {
                    fields: config.maximum_elements,
                    bytes: config.maximum_bytes,
                    overrides: Box::default(),
                },
            )?;
            output.insert(
                CaptureOrderPath::Headers,
                capture
                    .fields
                    .iter()
                    .map(|field| CaptureOrderElement::Name(field.name.as_str().into()))
                    .collect(),
            );
        }
        CanonicalDomain::PseudoHeaders => {
            let capture = PseudoHeaderCapture::from_canonical(value, config.maximum_bytes)?;
            let mut ids = Vec::new();
            for field in &capture.fields {
                ids.push(match field.name {
                    PseudoHeader::Method => 0,
                    PseudoHeader::Scheme => 1,
                    PseudoHeader::Authority => 2,
                    PseudoHeader::Path => 3,
                    PseudoHeader::Protocol => 4,
                    PseudoHeader::Status => {
                        return Err(ProfileDataError::Invalid(
                            "response pseudo-header in request analysis",
                        ));
                    }
                });
            }
            output.insert(CaptureOrderPath::PseudoHeaders, numbers(ids));
        }
        CanonicalDomain::Order => {
            let capture = OrderedProtocolCapture::from_canonical(
                value,
                OrderCaptureLimits {
                    elements: config.maximum_elements,
                    bytes: config.maximum_bytes,
                },
            )?;
            let path = match capture.namespace {
                OrderNamespace::QuicParameter => CaptureOrderPath::QuicParameters,
                OrderNamespace::Http3Setting => CaptureOrderPath::Http3Settings,
                OrderNamespace::QuicVersion => CaptureOrderPath::QuicVersions,
            };
            output.insert(path, numbers(capture.fields.iter().map(|field| field.id)));
        }
        CanonicalDomain::H2 => {
            let capture = H2Capture::from_canonical(
                value,
                H2CaptureLimits {
                    frames: config.maximum_elements,
                    settings: config.maximum_elements,
                    bytes: config.maximum_bytes,
                },
            )?;
            for (frame, value) in capture.frames.iter().enumerate() {
                if let H2CapturedFrame::Settings {
                    ack: false,
                    entries,
                } = value
                {
                    output.insert(
                        CaptureOrderPath::Http2Settings { frame },
                        numbers(entries.iter().map(|field| u64::from(field.id))),
                    );
                }
            }
        }

        #[cfg(feature = "tls")]
        CanonicalDomain::Tls => {
            let capture = TlsCapture::from_canonical(
                value,
                TlsCaptureLimits {
                    elements: config.maximum_elements,
                    bytes: config.maximum_bytes,
                },
            )?;
            output.insert(
                CaptureOrderPath::TlsCiphers,
                numbers(capture.ciphers.iter().copied().map(u64::from)),
            );
            output.insert(
                CaptureOrderPath::TlsExtensions,
                numbers(
                    capture
                        .extensions
                        .iter()
                        .map(|extension| u64::from(extension.id)),
                ),
            );
            for extension in &capture.extensions {
                let ids = match &extension.value {
                    TlsCapturedExtensionValue::U16List(ids) => {
                        Some(numbers(ids.iter().copied().map(u64::from)))
                    }
                    TlsCapturedExtensionValue::KeyShares(shares) => {
                        Some(numbers(shares.iter().map(|share| u64::from(share.group))))
                    }
                    _ => None,
                };
                if let Some(ids) = ids {
                    output.insert(
                        CaptureOrderPath::TlsExtensionValues {
                            extension: extension.id,
                        },
                        ids,
                    );
                }
            }
        }
        _ => (),
    }
    if output.len() > config.maximum_elements
        || output
            .values()
            .any(|sequence| sequence.len() > config.maximum_elements)
    {
        return Err(ProfileDataError::LimitExceeded(
            "capture analysis sequences",
        ));
    }
    Ok(output)
}

/// Analyze one retained structural scope. Joint captures remain complete weighted
/// variants; independently analyzed leaf orders do not create cross-slot combinations.
pub fn analyze_capture_bucket(
    bucket: &CountedObservationBucket,
    config: OrderAnalysisConfig,
) -> Result<CountedCaptureAnalysis, ProfileDataError> {
    config.validate()?;
    if bucket.retained_bytes() > config.maximum_bytes {
        return Err(ProfileDataError::LimitExceeded("capture analysis bytes"));
    }
    let snapshot = bucket.snapshot();
    if !matches!(
        snapshot.domain,
        CanonicalDomain::Headers
            | CanonicalDomain::Order
            | CanonicalDomain::Joint
            | CanonicalDomain::Tls
            | CanonicalDomain::H2
            | CanonicalDomain::PseudoHeaders
            | CanonicalDomain::RuntimeMetadata
            | CanonicalDomain::QuicFlight
            | CanonicalDomain::H3Sequence
            | CanonicalDomain::LegacyField
    ) {
        return Err(ProfileDataError::Invalid("capture analysis domain"));
    }
    if snapshot.samples.len() > config.maximum_samples
        || snapshot.counts.values.len() > config.maximum_literals
        || snapshot.values.len() > config.maximum_samples + config.maximum_literals
    {
        return Err(ProfileDataError::LimitExceeded("capture analysis samples"));
    }
    let mut frequencies = BTreeMap::<ValueId, usize>::new();
    for sample in &snapshot.samples {
        *frequencies.entry(sample.value).or_default() += 1;
    }
    let mut variants = Vec::new();
    let mut decoded = BTreeMap::new();
    for value in snapshot.values {
        value.validate_content(snapshot.domain, config.maximum_bytes)?;
        let weight = if snapshot.counts.untracked == 0 {
            let count = snapshot
                .counts
                .values
                .iter()
                .find(|entry| entry.value == value.id)
                .ok_or(ProfileDataError::Invalid("missing capture count"))?
                .count;
            AnalyzedOrderWeight::Counted(if snapshot.counts.losses.history_known {
                ObservationWeight::Exact(count)
            } else {
                ObservationWeight::UnknownHistory {
                    observed: count,
                    unassigned: 0,
                }
            })
        } else if let Some(count) = frequencies.get(&value.id) {
            AnalyzedOrderWeight::Sample {
                observed: *count,
                sample_size: snapshot.samples.len(),
                population: sampling_population(&snapshot.counts)?,
            }
        } else {
            continue;
        };
        decoded.insert(value.id, sequences(&value, snapshot.domain, config)?);
        variants.push(AnalyzedCaptureVariant { value, weight });
    }
    let paths: BTreeSet<_> = decoded
        .values()
        .flat_map(|sequences| sequences.keys().copied())
        .collect();
    if paths.len() > config.maximum_elements {
        return Err(ProfileDataError::LimitExceeded("capture analysis paths"));
    }
    let mut orders = Vec::new();
    for path in paths {
        let dictionary: BTreeSet<_> = decoded
            .values()
            .filter_map(|sequences| sequences.get(&path))
            .flatten()
            .cloned()
            .collect();
        if dictionary.len() > usize::from(u16::MAX) {
            return Err(ProfileDataError::LimitExceeded(
                "capture analysis dictionary",
            ));
        }
        let dictionary: Vec<_> = dictionary.into_iter().collect();
        let mut order_variants = Vec::new();
        let mut order_samples = BTreeMap::new();
        for (&value, sequences) in &decoded {
            let Some(sequence) = sequences.get(&path) else {
                continue;
            };
            let indices = sequence
                .iter()
                .map(|element| {
                    dictionary
                        .binary_search(element)
                        .map(|index| index as u16)
                        .map_err(|_error| ProfileDataError::Invalid("missing capture element"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let ids = sequence
                .iter()
                .zip(&indices)
                .map(|(element, index)| match element {
                    CaptureOrderElement::Number(id) => *id,
                    CaptureOrderElement::Name(_) => u64::from(*index),
                })
                .collect();
            order_samples.insert(value, ids);
            order_variants.push(CaptureOrderVariant {
                value,
                elements: indices.into(),
            });
        }
        let samples = snapshot
            .samples
            .iter()
            .map(|sample| {
                order_samples
                    .get(&sample.value)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let evidence = analyze_identifiers(&samples, &snapshot.counts.losses, config, |id| {
            path.reserved(id)
        })?;
        orders.push(CaptureOrderAnalysis {
            path,
            dictionary: dictionary.into(),
            variants: order_variants.into(),
            evidence,
        });
    }
    let numeric = analyze_numeric_variants(&variants, snapshot.domain, config)?;
    Ok(CountedCaptureAnalysis {
        numeric,
        classifier_revision: 1,
        domain: snapshot.domain,
        scope: snapshot.scope,
        counts: snapshot.counts,
        retained_samples: snapshot.samples.len(),
        sample_values: snapshot.samples.iter().map(|sample| sample.value).collect(),
        variants: variants.into(),
        orders: orders.into(),
    })
}

#[cfg(test)]
mod tests;
