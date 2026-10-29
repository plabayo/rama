//! A separate structural identity groups header permutations without losing raw order.

use std::cmp::Ordering;

use ahash::HashMap;
use rama_core::bytes::Bytes;
use rama_http::{HeaderName, Version, header::COOKIE};
use sha2::{Digest as _, Sha256};

use crate::profile::{
    capture::headers::{
        HeaderCapture, HeaderCapturePolicy, HeaderValueSource, RequestBinding,
        header_capture_binding, header_value_class,
    },
    format::canonical::{
        CanonicalReader, CanonicalValue, CanonicalWriter, HEADER_STRUCTURE_DOMAIN,
        ProfileDataError, ValueId,
    },
};

impl HeaderCapture {
    /// Order, occurrence ordinals and compression state remain in the complete capture.
    /// Structural keys retain names, value ownership and multiplicity. Literal values
    /// are retained except for per-request or per-device value classes, and H2/H3
    /// cookie fields count once since their split follows the caller's cookie jar.
    pub fn structural(
        &self,
        policy: &HeaderCapturePolicy,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.encode_structure(policy, true)
    }

    /// The structure as stored before volatile values were classified.
    #[cfg(test)]
    pub(in crate::profile) fn legacy_structural(
        &self,
        policy: &HeaderCapturePolicy,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.encode_structure(policy, false)
    }

    // Older stored keys retain volatile literals; validation accepts both encodings.
    fn encode_structure(
        &self,
        policy: &HeaderCapturePolicy,
        classify_values: bool,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(policy)?;
        let multiplexed = matches!(self.version, Version::HTTP_2 | Version::HTTP_3);
        let mut fields = self.fields.to_vec();
        if classify_values {
            let mut cookie_seen = false;
            fields.retain(|field| {
                let cookie = multiplexed
                    && field.name == COOKIE
                    && matches!(
                        field.value,
                        HeaderValueSource::Request(RequestBinding::Cookie)
                    );
                let keep = !(cookie && cookie_seen);
                cookie_seen |= cookie;
                keep
            });
        }
        for field in &mut fields {
            field.representation = None;
            if multiplexed {
                field.name = HeaderName::from_bytes(field.name.as_lower_str().as_bytes())
                    .map_err(|_error| ProfileDataError::Invalid("header structure name"))?;
            }
            if classify_values
                && !field.sensitive
                && matches!(field.value, HeaderValueSource::Profile(_))
                && let Some(binding) = structural_value_binding(&field.name)
            {
                field.value = HeaderValueSource::Request(binding);
            }
        }
        fields.sort_unstable_by(|a, b| {
            a.name
                .as_original_str()
                .cmp(&b.name.as_original_str())
                .then_with(|| a.sensitive.cmp(&b.sensitive))
                .then_with(|| {
                    let key = |value: &HeaderValueSource| match value {
                        HeaderValueSource::Profile(_) => 0,
                        HeaderValueSource::CaptureSafeProfile(_) => 1,
                        HeaderValueSource::Request(_) => 2,
                    };
                    key(&a.value)
                        .cmp(&key(&b.value))
                        .then_with(|| match (&a.value, &b.value) {
                            (HeaderValueSource::Profile(a), HeaderValueSource::Profile(b))
                            | (
                                HeaderValueSource::CaptureSafeProfile(a),
                                HeaderValueSource::CaptureSafeProfile(b),
                            ) => a.cmp(b),
                            (HeaderValueSource::Request(a), HeaderValueSource::Request(b)) => {
                                a.tag().cmp(&b.tag())
                            }
                            _ => Ordering::Equal,
                        })
                })
        });
        let mut occurrences = HashMap::<HeaderName, u32>::default();
        for field in &mut fields {
            let ordinal = occurrences.entry(field.name.clone()).or_default();
            field.occurrence = *ordinal;
            *ordinal = ordinal
                .checked_add(1)
                .ok_or(ProfileDataError::CounterOverflow)?;
        }
        let normalized = Self {
            completeness: self.completeness,
            version: self.version,
            fields: fields.into(),
        }
        .canonical(policy)?;
        let mut writer = CanonicalWriter::new(HEADER_STRUCTURE_DOMAIN, policy.bytes)?;
        writer.bytes(&normalized.bytes)?;
        Ok(writer.finish())
    }
}

/// Literal values that identify a request or device rather than the client build.
fn structural_value_binding(name: &HeaderName) -> Option<RequestBinding> {
    header_value_class(name).or_else(|| {
        // Stored captures predate request ownership of the fingerprint page marker.
        header_capture_binding(name)
    })
}

fn decode_header_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<(HeaderCapture, HeaderCapturePolicy), ProfileDataError> {
    value.verify(HEADER_STRUCTURE_DOMAIN, maximum_bytes)?;
    let mut reader = CanonicalReader::new(&value.bytes, HEADER_STRUCTURE_DOMAIN)?;
    let bytes = reader.bytes(maximum_bytes)?;
    let inner = CanonicalValue {
        id: ValueId(Sha256::digest(bytes).into()),
        bytes: Bytes::copy_from_slice(bytes),
    };
    reader.finish()?;
    let policy = HeaderCapturePolicy {
        fields: maximum_bytes,
        bytes: maximum_bytes,
        overrides: Box::default(),
    };
    let capture = HeaderCapture::from_canonical(&inner, &policy)?;
    Ok((capture, policy))
}

/// Re-key a stored structure, including older keys with volatile literals.
pub(in crate::profile) fn normalize_header_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<CanonicalValue, ProfileDataError> {
    validate_header_structure(value, maximum_bytes)?;
    let (capture, policy) = decode_header_structure(value, maximum_bytes)?;
    capture.structural(&policy)
}

pub(in crate::profile) fn validate_header_structure(
    value: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<(), ProfileDataError> {
    let (capture, policy) = decode_header_structure(value, maximum_bytes)?;
    if capture.structural(&policy)?.bytes != value.bytes
        && capture.encode_structure(&policy, false)?.bytes != value.bytes
    {
        return Err(ProfileDataError::Invalid("noncanonical header structure"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::profile::capture::completeness::ProfileCaptureCompleteness;
    use std::collections::BTreeSet;

    use rama_http::{
        HeaderMap, HeaderValue,
        proto::h3::observation::{FieldRepresentation, ObservedFieldRepresentation},
    };
    use rama_utils::octets::kib;

    use super::*;
    use crate::profile::{
        capture::joint::{
            CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
        },
        evidence::{
            bucket::{CountedObservationBucket, ProfileBucketLimits},
            ingestion::ObservationId,
        },
        format::canonical::CanonicalDomain,
    };

    #[test]
    fn ten_thousand_header_orders_share_structure_and_keep_bounded_complete_samples() {
        let policy = HeaderCapturePolicy::default();
        let limits = JointCaptureLimits::default();
        let mut structure = None;
        let mut raw_ids = BTreeSet::new();
        let mut bucket = None;
        let mut state = 1_u64;
        for sequence in 1..=10_000 {
            let mut names: Vec<_> = (0..12).collect();
            for index in (1..names.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                names.swap(index, (state % (index as u64 + 1)) as usize);
            }
            let mut headers = HeaderMap::new();
            for index in names {
                headers.insert(
                    HeaderName::from_bytes(format!("x-mode-{index}").as_bytes()).unwrap(),
                    HeaderValue::from_static("constant"),
                );
            }
            let captured = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_2,
                    &headers,
                    None,
                )
                .unwrap();
            let raw = captured.canonical(&policy).unwrap();
            let key = captured.structural(&policy).unwrap();
            validate_header_structure(&key, policy.bytes).unwrap();
            assert_ne!(raw.id, key.id);
            assert_eq!(*structure.get_or_insert(key.id), key.id);
            raw_ids.insert(raw.id);
            let joint = JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Request,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Headers,
                    value: raw.clone(),
                }]
                .into(),
            };
            let joint_key = joint.structural(limits).unwrap();
            joint_key.validated_domain(limits.bytes).unwrap();
            let bucket = bucket.get_or_insert_with(|| {
                CountedObservationBucket::new(
                    CanonicalDomain::Headers,
                    key.id,
                    [7; 32],
                    ProfileBucketLimits {
                        literal_values: 2,
                        samples: 4,
                        ..ProfileBucketLimits::default()
                    },
                )
                .unwrap()
            });
            bucket
                .observe(
                    ObservationId {
                        run: [1; 16],
                        sequence,
                    },
                    &raw,
                )
                .unwrap();
            assert!(bucket.snapshot().values.len() <= 6);
        }
        assert!(raw_ids.len() > 9_000);
        let snapshot = bucket.unwrap().snapshot();
        assert_eq!(snapshot.counts.total, 10_000);
        assert_eq!(snapshot.samples.len(), 4);
        for value in snapshot.values {
            let captured = HeaderCapture::from_canonical(&value, &policy).unwrap();
            assert_eq!(captured.fields.len(), 12);
            assert_eq!(captured.structural(&policy).unwrap().id, structure.unwrap());
            assert!(raw_ids.contains(&value.id));
        }
    }

    #[test]
    fn header_structure_keeps_semantics_multiplicity_spelling_and_ownership() {
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert("X-Mode", HeaderValue::from_static("one"));
        let original = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers,
                None,
            )
            .unwrap()
            .structural(&policy)
            .unwrap();
        for (name, value, duplicate) in [
            ("X-Mode", "two", false),
            ("x-mode", "one", false),
            ("X-Mode", "one", true),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static(value),
            );
            if duplicate {
                headers.append(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_static(value),
                );
            }
            assert_ne!(
                original.id,
                policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_11,
                        &headers,
                        None
                    )
                    .unwrap()
                    .structural(&policy)
                    .unwrap()
                    .id
            );
        }
        headers.insert("cookie", HeaderValue::from_static("secret-canary"));
        let bound = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers,
                None,
            )
            .unwrap();
        let key = bound.structural(&policy).unwrap();
        assert!(!key.bytes.windows(13).any(|v| v == b"secret-canary"));
        let mut forged = bound;
        forged.fields.last_mut().unwrap().value =
            HeaderValueSource::Profile(b"secret-canary".as_slice().into());
        forged.structural(&policy).unwrap_err();
        original
            .verify(CanonicalDomain::Headers, kib(64))
            .unwrap_err();
        original.validated_domain(kib(64)).unwrap();
    }

    #[test]
    fn header_structure_decoder_rejects_unsorted_raw_payload_and_truncation() {
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert("z-mode", HeaderValue::from_static("one"));
        headers.insert("a-mode", HeaderValue::from_static("two"));
        let capture = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_2,
                &headers,
                None,
            )
            .unwrap();
        let mut writer = CanonicalWriter::new(HEADER_STRUCTURE_DOMAIN, policy.bytes).unwrap();
        writer
            .bytes(&capture.canonical(&policy).unwrap().bytes)
            .unwrap();
        validate_header_structure(&writer.finish(), policy.bytes).unwrap_err();
        let key = capture.structural(&policy).unwrap();
        for length in 0..key.bytes.len() {
            let bytes = key.bytes.slice(..length);
            validate_header_structure(
                &CanonicalValue {
                    id: ValueId(Sha256::digest(&bytes).into()),
                    bytes,
                },
                policy.bytes,
            )
            .unwrap_err();
        }
        let mut bytes = key.bytes.to_vec();
        bytes.push(0);
        validate_header_structure(
            &CanonicalValue {
                id: ValueId(Sha256::digest(&bytes).into()),
                bytes: bytes.into(),
            },
            policy.bytes,
        )
        .unwrap_err();
    }
    #[test]
    fn compression_state_stays_in_raw_capture_without_splitting_header_structure() {
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/plain"));
        let mut structural = None;
        let mut raw_ids = BTreeSet::new();
        for index in 0..32 {
            let representation = ObservedFieldRepresentation {
                representation: FieldRepresentation::DynamicIndex,
                index: Some(index),
                name_huffman: false,
                value_huffman: false,
                never_index: false,
            };
            let capture = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_3,
                    &headers,
                    Some(&[representation]),
                )
                .unwrap();
            let raw = capture.canonical(&policy).unwrap();
            raw_ids.insert(raw.id);
            let key = capture.structural(&policy).unwrap();
            assert_eq!(*structural.get_or_insert(key.id), key.id);
            let restored = HeaderCapture::from_canonical(&raw, &policy).unwrap();
            assert_eq!(
                restored.fields[0].representation.unwrap().index,
                Some(index)
            );
        }
        assert_eq!(raw_ids.len(), 32);
    }
}
