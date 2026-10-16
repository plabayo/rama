//! Source completeness is explicit before an observation becomes profile data.

use serde::Serialize;

use crate::profile::format::canonical::ProfileDataError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ProfileCaptureCompleteness {
    #[default]
    Incomplete,
    Complete,
}

impl ProfileCaptureCompleteness {
    #[must_use]
    pub const fn from_complete(complete: bool) -> Self {
        if complete {
            Self::Complete
        } else {
            Self::Incomplete
        }
    }

    pub(in crate::profile) fn require_complete(
        self,
        component: &'static str,
    ) -> Result<(), ProfileDataError> {
        if self != Self::Complete {
            return Err(ProfileDataError::Incomplete(component));
        }
        Ok(())
    }

    pub(in crate::profile) const fn tag(self) -> u8 {
        match self {
            Self::Incomplete => 0,
            Self::Complete => 1,
        }
    }

    pub(in crate::profile) fn from_tag(tag: u8) -> Result<Self, ProfileDataError> {
        match tag {
            0 => Ok(Self::Incomplete),
            1 => Ok(Self::Complete),
            _ => Err(ProfileDataError::Invalid("capture completeness tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, iter};

    use rama_http::{HeaderMap, HeaderValue, Version};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::profile::{
        capture::{
            headers::{HeaderCapture, HeaderCapturePolicy},
            joint::{
                CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
            },
            observation::ProfileCapture,
            order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        },
        evidence::{
            bucket::{CountedObservationBucket, ProfileBucketLimits},
            ingestion::ObservationId,
        },
        format::canonical::{CanonicalDomain, CanonicalValue, ValueId},
        model::identity::{ConnectionContext, ProfileKey},
    };

    fn header() -> HeaderCapture {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/plain"));
        HeaderCapturePolicy::default()
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_3,
                &headers,
                None,
            )
            .unwrap()
    }
    fn order() -> OrderedProtocolCapture {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [(1, [1])],
            OrderCaptureLimits::default(),
        )
        .unwrap()
    }
    fn joint() -> JointCapture {
        JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicParameters,
                value: order().canonical(OrderCaptureLimits::default()).unwrap(),
            }]
            .into(),
        }
    }
    fn with_status(mut value: CanonicalValue, tag: u8) -> CanonicalValue {
        assert_eq!(&value.bytes[13..15], &[0, 2]);
        assert_eq!(value.bytes[18], 1);
        value.bytes[18] = tag;
        value.id = ValueId(Sha256::digest(&value.bytes).into());
        value
    }

    #[test]
    fn partial_capture_sources_fail_before_iterating_or_retaining_data() {
        assert_eq!(
            ProfileCaptureCompleteness::default(),
            ProfileCaptureCompleteness::Incomplete
        );
        let incomplete = ProfileCaptureCompleteness::from_complete(false);
        HeaderCapturePolicy::default()
            .capture(incomplete, Version::HTTP_3, &HeaderMap::new(), None)
            .unwrap_err();
        let visited = Cell::new(0);
        let input = iter::from_fn(|| {
            visited.set(visited.get() + 1);
            Some((1, [1]))
        });
        assert!(matches!(
            OrderedProtocolCapture::capture(
                incomplete,
                OrderNamespace::QuicParameter,
                input,
                OrderCaptureLimits {
                    elements: 1,
                    ..OrderCaptureLimits::default()
                }
            ),
            Err(ProfileDataError::Incomplete(_))
        ));
        assert_eq!(visited.get(), 0);
    }

    #[test]
    fn hand_built_incomplete_headers_orders_and_joint_tuples_have_no_canonical_value() {
        let policy = HeaderCapturePolicy::default();
        let mut header = header();
        header.completeness = ProfileCaptureCompleteness::Incomplete;
        header.canonical(&policy).unwrap_err();
        header.structural(&policy).unwrap_err();
        let mut order = order();
        order.completeness = ProfileCaptureCompleteness::Incomplete;
        order.canonical(OrderCaptureLimits::default()).unwrap_err();
        order.structural(OrderCaptureLimits::default()).unwrap_err();
        let mut joint = joint();
        joint.completeness = ProfileCaptureCompleteness::Incomplete;
        joint.canonical(JointCaptureLimits::default()).unwrap_err();
        joint.structural(JointCaptureLimits::default()).unwrap_err();
    }

    #[test]
    fn decoded_incomplete_unknown_or_legacy_flags_never_gain_profile_capability() {
        let limits = JointCaptureLimits::default();
        let values = [
            header().canonical(&HeaderCapturePolicy::default()).unwrap(),
            order().canonical(OrderCaptureLimits::default()).unwrap(),
            joint().canonical(limits).unwrap(),
            joint().structural(limits).unwrap(),
        ];
        for value in values {
            value.validated_domain(limits.bytes).unwrap();
            for tag in [0, 2, 255] {
                with_status(value.clone(), tag)
                    .validated_domain(limits.bytes)
                    .unwrap_err();
            }
            let mut bytes = value.bytes.into_vec();
            bytes[13..15].copy_from_slice(&[0, 1]);
            bytes.remove(18);
            let old = CanonicalValue {
                id: ValueId(Sha256::digest(&bytes).into()),
                bytes: bytes.into(),
            };
            assert!(matches!(
                old.validated_domain(limits.bytes),
                Err(ProfileDataError::Unsupported("canonical format version"))
            ));
        }
    }

    #[test]
    fn incomplete_values_cannot_be_laundered_through_joint_capture_or_loss_counts() {
        let limits = JointCaptureLimits::default();
        let mut joint = joint();
        let value = with_status(joint.slots[0].value.clone(), 0);
        joint.slots[0].value = value.clone();
        let profile = ProfileCapture {
            profile: ProfileKey::new("test"),
            flow: None,
            connection: ConnectionContext::default(),
            joint,
        };
        assert!(matches!(
            profile.prepare(false, limits),
            Err(ProfileDataError::Incomplete(_))
        ));
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Order,
            ValueId([1; 32]),
            [2; 32],
            ProfileBucketLimits {
                value_bytes: 1,
                ..ProfileBucketLimits::default()
            },
        )
        .unwrap();
        let before = serde_json::to_vec(&bucket.snapshot()).unwrap();
        assert!(matches!(
            bucket.observe(
                ObservationId {
                    run: [3; 16],
                    sequence: 1
                },
                &value
            ),
            Err(ProfileDataError::Incomplete(_))
        ));
        assert_eq!(before, serde_json::to_vec(&bucket.snapshot()).unwrap());
    }
}
