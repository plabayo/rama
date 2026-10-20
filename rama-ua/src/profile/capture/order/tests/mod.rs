use std::cell::Cell;

use super::*;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
    },
    evidence::{
        bucket::{CountedObservationBucket, ProfileBucketLimits},
        ingestion::ObservationId,
    },
    format::canonical::ValueId,
};

fn capture(namespace: OrderNamespace, fields: &[(u64, &[u8])]) -> OrderedProtocolCapture {
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        namespace,
        fields.iter().copied(),
        OrderCaptureLimits::default(),
    )
    .unwrap()
}

mod encoding;
mod structure;
mod validation;
