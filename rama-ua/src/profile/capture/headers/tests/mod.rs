use crate::profile::capture::completeness::ProfileCaptureCompleteness;
use crate::profile::format::canonical::CanonicalDomain;
use std::collections::BTreeSet;

use super::*;
use crate::profile::{
    evidence::{
        bucket::{CountedObservationBucket, ProfileBucketLimits},
        ingestion::ObservationId,
    },
    format::canonical::ValueId,
};
use sha2::{Digest as _, Sha256};

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    headers
}

fn encode(headers: &HeaderMap) -> CanonicalValue {
    let policy = HeaderCapturePolicy::default();
    policy
        .capture(
            ProfileCaptureCompleteness::Complete,
            Version::HTTP_11,
            headers,
            None,
        )
        .unwrap()
        .canonical(&policy)
        .unwrap()
}

mod ownership;
mod representation;
mod validation;
