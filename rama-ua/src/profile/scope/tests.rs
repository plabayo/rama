use std::collections::BTreeSet;

use rama_utils::octets::kib;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::profile::{ConnectionIpFamily, ResumptionContext};

fn scope() -> ProfileObservationScope {
    ProfileObservationScope {
        authorized: false,
        profile: ValueId([1; 32]),
        flow: None,
        connection: ConnectionContext::default(),
        structure: ValueId([2; 32]),
    }
}

fn rehash(bytes: Vec<u8>) -> CanonicalValue {
    CanonicalValue {
        id: ValueId(Sha256::digest(&bytes).into()),
        bytes: bytes.into(),
    }
}

#[test]
fn scope_identity_separates_authorization_references_and_observed_context() {
    let base = scope();
    let mut variants = vec![base.clone()];
    let mut other = base.clone();
    other.authorized = true;
    variants.push(other);
    let mut other = base.clone();
    other.profile = ValueId([3; 32]);
    variants.push(other);
    let mut other = base.clone();
    other.structure = ValueId([3; 32]);
    variants.push(other);
    for flow in [ValueId([0; 32]), ValueId([3; 32])] {
        let mut other = base.clone();
        other.flow = Some(flow);
        variants.push(other);
    }
    for resumption in [ResumptionContext::Fresh, ResumptionContext::Resumed] {
        let mut other = base.clone();
        other.connection.resumption = resumption;
        variants.push(other);
    }
    for flag in [false, true] {
        let mut other = base.clone();
        other.connection.early_data = Some(flag);
        variants.push(other);
        let mut other = base.clone();
        other.connection.token_present = Some(flag);
        variants.push(other);
    }
    for family in [ConnectionIpFamily::V4, ConnectionIpFamily::V6] {
        let mut other = base.clone();
        other.connection.ip_family = Some(family);
        variants.push(other);
    }
    let mut identities = BTreeSet::new();
    for scope in &variants {
        let canonical = scope.canonical(kib(1)).unwrap();
        assert!(identities.insert(canonical.id));
        let restored = ProfileObservationScope::from_canonical(&canonical, kib(1)).unwrap();
        assert_eq!(restored.canonical(kib(1)).unwrap().bytes, canonical.bytes);
    }
    assert_eq!(identities.len(), variants.len());
}

#[test]
fn scope_decoder_rejects_forged_tags_lengths_truncation_and_digest() {
    let value = scope().canonical(kib(1)).unwrap();
    for offset in [17, 58, 59, 60, 61, 62] {
        let mut bytes = value.bytes.to_vec();
        bytes[offset] = 3;
        ProfileObservationScope::from_canonical(&rehash(bytes), kib(1)).unwrap_err();
    }
    for length in 0..value.bytes.len() {
        ProfileObservationScope::from_canonical(&rehash(value.bytes[..length].to_vec()), kib(1))
            .unwrap_err();
    }
    for length in [0, 31, 33, 255] {
        let mut bytes = value.bytes.to_vec();
        bytes[25] = length;
        ProfileObservationScope::from_canonical(&rehash(bytes), kib(1)).unwrap_err();
    }
    // Short references still have well-framed following fields; a later parser
    // error must not conceal a missing fixed-size identity check.
    for (with_flow, length_offset, last_byte) in [(false, 25, 57), (true, 66, 98), (false, 70, 102)]
    {
        let mut input = scope();
        if with_flow {
            input.flow = Some(ValueId([3; 32]));
        }
        let mut bytes = input.canonical(kib(1)).unwrap().bytes.into_vec();
        bytes[length_offset] = 31;
        bytes.remove(last_byte);
        ProfileObservationScope::from_canonical(&rehash(bytes), kib(1)).unwrap_err();
    }
    let mut bytes = value.bytes.to_vec();
    bytes.push(0);
    ProfileObservationScope::from_canonical(&rehash(bytes), kib(1)).unwrap_err();
    let mut corrupt = value.clone();
    corrupt.id.0[0] ^= 1;
    ProfileObservationScope::from_canonical(&corrupt, kib(1)).unwrap_err();
    for offset in [0, 14, 16] {
        let mut bytes = value.bytes.to_vec();
        bytes[offset] ^= 1;
        ProfileObservationScope::from_canonical(&rehash(bytes), kib(1)).unwrap_err();
    }
    scope().canonical(102).unwrap_err();
    ProfileObservationScope::from_canonical(&value, 102).unwrap_err();
}

#[test]
fn scope_canonical_format_has_an_independent_fixed_vector() {
    let canonical = scope().canonical(kib(1)).unwrap();
    let mut expected = b"rama-profile\0\0\x01\0\x08\0".to_vec();
    expected.extend_from_slice(&32_u64.to_be_bytes());
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[0; 5]);
    expected.extend_from_slice(&32_u64.to_be_bytes());
    expected.extend_from_slice(&[2; 32]);
    assert_eq!(canonical.bytes.as_ref(), expected);
    assert_eq!(canonical.bytes.len(), 103);
    // Independently calculated with Python hashlib from the owned wire encoding.
    assert_eq!(
        canonical.id.0,
        [
            38, 213, 221, 128, 183, 125, 128, 227, 207, 148, 56, 240, 92, 235, 4, 23, 32, 142, 195,
            4, 114, 176, 214, 6, 240, 21, 247, 145, 45, 103, 122, 156
        ]
    );
}
