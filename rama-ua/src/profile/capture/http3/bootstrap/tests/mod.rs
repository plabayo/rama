use super::*;
use crate::profile::format::decoded::{CaptureDecodeLimits, DecodedCapture};
use sha2::{Digest as _, Sha256};

fn capture() -> H3BootstrapCapture {
    H3BootstrapCapture {
        request: ValueId([7; 32]),
        method: Method::GET,
        fields: 17,
        bindings: ObservedEncoderBindings {
            stream_id: 4,
            complete: true,
            insertions: [
                InsertionFieldMatch::Unique { field_index: 1 },
                InsertionFieldMatch::Absent,
                InsertionFieldMatch::Ambiguous,
                InsertionFieldMatch::Evicted,
                InsertionFieldMatch::Unavailable,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, field)| ObservedInsertionBinding {
                instruction_index: index + 1,
                insertion_index: index as u64,
                field,
            })
            .collect(),
        },
    }
}

#[test]
fn bootstrap_round_trip_retains_identity_and_every_association_state() {
    let limits = H3BootstrapLimits::default();
    let original = capture();
    let encoded = original.canonical(limits).unwrap();
    let decoded = H3BootstrapCapture::from_canonical(&encoded, limits).unwrap();
    assert_eq!(decoded.request, original.request);
    assert_eq!(decoded.method, original.method);
    assert_eq!(decoded.bindings.stream_id, original.bindings.stream_id);
    assert_eq!(decoded.canonical(limits).unwrap().bytes, encoded.bytes);
    for (before, after) in original
        .bindings
        .insertions
        .iter()
        .zip(&decoded.bindings.insertions)
    {
        assert_eq!(before.instruction_index, after.instruction_index);
        assert_eq!(before.insertion_index, after.insertion_index);
        assert_eq!(before.field, after.field);
    }
    let structure = original.structural(limits).unwrap();
    H3BootstrapCapture::decode(&structure, limits, true).unwrap();
    assert!(matches!(
        DecodedCapture::from_canonical(&encoded, &CaptureDecodeLimits::default()).unwrap(),
        DecodedCapture::H3Bootstrap(typed) if typed.request == original.request
    ));
    let mut corrupt = encoded.clone();
    corrupt.id.0[0] ^= 1;
    H3BootstrapCapture::from_canonical(&corrupt, limits).unwrap_err();
    let mut corrupt = encoded;
    corrupt.bytes = [corrupt.bytes.as_ref(), &[0]].concat().into();
    corrupt.id.0 = Sha256::digest(&corrupt.bytes).into();
    H3BootstrapCapture::from_canonical(&corrupt, limits).unwrap_err();
    let mut other = original;
    other.request.0[0] ^= 1;
    assert_ne!(other.structural(limits).unwrap().id, structure.id);
}

#[test]
fn bootstrap_admission_rejects_incomplete_invalid_positions_and_budgets() {
    let limits = H3BootstrapLimits::default();
    for case in 0..7 {
        let mut value = capture();
        match case {
            0 => value.bindings.complete = false,
            1 => value.bindings.stream_id = 3,
            2 => value.bindings.stream_id = 1 << 62,
            3 => {
                value.bindings.insertions[0].field = InsertionFieldMatch::Unique {
                    field_index: value.fields,
                }
            }
            4 => value.bindings.insertions[1].instruction_index = 1,
            5 => value.bindings.insertions[1].insertion_index = 0,
            _ => value.fields = limits.fields + 1,
        }
        value.canonical(limits).unwrap_err();
    }
    let value = capture();
    for bounds in [
        H3BootstrapLimits {
            fields: 1,
            ..limits
        },
        H3BootstrapLimits {
            instructions: 1,
            ..limits
        },
        H3BootstrapLimits {
            bytes: 32,
            ..limits
        },
    ] {
        value.canonical(bounds).unwrap_err();
    }
    let encoded = value.canonical(limits).unwrap();
    H3BootstrapCapture::from_canonical(
        &encoded,
        H3BootstrapLimits {
            instructions: 1,
            ..limits
        },
    )
    .unwrap_err();
}
