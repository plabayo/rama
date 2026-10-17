use super::*;
use crate::profile::{
    capture::joint::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
    },
    format::canonical::ValueId,
};
use rama_quic_proto::capture::{CaptureCompleteness, RawParameter};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

fn observation() -> QuicObservation {
    QuicObservation {
        connection_id: b"connection-secret".to_vec(),
        attempt_id: b"attempt-secret".to_vec(),
        retry_parent: None,
        first_flight: Some(FirstFlight {
            datagram_sizes: vec![1200],
            trailing_bytes: vec![0],
            version: Version::V1,
            dcid_len: 8,
            scid_len: 0,
            token_len: 0,
            first_packet_number: 3,
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
            parameters: vec![ParameterId(1)],
            chosen_version: None,
            available_versions: vec![],
            packet_numbers: vec![3],
            complete: true,
        }),
        transport_parameters: vec![RawParameter {
            id: ParameterId(1),
            value: vec![1],
        }],
        client_hello_message: b"private-clienthello".to_vec(),
        completeness: CaptureCompleteness {
            datagrams: true,
            frames: true,
            client_hello: true,
            transport_parameters: true,
            original_attempt: true,
        },
    }
}

fn capture() -> QuicFlightCapture {
    QuicFlightCapture::capture(&observation(), QuicFlightCaptureLimits::default()).unwrap()
}

fn resign(bytes: Vec<u8>) -> CanonicalValue {
    CanonicalValue {
        id: ValueId(Sha256::digest(&bytes).into()),
        bytes: bytes.into(),
    }
}

mod encoding;
mod structure;
mod validation;
