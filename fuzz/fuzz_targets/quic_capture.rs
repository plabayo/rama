#![no_main]
#![cfg(fuzzing)]

use libfuzzer_sys::fuzz_target;
use rama::{
    bytes::BytesMut,
    quic::proto::{
        MAX_CID_SIZE, Side,
        capture::{self, CaptureError, CaptureLimits, InitialKeys, KeyProvider},
        crypto::{CryptoError, HeaderKey, PacketKey},
        version::Version,
    },
    utils::octets::kib,
};

/// Keys that leave packets as they are, so every observed Initial reaches key derivation,
/// header and frame parsing and ClientHello reassembly.
struct Plain;

impl HeaderKey for Plain {
    fn decrypt(&self, _: usize, _: &mut [u8]) {}

    fn encrypt(&self, _: usize, _: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        16
    }
}

impl PacketKey for Plain {
    fn encrypt(&self, _: u64, _: &mut [u8], _: usize) -> Result<(), CryptoError> {
        Ok(())
    }

    fn decrypt(&self, _: u64, _: &[u8], payload: &mut BytesMut) -> Result<(), CryptoError> {
        let len = payload.len().checked_sub(16).ok_or_else(CryptoError::new)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

struct PlainKeys;

impl KeyProvider for PlainKeys {
    type Header = Plain;
    type Packet = Plain;

    fn initial_keys(
        &self,
        _: Version,
        dcid: &[u8],
        _: Side,
    ) -> Result<InitialKeys<Plain, Plain>, CaptureError> {
        assert!(
            dcid.len() <= MAX_CID_SIZE,
            "an oversized connection ID reached key derivation"
        );
        Ok(InitialKeys {
            header: Plain,
            packet: Plain,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&budget, data)) = data.split_first() else {
        return;
    };
    let data = &data[..data.len().min(kib(8))];
    let bound = usize::from(budget);
    let limits = CaptureLimits {
        bytes: kib(8),
        packets: bound,
        frames: bound,
        crypto_fragments: bound,
        client_hello_bytes: bound * 16,
        parameters: bound,
        datagrams: 4,
    };
    rama::quic::fuzzing::observe_sequence(data, limits);
    if let Ok(observed) = serde_json::from_slice::<capture::ObservedDatagram>(data) {
        let _ =
            observed.unprotect_initials_with_limits(data, &PlainKeys, Side::Server, None, &limits);
    }
    if let Ok(initial) = serde_json::from_slice::<capture::InitialPacket>(data) {
        let _ = capture::client_hello_with_limits(&[initial], &limits);
    }
    let _ = capture::first_flight_with_limits(&[data], &PlainKeys, &limits);
    if let Ok(observed) = capture::observe_with_limits(data, &limits) {
        let mut previous_end = 0;
        for packet in &observed.packets {
            assert_eq!(packet.range.start, previous_end);
            assert!(packet.range.end > packet.range.start);
            assert!(packet.range.end <= data.len());
            previous_end = packet.range.end;
        }
        assert_eq!(previous_end + observed.trailing, data.len());
        for side in [Side::Server, Side::Client] {
            if let Ok(initials) =
                observed.unprotect_initials_with_limits(data, &PlainKeys, side, None, &limits)
            {
                let _ = capture::client_hello_with_limits(&initials, &limits);
            }
        }
    }
    if let Ok(parameters) = capture::transport_parameters_with_limits(data, &limits) {
        let _ = capture::version_information(&parameters);
    }
});
