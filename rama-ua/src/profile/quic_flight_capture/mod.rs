mod structure;
// Bounded first-flight facts without connection identifiers or handshake bytes.

use super::{
    CanonicalDomain, CanonicalValue, ProfileCaptureCompleteness, ProfileDataError,
    canonical::{CanonicalReader, CanonicalWriter},
};
use rama_quic_proto::{
    Version,
    capture::{FirstFlight, ObservedFrame, QuicObservation},
    profile::{PaddingPlacement, ParameterId},
    version::VersionInformation,
};
use rama_utils::octets::kib;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
/// Resource limits for one retained QUIC first flight.
pub struct QuicFlightCaptureLimits {
    pub datagrams: usize,
    pub packets: usize,
    pub frames: usize,
    pub parameters: usize,
    pub observed_bytes: usize,
    pub bytes: usize,
}

impl Default for QuicFlightCaptureLimits {
    fn default() -> Self {
        Self {
            datagrams: 32,
            packets: 64,
            frames: 256,
            parameters: 256,
            observed_bytes: kib(64),
            bytes: kib(16),
        }
    }
}

/// Observed layout facts. Packet kinds after the Initial, varint widths and
/// ignored frame payloads are absent from the source observation. These facts
/// alone do not establish exact wire replay capability.
#[derive(Debug, Clone, Serialize)]
pub struct QuicFlightCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub flight: FirstFlight,
}

impl QuicFlightCapture {
    pub fn capture(
        observed: &QuicObservation,
        limits: QuicFlightCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        if !observed.completeness.is_complete() {
            return Err(ProfileDataError::Incomplete("QUIC first flight"));
        }
        let flight = observed
            .first_flight
            .as_ref()
            .ok_or(ProfileDataError::Incomplete("missing QUIC first flight"))?;
        encode(ProfileCaptureCompleteness::Complete, flight, limits)?;
        if !flight.parameters.iter().copied().eq(observed
            .transport_parameters
            .iter()
            .map(|parameter| parameter.id))
        {
            return Err(ProfileDataError::Invalid(
                "QUIC parameter observation mismatch",
            ));
        }
        Ok(Self {
            completeness: ProfileCaptureCompleteness::Complete,
            flight: flight.clone(),
        })
    }

    pub fn canonical(
        &self,
        limits: QuicFlightCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        encode(self.completeness, &self.flight, limits)
    }
    /// Preserve client choices while connection-owned sizes and draws remain in
    /// complete samples, outside the grouping identity.
    pub fn structural(
        &self,
        limits: QuicFlightCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.completeness.require_complete("QUIC first flight")?;
        validate(&self.flight, limits)?;
        structure::encode(&self.flight, limits)
    }

    pub(super) fn validate_structure(
        value: &CanonicalValue,
        limits: QuicFlightCaptureLimits,
    ) -> Result<(), ProfileDataError> {
        structure::validate(value, limits)
    }
    pub fn from_canonical(
        value: &CanonicalValue,
        limits: QuicFlightCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        value.verify(CanonicalDomain::QuicFlight, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::QuicFlight)?;
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        completeness.require_complete("QUIC first flight")?;
        let datagram_sizes = read_sizes(&mut reader, limits.datagrams, 65_527)?;
        let trailing_bytes = read_sizes(&mut reader, limits.datagrams, 65_527)?;
        let version = Version::from_u32(reader.u32()?);
        let dcid_len = reader.count(20)?;
        let scid_len = reader.count(20)?;
        let token_len = reader.count(limits.observed_bytes)?;
        let first_packet_number = reader.u64()?;
        let packet_number_len = reader.u8()?;
        let mut frames = Vec::new();
        let mut remaining = limits.frames;
        for _ in 0..reader.count(limits.packets)? {
            let count = reader.count(remaining)?;
            remaining -= count;
            let mut packet = Vec::new();
            for _ in 0..count {
                packet.push(match reader.u8()? {
                    0 => ObservedFrame::Padding {
                        len: reader.count(limits.observed_bytes)?,
                    },
                    1 => ObservedFrame::Ping,
                    2 => ObservedFrame::Ack,
                    3 => ObservedFrame::Crypto {
                        offset: reader.u64()?,
                        len: reader.count(limits.observed_bytes)?,
                    },
                    4 => ObservedFrame::Other { ty: reader.u64()? },
                    _ => return Err(ProfileDataError::Invalid("QUIC Initial frame shape")),
                });
            }
            frames.push(packet);
        }
        let padding = match reader.u8()? {
            0 => PaddingPlacement::Frames,
            1 => PaddingPlacement::DatagramTail,
            _ => return Err(ProfileDataError::Invalid("QUIC padding placement")),
        };
        let coalesced = flag(&mut reader)?;
        let mut parameters = Vec::new();
        for _ in 0..reader.count(limits.parameters)? {
            parameters.push(ParameterId(reader.u64()?));
        }
        let chosen_version = if flag(&mut reader)? {
            Some(Version::from_u32(reader.u32()?))
        } else {
            None
        };
        let mut available_versions = Vec::new();
        for _ in 0..reader.count(limits.parameters)? {
            available_versions.push(Version::from_u32(reader.u32()?));
        }
        let mut packet_numbers = Vec::new();
        for _ in 0..reader.count(limits.packets)? {
            packet_numbers.push(reader.u64()?);
        }
        reader.finish()?;
        let result = Self {
            completeness,
            flight: FirstFlight {
                datagram_sizes,
                trailing_bytes,
                version,
                dcid_len,
                scid_len,
                token_len,
                first_packet_number,
                packet_number_len,
                frames,
                padding,
                coalesced,
                parameters,
                chosen_version,
                available_versions,
                packet_numbers,
                complete: true,
            },
        };
        if result.canonical(limits)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical QUIC first flight"));
        }
        Ok(result)
    }
}

fn flag(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProfileDataError::Invalid("QUIC flight flag")),
    }
}

fn read_sizes(
    reader: &mut CanonicalReader<'_>,
    count: usize,
    maximum: usize,
) -> Result<Vec<usize>, ProfileDataError> {
    let mut values = Vec::new();
    for _ in 0..reader.count(count)? {
        values.push(reader.count(maximum)?);
    }
    Ok(values)
}

fn write_sizes(writer: &mut CanonicalWriter, values: &[usize]) -> Result<(), ProfileDataError> {
    writer.u64(values.len() as u64)?;
    for value in values {
        writer.u64(*value as u64)?;
    }
    Ok(())
}

fn validate(flight: &FirstFlight, limits: QuicFlightCaptureLimits) -> Result<(), ProfileDataError> {
    if !flight.complete {
        return Err(ProfileDataError::Incomplete("QUIC first flight layout"));
    }
    if flight.datagram_sizes.len() > limits.datagrams
        || flight.packet_numbers.len() > limits.packets
        || flight.frames.len() > limits.packets
        || flight.parameters.len() > limits.parameters
        || flight.available_versions.len() > limits.parameters
    {
        return Err(ProfileDataError::LimitExceeded(
            "QUIC first flight elements",
        ));
    }
    if flight.datagram_sizes.is_empty()
        || flight.datagram_sizes.len() != flight.trailing_bytes.len()
        || flight.frames.is_empty()
        || flight.packet_numbers.first() != Some(&flight.first_packet_number)
        || !(1..=4).contains(&flight.packet_number_len)
        || flight.dcid_len > 20
        || flight.scid_len > 20
        || flight.token_len > limits.observed_bytes
        || flight.version.as_u32() == 0
    {
        return Err(ProfileDataError::Invalid("QUIC first flight layout"));
    }
    let mut bytes = limits.observed_bytes;
    for (&size, &trailing) in flight.datagram_sizes.iter().zip(&flight.trailing_bytes) {
        if size == 0 || size > 65_527 || trailing >= size {
            return Err(ProfileDataError::Invalid("QUIC datagram shape"));
        }
        bytes = bytes
            .checked_sub(size)
            .ok_or(ProfileDataError::LimitExceeded(
                "QUIC observed datagram bytes",
            ))?;
    }
    if matches!(flight.padding, PaddingPlacement::DatagramTail)
        != flight.trailing_bytes.iter().any(|trailing| *trailing != 0)
    {
        return Err(ProfileDataError::Invalid(
            "QUIC padding placement and trailing bytes",
        ));
    }
    let mut remaining = limits.frames;
    for packet in &flight.frames {
        if packet.is_empty()
            || packet.windows(2).any(|pair| {
                matches!(
                    pair,
                    [ObservedFrame::Padding { .. }, ObservedFrame::Padding { .. }]
                )
            })
        {
            return Err(ProfileDataError::Invalid("noncanonical QUIC frame runs"));
        }
        remaining = remaining
            .checked_sub(packet.len())
            .ok_or(ProfileDataError::LimitExceeded("QUIC Initial frame shapes"))?;
        for frame in packet {
            match frame {
                ObservedFrame::Padding { len } if *len == 0 || *len > limits.observed_bytes => {
                    return Err(ProfileDataError::Invalid("QUIC padding run"));
                }
                ObservedFrame::Crypto { offset, len }
                    if *len > limits.observed_bytes
                        || offset
                            .checked_add(*len as u64)
                            .is_none_or(|end| end >= (1 << 62)) =>
                {
                    return Err(ProfileDataError::Invalid("QUIC CRYPTO shape"));
                }
                ObservedFrame::Other { ty }
                    if *ty >= (1 << 62) || matches!(*ty, 0 | 1 | 2 | 3 | 6) =>
                {
                    return Err(ProfileDataError::Invalid("QUIC frame type"));
                }
                _ => {}
            }
        }
    }
    let mut unique = 0;
    for (i, number) in flight.packet_numbers.iter().enumerate() {
        if *number >= (1 << 62) {
            return Err(ProfileDataError::Invalid("QUIC packet number"));
        }
        if !flight.packet_numbers[..i].contains(number) {
            unique += 1;
        }
    }
    if unique != flight.frames.len() {
        return Err(ProfileDataError::Invalid("QUIC Initial packet shape count"));
    }
    for (i, id) in flight.parameters.iter().enumerate() {
        if id.0 >= (1 << 62) || flight.parameters[..i].contains(id) {
            return Err(ProfileDataError::Invalid("QUIC parameter identity"));
        }
    }
    match flight.chosen_version {
        Some(chosen) => {
            if chosen != flight.version
                || !flight
                    .parameters
                    .contains(&ParameterId::VERSION_INFORMATION)
            {
                return Err(ProfileDataError::Invalid(
                    "QUIC version information context",
                ));
            }
            let mut bytes = Vec::new();
            VersionInformation::new(chosen, flight.available_versions.clone()).write(&mut bytes);
            VersionInformation::read(true, bytes.len(), &mut bytes.as_slice())
                .map_err(|_error| ProfileDataError::Invalid("QUIC available versions"))?;
        }
        None if !flight.available_versions.is_empty()
            || flight
                .parameters
                .contains(&ParameterId::VERSION_INFORMATION) =>
        {
            return Err(ProfileDataError::Invalid(
                "missing QUIC version information",
            ));
        }
        None => {}
    }
    Ok(())
}

fn encode(
    completeness: ProfileCaptureCompleteness,
    flight: &FirstFlight,
    limits: QuicFlightCaptureLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    completeness.require_complete("QUIC first flight")?;
    validate(flight, limits)?;
    let mut writer = CanonicalWriter::new(CanonicalDomain::QuicFlight, limits.bytes)?;
    writer.u8(completeness.tag())?;
    write_sizes(&mut writer, &flight.datagram_sizes)?;
    write_sizes(&mut writer, &flight.trailing_bytes)?;
    writer.u32(flight.version.as_u32())?;
    writer.u64(flight.dcid_len as u64)?;
    writer.u64(flight.scid_len as u64)?;
    writer.u64(flight.token_len as u64)?;
    writer.u64(flight.first_packet_number)?;
    writer.u8(flight.packet_number_len)?;
    writer.u64(flight.frames.len() as u64)?;
    for packet in &flight.frames {
        writer.u64(packet.len() as u64)?;
        for frame in packet {
            match frame {
                ObservedFrame::Padding { len } => {
                    writer.u8(0)?;
                    writer.u64(*len as u64)?;
                }
                ObservedFrame::Ping => writer.u8(1)?,
                ObservedFrame::Ack => writer.u8(2)?,
                ObservedFrame::Crypto { offset, len } => {
                    writer.u8(3)?;
                    writer.u64(*offset)?;
                    writer.u64(*len as u64)?;
                }
                ObservedFrame::Other { ty } => {
                    writer.u8(4)?;
                    writer.u64(*ty)?;
                }
            }
        }
    }
    writer.u8(match flight.padding {
        PaddingPlacement::Frames => 0,
        PaddingPlacement::DatagramTail => 1,
        _ => return Err(ProfileDataError::Unsupported("QUIC padding placement")),
    })?;
    writer.u8(u8::from(flight.coalesced))?;
    writer.u64(flight.parameters.len() as u64)?;
    for id in &flight.parameters {
        writer.u64(id.0)?;
    }
    writer.u8(u8::from(flight.chosen_version.is_some()))?;
    if let Some(version) = flight.chosen_version {
        writer.u32(version.as_u32())?;
    }
    writer.u64(flight.available_versions.len() as u64)?;
    for version in &flight.available_versions {
        writer.u32(version.as_u32())?;
    }
    writer.u64(flight.packet_numbers.len() as u64)?;
    for number in &flight.packet_numbers {
        writer.u64(*number)?;
    }
    Ok(writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits, ValueId,
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

    #[test]
    fn flight_roundtrip_retains_layout_without_connection_secrets() {
        let limits = QuicFlightCaptureLimits::default();
        let capture = capture();
        let canonical = capture.canonical(limits).unwrap();
        assert_eq!(
            QuicFlightCapture::from_canonical(&canonical, limits)
                .unwrap()
                .flight,
            capture.flight
        );
        for secret in [
            b"connection-secret".as_slice(),
            b"attempt-secret",
            b"private-clienthello",
        ] {
            assert!(
                !canonical
                    .bytes
                    .windows(secret.len())
                    .any(|value| value == secret)
            );
            assert!(
                !serde_json::to_vec(&capture)
                    .unwrap()
                    .windows(secret.len())
                    .any(|value| value == secret)
            );
        }
        assert_ne!(canonical.id, capture.structural(limits).unwrap().id);
        let structure = capture.structural(limits).unwrap();
        assert_eq!(
            structure.id.0,
            [
                183, 115, 0, 156, 201, 184, 78, 200, 115, 134, 248, 59, 135, 111, 8, 72, 117, 91,
                184, 108, 172, 227, 189, 222, 189, 255, 186, 158, 49, 21, 190, 61
            ]
        );
        assert_eq!(structure.bytes.as_ref(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x15\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(canonical.bytes.len(), 172);
        assert_eq!(
            canonical.id.0,
            [
                1, 237, 112, 216, 8, 96, 212, 129, 1, 57, 234, 121, 151, 226, 123, 201, 163, 24,
                246, 91, 51, 192, 149, 123, 247, 200, 75, 154, 252, 75, 85, 179
            ]
        );
    }

    #[test]
    fn flight_capture_requires_all_source_completeness_flags() {
        let limits = QuicFlightCaptureLimits::default();
        for flag in 0..7 {
            let mut source = observation();
            match flag {
                0 => source.completeness.datagrams = false,
                1 => source.completeness.frames = false,
                2 => source.completeness.client_hello = false,
                3 => source.completeness.transport_parameters = false,
                4 => source.completeness.original_attempt = false,
                5 => source.first_flight.as_mut().unwrap().complete = false,
                _ => source.first_flight = None,
            }
            QuicFlightCapture::capture(&source, limits).unwrap_err();
        }
        let mut source = observation();
        source.transport_parameters.clear();
        QuicFlightCapture::capture(&source, limits).unwrap_err();
        let mut capture = capture();
        capture.completeness = ProfileCaptureCompleteness::Incomplete;
        capture.canonical(limits).unwrap_err();
    }

    #[test]
    fn flight_limits_apply_before_retention_to_each_nested_collection() {
        let source = observation();
        let limits = QuicFlightCaptureLimits::default();
        for limits in [
            QuicFlightCaptureLimits {
                observed_bytes: 1199,
                ..limits
            },
            QuicFlightCaptureLimits {
                datagrams: 0,
                ..limits
            },
            QuicFlightCaptureLimits {
                packets: 0,
                ..limits
            },
            QuicFlightCaptureLimits {
                frames: 1,
                ..limits
            },
            QuicFlightCaptureLimits {
                parameters: 0,
                ..limits
            },
        ] {
            QuicFlightCapture::capture(&source, limits).unwrap_err();
        }
        QuicFlightCapture::capture(
            &source,
            QuicFlightCaptureLimits {
                observed_bytes: 1200,
                ..limits
            },
        )
        .unwrap();
        let mut capture = capture();
        capture.flight.datagram_sizes[0] = kib(32);
        let encoded = capture
            .canonical(QuicFlightCaptureLimits {
                bytes: kib(1),
                ..limits
            })
            .unwrap();
        QuicFlightCapture::from_canonical(
            &encoded,
            QuicFlightCaptureLimits {
                bytes: kib(1),
                ..limits
            },
        )
        .unwrap();
        capture.flight.frames[0].push(ObservedFrame::Ping);
        capture
            .canonical(QuicFlightCaptureLimits {
                frames: 2,
                ..limits
            })
            .unwrap_err();
    }

    #[test]
    fn flight_rejects_inconsistent_lengths_numbers_and_version_context() {
        let limits = QuicFlightCaptureLimits::default();
        for case in 0..14 {
            let mut capture = capture();
            let flight = &mut capture.flight;
            match case {
                0 => flight.trailing_bytes.clear(),
                1 => flight.trailing_bytes[0] = 1201,
                2 => flight.datagram_sizes[0] = 0,
                3 => flight.dcid_len = 21,
                4 => flight.packet_number_len = 0,
                5 => flight.first_packet_number = 4,
                6 => flight.packet_numbers.push(4),
                7 => {
                    flight.first_packet_number = 1 << 62;
                    flight.packet_numbers[0] = 1 << 62;
                }
                8 => {
                    flight.frames[0][0] = ObservedFrame::Crypto {
                        offset: (1 << 62) - 1,
                        len: 1,
                    }
                }
                9 => flight.frames[0][0] = ObservedFrame::Other { ty: 1 << 62 },
                10 => flight.frames[0][0] = ObservedFrame::Padding { len: 0 },
                11 => flight.parameters.push(ParameterId(1)),
                12 => flight.parameters[0] = ParameterId(1 << 62),
                _ => flight.chosen_version = Some(Version::V2),
            }
            capture.canonical(limits).unwrap_err();
        }
        let mut capture = capture();
        capture.flight.packet_numbers.push(3);
        let value = capture.canonical(limits).unwrap();
        assert_eq!(
            QuicFlightCapture::from_canonical(&value, limits)
                .unwrap()
                .flight
                .packet_numbers,
            [3, 3]
        );
        capture
            .flight
            .parameters
            .push(ParameterId::VERSION_INFORMATION);
        capture.flight.chosen_version = Some(Version::V1);
        capture.flight.available_versions = vec![Version::V2, Version::V1];
        capture.canonical(limits).unwrap();
        capture.flight.available_versions = vec![Version::V2];
        capture.canonical(limits).unwrap_err();
    }

    #[test]
    fn flight_import_rejects_bad_envelopes_truncation_and_trailers() {
        let limits = QuicFlightCaptureLimits::default();
        let value = capture().canonical(limits).unwrap();
        for end in 0..value.bytes.len() {
            QuicFlightCapture::from_canonical(&resign(value.bytes[..end].to_vec()), limits)
                .unwrap_err();
        }
        let mut bytes = value.bytes.to_vec();
        bytes.push(0);
        QuicFlightCapture::from_canonical(&resign(bytes), limits).unwrap_err();
        let mut bad = value.clone();
        bad.id.0[0] ^= 1;
        QuicFlightCapture::from_canonical(&bad, limits).unwrap_err();
        for index in [14, 16, 17] {
            let mut bytes = value.bytes.to_vec();
            bytes[index] = 255;
            resign(bytes).validated_domain(limits.bytes).unwrap_err();
        }
    }

    #[test]
    fn flight_joint_slot_is_connection_owned() {
        let mut joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::QuicFirstFlight,
                value: capture()
                    .canonical(QuicFlightCaptureLimits::default())
                    .unwrap(),
            }]),
        };
        let limits = JointCaptureLimits::default();
        let value = joint.canonical(limits).unwrap();
        JointCapture::from_canonical(&value, limits).unwrap();
        joint
            .structural(limits)
            .unwrap()
            .validated_domain(limits.bytes)
            .unwrap();
        joint.level = CaptureLevel::Request;
        joint.canonical(limits).unwrap_err();
    }

    #[test]
    fn ten_thousand_flights_share_structures_without_discarding_raw_draws() {
        let limits = QuicFlightCaptureLimits::default();
        let mut first = None;
        let mut first_joint = None;
        let mut raw = BTreeSet::new();
        for index in 0..10_000_u64 {
            let mut captured = capture();
            let flight = &mut captured.flight;
            flight.datagram_sizes[0] += (index % 17) as usize;
            flight.token_len = 1 + (index % 32) as usize;
            flight.first_packet_number = index + 3;
            flight.packet_numbers = vec![index + 3; 1 + (index % 3) as usize];
            flight.frames[0] = vec![
                ObservedFrame::Crypto {
                    offset: 0,
                    len: 50 + (index % 50) as usize,
                },
                ObservedFrame::Crypto {
                    offset: 50 + index % 50,
                    len: 100 + (index % 100) as usize,
                },
                ObservedFrame::Padding {
                    len: 700 + (index % 100) as usize,
                },
            ];
            flight.parameters = vec![
                ParameterId(1),
                ParameterId::VERSION_INFORMATION,
                ParameterId(31 * (index + 1) + 27),
            ];
            flight.parameters.rotate_left((index % 3) as usize);
            flight.chosen_version = Some(Version::V1);
            flight.available_versions = vec![Version::V1, Version::V2];
            flight.available_versions.insert(
                (index % 3) as usize,
                Version::from_u32(0x0a0a_0a0a | ((index % 16) as u32 * 0x1010_1010)),
            );
            let value = captured.canonical(limits).unwrap();
            let structure = captured.structural(limits).unwrap();
            structure.validated_domain(limits.bytes).unwrap();
            assert_eq!(*first.get_or_insert(structure.id), structure.id);
            raw.insert(value.id);
            let joint = JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::QuicFirstFlight,
                    value,
                }]
                .into(),
            };
            let structure = joint.structural(JointCaptureLimits::default()).unwrap();
            assert_eq!(*first_joint.get_or_insert(structure.id), structure.id);
        }
        assert_eq!(raw.len(), 10_000);
    }

    #[test]
    fn flight_structures_keep_client_choices_and_known_version_preference() {
        let limits = QuicFlightCaptureLimits::default();
        let base = capture();
        let expected = base.structural(limits).unwrap();
        for case in 0..7 {
            let mut changed = base.clone();
            match case {
                0 => changed.flight.version = Version::V2,
                1 => changed.flight.dcid_len = 7,
                2 => changed.flight.scid_len += 1,
                3 => changed.flight.packet_number_len += 1,
                4 => changed.flight.token_len = 1,
                5 => changed.flight.coalesced = true,
                _ => changed.flight.frames[0].push(ObservedFrame::Ping),
            }
            assert_ne!(expected.id, changed.structural(limits).unwrap().id);
        }
        let mut versions = base;
        versions
            .flight
            .parameters
            .push(ParameterId::VERSION_INFORMATION);
        versions.flight.chosen_version = Some(Version::V1);
        versions.flight.available_versions = vec![Version::V1, Version::V2];
        let ordered = versions.structural(limits).unwrap();
        versions.flight.available_versions.reverse();
        assert_ne!(ordered.id, versions.structural(limits).unwrap().id);
    }

    #[test]
    fn firefox_connection_id_draws_share_flight_and_joint_structures() {
        // Four Firefox 157.0.1 loopback connections, captured before authentication.
        // The fixture contains flight metadata only, without ClientHello or CID bytes.
        let flights: Vec<FirstFlight> =
            serde_json::from_str(include_str!("firefox_flights.json")).unwrap();
        assert_eq!(flights.len(), 4);
        assert_eq!(
            flights
                .iter()
                .map(|flight| flight.dcid_len)
                .collect::<Vec<_>>(),
            [12, 8, 9, 14]
        );
        let limits = QuicFlightCaptureLimits::default();
        let mut literals = BTreeSet::new();
        let mut structures = BTreeSet::new();
        let mut joints = BTreeSet::new();
        for flight in flights {
            let captured = QuicFlightCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                flight,
            };
            let literal = captured.canonical(limits).unwrap();
            let restored = QuicFlightCapture::from_canonical(&literal, limits).unwrap();
            assert_eq!(
                serde_json::to_value(&restored.flight).unwrap(),
                serde_json::to_value(&captured.flight).unwrap()
            );
            literals.insert(literal.id);
            let structure = captured.structural(limits).unwrap();
            QuicFlightCapture::validate_structure(&structure, limits).unwrap();
            structures.insert(structure.id);
            let joint = JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::QuicFirstFlight,
                    value: literal,
                }]
                .into(),
            };
            joints.insert(joint.structural(JointCaptureLimits::default()).unwrap().id);
        }
        assert_eq!(literals.len(), 4);
        assert_eq!(structures.len(), 1);
        assert_eq!(joints.len(), 1);
    }

    #[test]
    fn cid_length_classes_preserve_literal_draws_and_routing_choices() {
        let limits = QuicFlightCaptureLimits::default();
        for version in [Version::V1, Version::V2] {
            let mut expected = None;
            for dcid in 8..=20 {
                for scid in 1..=20 {
                    let mut captured = capture();
                    captured.flight.version = version;
                    captured.flight.dcid_len = dcid;
                    captured.flight.scid_len = scid;
                    let literal = captured.canonical(limits).unwrap();
                    let restored = QuicFlightCapture::from_canonical(&literal, limits).unwrap();
                    assert_eq!(restored.flight.dcid_len, dcid);
                    assert_eq!(restored.flight.scid_len, scid);
                    let structure = captured.structural(limits).unwrap();
                    QuicFlightCapture::validate_structure(&structure, limits).unwrap();
                    assert_eq!(*expected.get_or_insert(structure.id), structure.id);
                }
            }
            let mut captured = capture();
            captured.flight.version = version;
            assert_ne!(expected.unwrap(), captured.structural(limits).unwrap().id);
            captured.flight.scid_len = 1;
            for dcid in 0..8 {
                captured.flight.dcid_len = dcid;
                assert_ne!(expected.unwrap(), captured.structural(limits).unwrap().id);
            }
        }
    }

    #[test]
    fn flight_structure_import_rejects_unclassified_cid_lengths() {
        let limits = QuicFlightCaptureLimits::default();
        let value = capture().structural(limits).unwrap();
        // The canonical domain/version prefix is followed by QUIC version and CID classes.
        for (offset, lengths) in [(21, 9..=20u64), (29, 2..=20u64)] {
            for length in lengths {
                let mut bytes = value.bytes.to_vec();
                bytes[offset..offset + 8].copy_from_slice(&length.to_be_bytes());
                QuicFlightCapture::validate_structure(&resign(bytes), limits).unwrap_err();
            }
        }
    }

    #[test]
    fn flight_import_rejects_noncanonical_runs_and_padding_placement() {
        let limits = QuicFlightCaptureLimits::default();
        for case in 0..9 {
            let mut captured = capture();
            match case {
                0 => captured.flight.frames[0].push(ObservedFrame::Padding { len: 1 }),
                1 => {
                    captured.flight.padding = PaddingPlacement::DatagramTail;
                    captured.flight.trailing_bytes[0] = captured.flight.datagram_sizes[0];
                }
                2 => captured.flight.padding = PaddingPlacement::DatagramTail,
                3 => captured.flight.trailing_bytes[0] = 1,
                4 => captured.flight.frames[0].clear(),
                case => {
                    captured.flight.frames[0][0] = ObservedFrame::Other {
                        ty: [0, 1, 2, 6][case - 5],
                    }
                }
            }
            captured.canonical(limits).unwrap_err();
        }
        let mut captured = capture();
        captured.flight.padding = PaddingPlacement::DatagramTail;
        captured.flight.trailing_bytes[0] = 1;
        let value = captured.canonical(limits).unwrap();
        QuicFlightCapture::from_canonical(&value, limits).unwrap();
    }

    #[test]
    fn flight_structure_decoder_checks_bounds_canonicality_and_truncation() {
        let limits = QuicFlightCaptureLimits::default();
        let value = capture().structural(limits).unwrap();
        for end in 0..value.bytes.len() {
            QuicFlightCapture::validate_structure(&resign(value.bytes[..end].to_vec()), limits)
                .unwrap_err();
        }
        let mut bytes = value.bytes.to_vec();
        bytes.push(0);
        QuicFlightCapture::validate_structure(&resign(bytes), limits).unwrap_err();
        for limits in [
            QuicFlightCaptureLimits {
                packets: 0,
                ..limits
            },
            QuicFlightCaptureLimits {
                frames: 1,
                ..limits
            },
            QuicFlightCaptureLimits {
                parameters: 0,
                ..limits
            },
            QuicFlightCaptureLimits {
                bytes: value.bytes.len() - 1,
                ..limits
            },
        ] {
            QuicFlightCapture::validate_structure(&value, limits).unwrap_err();
        }
    }

    #[test]
    fn chromium_chaos_layouts_share_structure_without_losing_frame_evidence() {
        // Chrome 154.0.8037.98: six fresh loopback connections, two Initials each.
        // Only public wire frame types, offsets and lengths are retained here.
        const PACKETS: &[&[(u64, u64, usize)]] = &[
            &[
                (6, 0, 55),
                (6, 1099, 197),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 1011, 88),
                (0, 0, 3),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 9),
                (1, 0, 0),
                (0, 0, 107),
                (1, 0, 0),
                (0, 0, 1),
                (1, 0, 0),
                (0, 0, 1),
                (6, 55, 18),
                (0, 0, 129),
                (1, 0, 0),
                (6, 1296, 576),
            ],
            &[
                (0, 0, 27),
                (1, 0, 0),
                (0, 0, 217),
                (6, 1009, 1),
                (0, 0, 1),
                (6, 897, 112),
                (6, 73, 824),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 5),
                (1, 0, 0),
                (6, 1010, 1),
                (0, 0, 4),
            ],
            &[
                (0, 0, 212),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 47, 9),
                (0, 0, 9),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 1015, 733),
                (6, 0, 9),
                (6, 9, 15),
                (0, 0, 8),
                (1, 0, 0),
                (6, 24, 23),
                (6, 1748, 166),
                (1, 0, 0),
                (1, 0, 0),
            ],
            &[
                (6, 758, 32),
                (0, 0, 62),
                (6, 790, 20),
                (1, 0, 0),
                (0, 0, 2),
                (6, 810, 205),
                (1, 0, 0),
                (0, 0, 11),
                (6, 56, 702),
                (0, 0, 161),
            ],
            &[
                (6, 3, 11),
                (0, 0, 30),
                (6, 82, 1),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 162),
                (1, 0, 0),
                (6, 21, 39),
                (1, 0, 0),
                (6, 65, 16),
                (0, 0, 5),
                (1, 0, 0),
                (1, 0, 0),
                (6, 63, 1),
                (6, 2, 1),
                (6, 0, 2),
                (6, 81, 1),
                (6, 14, 7),
                (0, 0, 16),
                (6, 1040, 869),
                (6, 60, 3),
                (6, 64, 1),
                (1, 0, 0),
                (1, 0, 0),
            ],
            &[
                (0, 0, 131),
                (6, 313, 212),
                (0, 0, 65),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 843, 93),
                (0, 0, 12),
                (6, 525, 256),
                (6, 781, 2),
                (6, 783, 60),
                (6, 83, 230),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 936, 104),
                (0, 0, 9),
            ],
            &[
                (1, 0, 0),
                (1, 0, 0),
                (1, 0, 0),
                (6, 65, 4),
                (6, 62, 1),
                (0, 0, 181),
                (6, 1030, 169),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 5),
                (6, 46, 13),
                (6, 0, 46),
                (1, 0, 0),
                (6, 1199, 711),
                (6, 63, 2),
                (0, 0, 33),
                (6, 59, 3),
                (1, 0, 0),
                (0, 0, 3),
                (6, 69, 4),
            ],
            &[
                (1, 0, 0),
                (0, 0, 4),
                (6, 77, 367),
                (0, 0, 165),
                (1, 0, 0),
                (0, 0, 2),
                (1, 0, 0),
                (0, 0, 39),
                (1, 0, 0),
                (6, 461, 145),
                (1, 0, 0),
                (6, 660, 200),
                (0, 0, 3),
                (1, 0, 0),
                (6, 73, 4),
                (1, 0, 0),
                (6, 444, 17),
                (0, 0, 4),
                (6, 860, 170),
                (1, 0, 0),
                (6, 606, 54),
            ],
            &[
                (0, 0, 36),
                (6, 1310, 429),
                (0, 0, 8),
                (6, 1309, 1),
                (1, 0, 0),
                (0, 0, 130),
                (6, 1039, 99),
                (0, 0, 17),
                (1, 0, 0),
                (6, 1739, 207),
                (0, 0, 18),
                (6, 1186, 123),
                (6, 0, 64),
                (0, 0, 1),
                (6, 1138, 48),
            ],
            &[
                (6, 629, 116),
                (0, 0, 1),
                (6, 745, 294),
                (0, 0, 65),
                (1, 0, 0),
                (6, 219, 230),
                (0, 0, 128),
                (1, 0, 0),
                (6, 64, 24),
                (6, 88, 131),
                (0, 0, 9),
                (6, 539, 90),
                (6, 449, 90),
            ],
            &[
                (0, 0, 198),
                (6, 1065, 810),
                (0, 0, 24),
                (6, 42, 16),
                (1, 0, 0),
                (1, 0, 0),
                (6, 76, 3),
                (6, 8, 4),
                (1, 0, 0),
                (0, 0, 21),
                (6, 0, 8),
                (1, 0, 0),
                (6, 58, 18),
                (6, 1019, 46),
                (1, 0, 0),
                (6, 12, 30),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 2),
            ],
            &[
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 17),
                (6, 714, 305),
                (1, 0, 0),
                (1, 0, 0),
                (0, 0, 10),
                (6, 79, 207),
                (0, 0, 191),
                (1, 0, 0),
                (0, 0, 1),
                (6, 494, 220),
                (6, 286, 208),
                (0, 0, 30),
            ],
        ];
        let limits = QuicFlightCaptureLimits::default();
        let mut structures = BTreeSet::new();
        let mut literals = BTreeSet::new();
        for packets in PACKETS.as_chunks::<2>().0 {
            let mut captured = capture();
            captured.flight.datagram_sizes = vec![1250, 1250];
            captured.flight.trailing_bytes = vec![0, 0];
            captured.flight.first_packet_number = 1;
            captured.flight.packet_numbers = vec![1, 2];
            captured.flight.packet_number_len = 1;
            captured.flight.frames = packets
                .iter()
                .map(|packet| {
                    packet
                        .iter()
                        .map(|&(ty, offset, len)| match ty {
                            0 => ObservedFrame::Padding { len },
                            1 => ObservedFrame::Ping,
                            6 => ObservedFrame::Crypto { offset, len },
                            _ => panic!("unexpected fixture frame"),
                        })
                        .collect()
                })
                .collect();
            let value = captured.canonical(limits).unwrap();
            let restored = QuicFlightCapture::from_canonical(&value, limits).unwrap();
            assert_eq!(
                serde_json::to_value(&restored.flight.frames).unwrap(),
                serde_json::to_value(&captured.flight.frames).unwrap()
            );
            literals.insert(value.id);
            let structure = captured.structural(limits).unwrap();
            QuicFlightCapture::validate_structure(&structure, limits).unwrap();
            structures.insert(structure.id);
        }
        assert_eq!(literals.len(), 6);
        assert_eq!(structures.len(), 1);
        let mut changed = capture();
        let before = changed.structural(limits).unwrap();
        changed.flight.datagram_sizes.push(1200);
        changed.flight.trailing_bytes.push(0);
        assert_ne!(before.id, changed.structural(limits).unwrap().id);
    }
}
