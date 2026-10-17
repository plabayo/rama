mod structure;
// Bounded first-flight facts without connection identifiers or handshake bytes.

use crate::profile::{
    capture::completeness::ProfileCaptureCompleteness,
    format::canonical::{
        CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError,
    },
};
use rama_quic_proto::{
    Version,
    capture::{FirstFlight, ObservedFrame, QuicObservation},
    frame::FrameType,
    profile::{PaddingPlacement, ParameterId},
    version::VersionInformation,
};
use rama_utils::octets::kib;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
/// Resource limits for one retained QUIC first flight.
pub struct QuicFlightCaptureLimits {
    /// Maximum UDP datagrams in the captured first flight.
    pub datagrams: usize,
    /// Maximum Initial packets across those datagrams.
    pub packets: usize,
    /// Maximum observed frame shapes across those packets.
    pub frames: usize,
    /// Maximum transport parameter identifiers.
    pub parameters: usize,
    /// Maximum bytes represented by one retained shape value.
    pub observed_bytes: usize,
    /// Maximum bytes in the canonical capture.
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
    /// Whether every source component required by the capture was complete.
    pub completeness: ProfileCaptureCompleteness,
    /// Capture-safe first-flight layout and ordering facts.
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

    pub(in crate::profile) fn validate_structure(
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
        let mut packet_number_lengths = Vec::new();
        for _ in 0..reader.count(limits.packets)? {
            packet_number_lengths.push(reader.u8()?);
        }
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
                packet_number_lengths,
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
        || flight.packet_number_lengths.len() > limits.packets
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
        || flight.packet_number_lengths.len() != flight.packet_numbers.len()
        || flight.packet_number_lengths.first() != Some(&flight.packet_number_len)
        || flight
            .packet_number_lengths
            .iter()
            .any(|width| !(1..=4).contains(width))
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
                    if *ty >= (1 << 62)
                        || [
                            FrameType::PADDING,
                            FrameType::PING,
                            FrameType::ACK,
                            FrameType::ACK_ECN,
                            FrameType::CRYPTO,
                        ]
                        .iter()
                        .any(|known| known.as_u64() == *ty) =>
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
    writer.u64(flight.packet_number_lengths.len() as u64)?;
    for width in &flight.packet_number_lengths {
        writer.u8(*width)?;
    }
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
mod tests;
