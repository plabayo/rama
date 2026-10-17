//! Group connection-owned lengths and draws without changing retained samples.

use std::collections::BTreeSet;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Shape {
    version: u32,
    dcid: usize,
    scid: usize,
    pn_widths: Vec<u8>,
    token: bool,
    padding: u8,
    coalesced: bool,
    datagrams: usize,
    frames: Vec<Vec<u64>>,
    parameters: Vec<Option<u64>>,
    chosen: Option<u32>,
    versions: Vec<Option<u32>>,
}

impl Shape {
    fn capture(flight: &FirstFlight) -> Result<Self, ProfileDataError> {
        let mut parameters: Vec<_> = flight
            .parameters
            .iter()
            .map(|id| (!id.is_reserved()).then_some(id.0))
            .collect();
        parameters.sort_unstable();
        let mut versions: Vec<_> = flight
            .available_versions
            .iter()
            .map(|version| {
                let id = version.as_u32();
                (Some(*version) == flight.chosen_version || !version.is_reserved()).then_some(id)
            })
            .collect();
        // Reserved placement is generated; known-version preference remains literal.
        versions.sort_by_key(|version| version.is_none());
        Ok(Self {
            version: flight.version.as_u32(),
            // RFC 9000 §7.2: an original client DCID is at least eight bytes.
            // Its exact length is a connection draw retained in the literal sample.
            dcid: flight.dcid_len.min(8),
            // Zero-length CIDs disable CID-based routing; nonzero lengths can vary.
            scid: usize::from(flight.scid_len != 0),
            pn_widths: flight
                .packet_numbers
                .iter()
                .enumerate()
                .filter(|(index, number)| !flight.packet_numbers[..*index].contains(number))
                .map(|(index, _)| flight.packet_number_lengths[index])
                .collect(),
            token: flight.token_len != 0,
            padding: match flight.padding {
                PaddingPlacement::Frames => 0,
                PaddingPlacement::DatagramTail => 1,
                _ => return Err(ProfileDataError::Unsupported("QUIC padding placement")),
            },
            coalesced: flight.coalesced,
            datagrams: flight.datagram_sizes.len(),
            frames: flight
                .frames
                .iter()
                .map(|packet| {
                    packet
                        .iter()
                        .map(|frame| match frame {
                            ObservedFrame::Padding { .. } => 0,
                            ObservedFrame::Ping => 1,
                            ObservedFrame::Ack => 2,
                            ObservedFrame::Crypto { .. } => 6,
                            ObservedFrame::Other { ty } => *ty,
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                })
                .collect(),
            parameters,
            chosen: flight.chosen_version.map(|version| version.as_u32()),
            versions,
        })
    }

    fn encode(&self, limits: QuicFlightCaptureLimits) -> Result<CanonicalValue, ProfileDataError> {
        self.validate(limits)?;
        let mut writer = CanonicalWriter::new(CanonicalDomain::QuicFlightStructure, limits.bytes)?;
        writer.u32(self.version)?;
        writer.u64(self.dcid as u64)?;
        writer.u64(self.scid as u64)?;
        writer.u64(self.pn_widths.len() as u64)?;
        for width in &self.pn_widths {
            writer.u8(*width)?;
        }
        writer.u8(u8::from(self.token))?;
        writer.u8(self.padding)?;
        writer.u8(u8::from(self.coalesced))?;
        writer.u64(self.datagrams as u64)?;
        writer.u64(self.frames.len() as u64)?;
        for packet in &self.frames {
            writer.u64(packet.len() as u64)?;
            for frame in packet {
                writer.u64(*frame)?;
            }
        }
        writer.u64(self.parameters.len() as u64)?;
        for id in &self.parameters {
            writer.u8(u8::from(id.is_some()))?;
            if let Some(id) = id {
                writer.u64(*id)?;
            }
        }
        writer.u8(u8::from(self.chosen.is_some()))?;
        if let Some(chosen) = self.chosen {
            writer.u32(chosen)?;
        }
        writer.u64(self.versions.len() as u64)?;
        for version in &self.versions {
            writer.u8(u8::from(version.is_some()))?;
            if let Some(version) = version {
                writer.u32(*version)?;
            }
        }
        Ok(writer.finish())
    }

    fn validate(&self, limits: QuicFlightCaptureLimits) -> Result<(), ProfileDataError> {
        if self.version == 0
            || self.dcid > 8
            || self.scid > 1
            || self.pn_widths.len() != self.frames.len()
            || self.pn_widths.iter().any(|width| !(1..=4).contains(width))
            || self.padding > 1
            || self.frames.is_empty()
            || self.datagrams == 0
        {
            return Err(ProfileDataError::Invalid("QUIC flight structural shape"));
        }
        if self.datagrams > limits.datagrams
            || self.frames.len() > limits.packets
            || self.parameters.len() > limits.parameters
            || self.versions.len() > limits.parameters
        {
            return Err(ProfileDataError::LimitExceeded(
                "QUIC flight structure elements",
            ));
        }
        let mut remaining = limits.frames;
        for packet in &self.frames {
            remaining =
                remaining
                    .checked_sub(packet.len())
                    .ok_or(ProfileDataError::LimitExceeded(
                        "QUIC flight structure frames",
                    ))?;
            if packet.is_empty()
                || packet.iter().any(|ty| *ty >= (1 << 62) || *ty == 3)
                || packet.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(ProfileDataError::Invalid("QUIC flight structural frames"));
            }
        }
        if self
            .parameters
            .windows(2)
            .any(|pair| pair[0] > pair[1] || (pair[0].is_some() && pair[0] == pair[1]))
            || self
                .parameters
                .iter()
                .flatten()
                .any(|id| *id >= (1 << 62) || ParameterId(*id).is_reserved())
        {
            return Err(ProfileDataError::Invalid("QUIC structural parameters"));
        }
        let mut reserved = false;
        for version in &self.versions {
            if let Some(version) = version {
                if reserved
                    || *version == 0
                    || (Some(*version) != self.chosen && Version::from_u32(*version).is_reserved())
                {
                    return Err(ProfileDataError::Invalid("QUIC structural versions"));
                }
            } else {
                reserved = true;
            }
        }
        match self.chosen {
            Some(chosen)
                if chosen == self.version
                    && self
                        .parameters
                        .contains(&Some(ParameterId::VERSION_INFORMATION.0))
                    && self.versions.contains(&Some(chosen)) => {}
            None if self.versions.is_empty()
                && !self
                    .parameters
                    .contains(&Some(ParameterId::VERSION_INFORMATION.0)) => {}
            _ => return Err(ProfileDataError::Invalid("QUIC structural version context")),
        }
        Ok(())
    }
}

pub(super) fn encode(
    flight: &FirstFlight,
    limits: QuicFlightCaptureLimits,
) -> Result<CanonicalValue, ProfileDataError> {
    Shape::capture(flight)?.encode(limits)
}

pub(super) fn validate(
    value: &CanonicalValue,
    limits: QuicFlightCaptureLimits,
) -> Result<(), ProfileDataError> {
    value.verify(CanonicalDomain::QuicFlightStructure, limits.bytes)?;
    let mut reader = CanonicalReader::new(&value.bytes, CanonicalDomain::QuicFlightStructure)?;
    let version = reader.u32()?;
    let dcid = reader.count(20)?;
    let scid = reader.count(20)?;
    let mut pn_widths = Vec::new();
    for _ in 0..reader.count(limits.packets)? {
        pn_widths.push(reader.u8()?);
    }
    let token = flag(&mut reader)?;
    let padding = reader.u8()?;
    let coalesced = flag(&mut reader)?;
    let datagrams = reader.count(limits.datagrams)?;
    let mut frames = Vec::new();
    let mut remaining = limits.frames;
    for _ in 0..reader.count(limits.packets)? {
        let count = reader.count(remaining)?;
        remaining -= count;
        let mut packet = Vec::new();
        for _ in 0..count {
            packet.push(reader.u64()?);
        }
        frames.push(packet);
    }
    let mut parameters = Vec::new();
    for _ in 0..reader.count(limits.parameters)? {
        parameters.push(if flag(&mut reader)? {
            Some(reader.u64()?)
        } else {
            None
        });
    }
    let chosen = if flag(&mut reader)? {
        Some(reader.u32()?)
    } else {
        None
    };
    let mut versions = Vec::new();
    for _ in 0..reader.count(limits.parameters)? {
        versions.push(if flag(&mut reader)? {
            Some(reader.u32()?)
        } else {
            None
        });
    }
    reader.finish()?;
    let shape = Shape {
        version,
        dcid,
        scid,
        pn_widths,
        token,
        padding,
        coalesced,
        datagrams,
        frames,
        parameters,
        chosen,
        versions,
    };
    if shape.encode(limits)?.bytes != value.bytes {
        return Err(ProfileDataError::Invalid(
            "noncanonical QUIC flight structure",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_frame_sets_reject_duplicates_and_noncanonical_order() {
        let limits = QuicFlightCaptureLimits::default();
        let mut shape = Shape {
            version: 1,
            dcid: 8,
            scid: 0,
            pn_widths: vec![1],
            token: false,
            padding: 0,
            coalesced: false,
            datagrams: 1,
            frames: vec![vec![0, 1, 6]],
            parameters: Vec::new(),
            chosen: None,
            versions: Vec::new(),
        };
        let valid = shape.encode(limits).unwrap();
        validate(&valid, limits).unwrap();
        for frames in [vec![0, 0, 6], vec![6, 1, 0], vec![0, 3, 6], vec![1 << 62]] {
            shape.frames = vec![frames];
            shape.encode(limits).unwrap_err();
        }
    }
}
