//! Validated layouts for an original client Initial burst.
//!
//! Only packet metadata is retained. The engine supplies fresh TLS bytes,
//! connection identifiers, tokens and packet protection for each connection.
//! Later retransmissions and other packet spaces keep ordinary packetization.

use alloc::{sync::Arc, vec::Vec};
use core::{fmt, marker::PhantomData};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};

use super::{PacketizationProfile, ProfileError};
use crate::{MAX_CID_SIZE, MIN_INITIAL_DCID_SIZE, VarInt, Version, packet::PacketNumber};

// Admission budgets for executable layout metadata, independent of receive limits.
const MAX_PACKETS: usize = 16;
const MAX_FRAMES: usize = 256;
const MAX_CRYPTO_BYTES: usize = 65_536;

/// A frame shape containing no connection-owned bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InitialFrame {
    /// A slice of the current handshake's Initial CRYPTO stream.
    Crypto {
        offset: u64,
        len: usize,
    },
    Ping,
    Padding {
        len: usize,
    },
}

/// One original Initial packet, alone in its datagram.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PacketData")]
pub struct InitialPacket {
    number: u64,
    number_len: u8,
    datagram_size: u16,
    frames: Vec<InitialFrame>,
}

#[derive(Deserialize)]
struct PacketData {
    number: u64,
    number_len: u8,
    datagram_size: u16,
    #[serde(deserialize_with = "bounded_sequence::<_, _, MAX_FRAMES>")]
    frames: Vec<InitialFrame>,
}

impl TryFrom<PacketData> for InitialPacket {
    type Error = ProfileError;

    fn try_from(data: PacketData) -> Result<Self, Self::Error> {
        PacketizationProfile::standard().try_with_initial_datagram_size(data.datagram_size)?;
        if PacketNumber::new(data.number, 0).is_none()
            || !(1..=4).contains(&data.number_len)
            || data.frames.len() > MAX_FRAMES
        {
            return Err(ProfileError::InitialFlight(
                "packet geometry or frame budget",
            ));
        }
        let mut crypto = false;
        for frame in &data.frames {
            match frame {
                InitialFrame::Crypto { offset, len } => {
                    crypto = true;
                    if *len == 0
                        || offset
                            .checked_add(*len as u64)
                            .is_none_or(|end| end > MAX_CRYPTO_BYTES as u64)
                    {
                        return Err(ProfileError::InitialFlight("CRYPTO range"));
                    }
                }
                InitialFrame::Padding { len } if *len == 0 || *len > MAX_CRYPTO_BYTES => {
                    return Err(ProfileError::InitialFlight("PADDING length"));
                }
                _ => {}
            }
        }
        let packet = Self {
            number: data.number,
            number_len: data.number_len,
            datagram_size: data.datagram_size,
            frames: data.frames,
        };
        if !crypto || packet.payload_len() >= usize::from(packet.datagram_size) {
            return Err(ProfileError::InitialFlight(
                "packet must carry CRYPTO within its datagram",
            ));
        }
        Ok(packet)
    }
}

impl InitialPacket {
    /// Admit one packet's metadata; native preparation later checks its exact
    /// header and protection overhead against the current connection.
    pub fn try_new(
        number: u64,
        number_len: u8,
        datagram_size: u16,
        frames: Vec<InitialFrame>,
    ) -> Result<Self, ProfileError> {
        PacketData {
            number,
            number_len,
            datagram_size,
            frames,
        }
        .try_into()
    }

    /// The full Initial packet number.
    #[must_use]
    pub fn number(&self) -> u64 {
        self.number
    }

    /// Encoded packet-number width, in bytes.
    #[must_use]
    pub fn number_len(&self) -> u8 {
        self.number_len
    }

    /// Complete UDP payload size, in bytes.
    #[must_use]
    pub fn datagram_size(&self) -> u16 {
        self.datagram_size
    }

    /// Frame shapes in their retained wire order.
    #[must_use]
    pub fn frames(&self) -> &[InitialFrame] {
        &self.frames
    }

    /// Encoded frame bytes, using the protocol's minimal integer encodings.
    pub fn payload_len(&self) -> usize {
        self.frames
            .iter()
            .map(|frame| match frame {
                InitialFrame::Crypto { offset, len } => {
                    1 + VarInt::from_u32(*offset as u32).size()
                        + VarInt::from_u32(*len as u32).size()
                        + len
                }
                InitialFrame::Ping => 1,
                InitialFrame::Padding { len } => *len,
            })
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct FlightData {
    version: Version,
    destination_cid_len: u8,
    source_cid_len: u8,
    #[serde(deserialize_with = "bounded_sequence::<_, _, MAX_PACKETS>")]
    packets: Vec<InitialPacket>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct ValidatedFlight {
    wire: FlightData,
    crypto_len: usize,
}

/// Immutable, bounded metadata for a tokenless original Initial burst.
///
/// Construction admits consecutive packet numbers, one packet per datagram,
/// and CRYPTO/PING/PADDING frames with complete, non-overlapping CRYPTO coverage.
/// Unsupported token, coalescing and frame shapes require another replay policy.
/// Clones share the validated layout; no handshake bytes are stored here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordedInitialFlight(Arc<ValidatedFlight>);

impl RecordedInitialFlight {
    /// Admit a uniform-sized original burst with complete CRYPTO coverage.
    /// CID lengths describe expected fresh bindings; no CID values are retained.
    pub fn try_new(
        version: Version,
        destination_cid_len: u8,
        source_cid_len: u8,
        packets: Vec<InitialPacket>,
    ) -> Result<Self, ProfileError> {
        Self::validate(FlightData {
            version,
            destination_cid_len,
            source_cid_len,
            packets,
        })
    }

    /// Version used by the original Initial burst.
    #[must_use]
    pub fn version(&self) -> Version {
        self.0.wire.version
    }

    /// Expected fresh destination connection ID length, in bytes.
    #[must_use]
    pub fn destination_cid_len(&self) -> u8 {
        self.0.wire.destination_cid_len
    }

    /// Expected fresh source connection ID length, in bytes.
    #[must_use]
    pub fn source_cid_len(&self) -> u8 {
        self.0.wire.source_cid_len
    }

    /// Original Initial packets in transmission order.
    #[must_use]
    pub fn packets(&self) -> &[InitialPacket] {
        &self.0.wire.packets
    }

    /// Required extent of the fresh Initial CRYPTO stream, in bytes.
    #[must_use]
    pub fn crypto_len(&self) -> usize {
        self.0.crypto_len
    }

    /// Match an original packet number without a separate replay cursor.
    pub fn packet(&self, number: u64) -> Option<&InitialPacket> {
        let first = self.0.wire.packets.first()?;
        let index = usize::try_from(number.checked_sub(first.number)?).ok()?;
        self.0.wire.packets.get(index)
    }

    fn validate(wire: FlightData) -> Result<Self, ProfileError> {
        if wire.packets.is_empty() || wire.packets.len() > MAX_PACKETS {
            return Err(ProfileError::InitialFlight("packet budget"));
        }
        if wire.version.to_wire().is_none()
            || !(MIN_INITIAL_DCID_SIZE..=MAX_CID_SIZE)
                .contains(&usize::from(wire.destination_cid_len))
            || usize::from(wire.source_cid_len) > MAX_CID_SIZE
        {
            return Err(ProfileError::InitialFlight(
                "version or connection identifier lengths",
            ));
        }
        let first = wire.packets[0].number;
        let mut ranges = Vec::new();
        let mut frame_count = 0usize;
        for (index, packet) in wire.packets.iter().enumerate() {
            if first.checked_add(index as u64) != Some(packet.number)
                || packet.datagram_size != wire.packets[0].datagram_size
            {
                return Err(ProfileError::InitialFlight(
                    "packet number or datagram geometry",
                ));
            }
            frame_count = frame_count
                .checked_add(packet.frames.len())
                .ok_or(ProfileError::InitialFlight("frame budget"))?;
            if frame_count > MAX_FRAMES {
                return Err(ProfileError::InitialFlight("frame budget"));
            }
            let previous = ranges.len();
            for frame in &packet.frames {
                match frame {
                    InitialFrame::Crypto { offset, len } => {
                        let start = usize::try_from(*offset)
                            .map_err(|_error| ProfileError::InitialFlight("CRYPTO range"))?;
                        let end = start
                            .checked_add(*len)
                            .filter(|end| *len != 0 && *end <= MAX_CRYPTO_BYTES)
                            .ok_or(ProfileError::InitialFlight("CRYPTO range"))?;
                        ranges.push((start, end));
                    }
                    InitialFrame::Padding { len } if *len == 0 || *len > MAX_CRYPTO_BYTES => {
                        return Err(ProfileError::InitialFlight("PADDING length"));
                    }
                    _ => {}
                }
            }
            if ranges.len() == previous || packet.payload_len() >= usize::from(packet.datagram_size)
            {
                return Err(ProfileError::InitialFlight(
                    "packet must carry CRYPTO within its datagram",
                ));
            }
        }
        ranges.sort_unstable();
        let mut end = 0;
        for (start, next) in ranges {
            if start != end {
                return Err(ProfileError::InitialFlight(
                    "CRYPTO coverage has an overlap or gap",
                ));
            }
            end = next;
        }
        Ok(Self(Arc::new(ValidatedFlight {
            wire,
            crypto_len: end,
        })))
    }
}

impl Serialize for RecordedInitialFlight {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecordedInitialFlight {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::validate(FlightData::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "std")]
impl TryFrom<&crate::capture::FirstFlight> for RecordedInitialFlight {
    type Error = ProfileError;

    fn try_from(flight: &crate::capture::FirstFlight) -> Result<Self, Self::Error> {
        use crate::{capture::ObservedFrame, profile::PaddingPlacement};

        if !flight.complete
            || flight.token_len != 0
            || flight.coalesced
            || flight.padding != PaddingPlacement::Frames
            || flight.frames.is_empty()
            || flight.frames.len() > MAX_PACKETS
            || flight.frames.len() != flight.datagram_sizes.len()
            || flight.frames.len() != flight.packet_numbers.len()
            || flight.frames.len() != flight.packet_number_lengths.len()
            || flight.trailing_bytes.len() != flight.datagram_sizes.len()
            || flight.trailing_bytes.iter().any(|tail| *tail != 0)
            || flight.packet_numbers.first() != Some(&flight.first_packet_number)
            || flight.packet_number_lengths.first() != Some(&flight.packet_number_len)
        {
            return Err(ProfileError::InitialFlight(
                "unsupported or incomplete original burst",
            ));
        }
        if flight
            .frames
            .iter()
            .try_fold(0usize, |sum, frames| sum.checked_add(frames.len()))
            .is_none_or(|count| count > MAX_FRAMES)
        {
            return Err(ProfileError::InitialFlight("frame budget"));
        }
        let mut packets = Vec::with_capacity(flight.frames.len());
        for (index, frames) in flight.frames.iter().enumerate() {
            let frames = frames
                .iter()
                .map(|frame| match frame {
                    ObservedFrame::Crypto { offset, len } => Ok(InitialFrame::Crypto {
                        offset: *offset,
                        len: *len,
                    }),
                    ObservedFrame::Ping => Ok(InitialFrame::Ping),
                    ObservedFrame::Padding { len } => Ok(InitialFrame::Padding { len: *len }),
                    _ => Err(ProfileError::InitialFlight("unsupported original frame")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            packets.push(InitialPacket::try_from(PacketData {
                number: flight.packet_numbers[index],
                number_len: flight.packet_number_lengths[index],
                datagram_size: u16::try_from(flight.datagram_sizes[index])
                    .map_err(|_error| ProfileError::InitialFlight("datagram size"))?,
                frames,
            })?);
        }
        Self::validate(FlightData {
            version: flight.version,
            destination_cid_len: u8::try_from(flight.dcid_len)
                .map_err(|_error| ProfileError::InitialFlight("destination CID length"))?,
            source_cid_len: u8::try_from(flight.scid_len)
                .map_err(|_error| ProfileError::InitialFlight("source CID length"))?,
            packets,
        })
    }
}

/// Bound allocation while decoding, before the full layout can be validated.
/// Frames contain only numeric metadata, and each packet's frame list is bounded.
fn bounded_sequence<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Items<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Items<T, MAX> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} recorded Initial metadata items")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|count| count > MAX) {
                return Err(A::Error::custom("recorded Initial metadata item budget"));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(A::Error::custom("recorded Initial metadata item budget"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(Items::<T, MAX>(PhantomData))
}

#[cfg(test)]
mod tests;
