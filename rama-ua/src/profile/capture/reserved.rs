//! Slots for reserved identifiers a client generates afresh per connection.
//!
//! A slot names the range the client draws from instead of one drawn value, so
//! captures that differ only in that draw are one value and a selection can draw
//! again. Reserved identifiers a client keeps constant are never slots.

use rama_http::proto::h3::FrameType;
use rama_quic_proto::{Version, transport_parameters::TransportParameterId};

/// Fewer ordinal bits than this do not show a generated identifier.
const MINIMUM_RUN: u8 = 15;
const MAXIMUM_ORDINAL_BITS: u8 = 4;
const RANGED: u8 = MAXIMUM_ORDINAL_BITS + 1;

/// Reserved identifiers of the form `base + step * ordinal`.
#[derive(Debug, Clone, Copy)]
pub(in crate::profile) enum ReservedFamily {
    TransportParameters,
    H3Frames,
}

/// QUIC transport parameters reserved to exercise unknown-parameter handling.
pub(in crate::profile) const TRANSPORT_PARAMETERS: ReservedFamily =
    ReservedFamily::TransportParameters;

/// HTTP/3 frame types reserved to exercise unknown-frame handling.
pub(in crate::profile) const H3_FRAMES: ReservedFamily = ReservedFamily::H3Frames;

/// How a client generates one reserved identifier and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::profile) struct ReservedSlot {
    /// Ordinals are drawn below two to this power.
    pub(in crate::profile) bits: u8,
    pub(in crate::profile) length: ReservedLength,
}

/// Where the payload length of a generated identifier comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::profile) enum ReservedLength {
    /// The length the capture holds.
    Captured,
    /// The value of this many low ordinal bits.
    Ordinal(u8),
    /// Drawn afresh, up to the length the capture holds.
    Ranged,
}

impl ReservedLength {
    /// Count of clear low bits in the slot's ordinal.
    fn code(self) -> Option<u8> {
        match self {
            Self::Captured => Some(0),
            Self::Ordinal(bits) => (1..=MAXIMUM_ORDINAL_BITS).contains(&bits).then_some(bits),
            Self::Ranged => Some(RANGED),
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Captured),
            RANGED => Some(Self::Ranged),
            bits => (bits <= MAXIMUM_ORDINAL_BITS).then_some(Self::Ordinal(bits)),
        }
    }
}

impl ReservedFamily {
    /// Position of a reserved identifier within its family.
    pub(in crate::profile) fn ordinal(self, id: u64) -> Option<u64> {
        match self {
            Self::TransportParameters => TransportParameterId::from(id).reserved_ordinal(),
            Self::H3Frames => FrameType::new(id).reserved_ordinal(),
        }
    }

    pub(in crate::profile) fn id(self, ordinal: u64) -> Option<u64> {
        match self {
            Self::TransportParameters => TransportParameterId::reserved(ordinal).map(u64::from),
            Self::H3Frames => FrameType::reserved(ordinal).map(FrameType::value),
        }
    }

    /// The slot's ordinal is a run of ones from the length's bit up to bit `bits - 2`,
    /// which stays a valid identifier for every range a client can draw from.
    pub(in crate::profile) fn slot_id(self, slot: ReservedSlot) -> Option<u64> {
        let code = slot.length.code()?;
        if slot.bits > 58 || slot.bits < code + MINIMUM_RUN + 1 {
            return None;
        }
        self.id((1 << (slot.bits - 1)) - (1 << code))
    }

    pub(in crate::profile) fn slot(self, id: u64) -> Option<ReservedSlot> {
        let ordinal = self.ordinal(id)?;
        let slot = ReservedSlot {
            bits: u8::try_from(u64::BITS - ordinal.leading_zeros()).ok()? + 1,
            length: ReservedLength::from_code(u8::try_from(ordinal.trailing_zeros()).ok()?)?,
        };
        (self.slot_id(slot) == Some(id)).then_some(slot)
    }

    /// A fresh identifier for the slot, or `None` when `random` falls outside the family.
    pub(in crate::profile) fn draw(self, slot: ReservedSlot, random: u64) -> Option<(u64, u64)> {
        let ordinal = random & ((1 << slot.bits) - 1);
        Some((self.id(ordinal)?, ordinal))
    }
}

/// Stands in for a QUIC version a client generates to exercise version negotiation.
// The slot is a value clients do not hardcode, unlike the repeated-byte members of the family.
pub(in crate::profile) const VERSION_SLOT: Version = Version::from_u32(0x1a2a_3a4a);

#[cfg(test)]
mod tests {
    use super::*;

    // Embedded profiles hold identifiers drawn from these families, so their values are pinned.
    #[test]
    fn families_keep_their_identifiers() {
        let maximum = (1 << 62) - 1;
        for (family, base, step) in [(TRANSPORT_PARAMETERS, 27, 31), (H3_FRAMES, 0x21, 0x1f)] {
            let maximum_ordinal = (maximum - base) / step;
            for ordinal in [0, 1, 1 << 40, maximum_ordinal] {
                let id = base + step * ordinal;
                assert_eq!(family.id(ordinal), Some(id));
                assert_eq!(family.ordinal(id), Some(ordinal));
            }
            assert_eq!(family.id(maximum_ordinal + 1), None);
            assert_eq!(family.ordinal(base + 1), None);
            assert_eq!(family.ordinal(base - 1), None);
        }
        assert_eq!(Version::reserved(0).as_u32(), 0x0a0a_0a0a);
        assert_eq!(Version::reserved(0x1234).as_u32(), 0x1a2a_3a4a);
        assert_eq!(Version::reserved(0xffff).as_u32(), 0xfafa_fafa);
    }
}
