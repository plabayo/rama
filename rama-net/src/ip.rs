//! Internet Protocol packet metadata.

/// Explicit Congestion Notification codepoint from the low two IP traffic-class bits.
///
/// RFC 8311 permits protocol-specific experimental use of ECT(1), so this type
/// exposes the codepoint without assigning transport behavior to it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// The sender is not ECN-capable (`00`).
    NotEct = 0b00,
    /// ECN Capable Transport (1) (`01`).
    Ect1 = 0b01,
    /// ECN Capable Transport (0) (`10`).
    Ect0 = 0b10,
    /// Congestion Experienced (`11`).
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Decode the low two bits of an IP traffic-class value.
    #[inline]
    #[must_use]
    pub const fn from_bits(value: u8) -> Self {
        match value & 0b11 {
            0b00 => Self::NotEct,
            0b01 => Self::Ect1,
            0b10 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// Return the two wire bits for this codepoint.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecn_ignores_dscp_bits() {
        assert_eq!(EcnCodepoint::from_bits(0b1111_1100), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_bits(0b1111_1101), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_bits(0b1111_1110), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_bits(0b1111_1111), EcnCodepoint::Ce);
    }
}
