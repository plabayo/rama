use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::RecordType;

/// Parse one complete A-record RDATA value.
///
/// RFC 1035 Section 3.4.1 defines A RDATA as exactly four address octets.
/// All 32-bit values are accepted; address-policy filtering belongs above the
/// wire layer.
pub fn parse_a_rdata(rdata: &[u8]) -> Result<Ipv4Addr, AddressRdataParseError> {
    let octets = match <[u8; 4]>::try_from(rdata) {
        Ok(octets) => octets,
        Err(_invalid_length) => {
            return Err(AddressRdataParseError::new(RecordType::A, 4, rdata.len()));
        }
    };
    Ok(Ipv4Addr::from(octets))
}

/// Parse one complete AAAA-record RDATA value.
///
/// RFC 3596 Section 2.2 defines AAAA RDATA as exactly 16 address octets in
/// network byte order. All 128-bit values are accepted; address-policy
/// filtering belongs above the wire layer.
pub fn parse_aaaa_rdata(rdata: &[u8]) -> Result<Ipv6Addr, AddressRdataParseError> {
    let octets = match <[u8; 16]>::try_from(rdata) {
        Ok(octets) => octets,
        Err(_invalid_length) => {
            return Err(AddressRdataParseError::new(
                RecordType::AAAA,
                16,
                rdata.len(),
            ));
        }
    };
    Ok(Ipv6Addr::from(octets))
}

/// Error returned when address-record RDATA has the wrong wire length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRdataParseError {
    record_type: RecordType,
    expected_len: usize,
    actual_len: usize,
}

impl AddressRdataParseError {
    const fn new(record_type: RecordType, expected_len: usize, actual_len: usize) -> Self {
        Self {
            record_type,
            expected_len,
            actual_len,
        }
    }

    /// Return the record type whose RDATA was parsed.
    #[must_use]
    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Return the required RDATA length in octets.
    #[must_use]
    pub const fn expected_len(&self) -> usize {
        self.expected_len
    }

    /// Return the supplied RDATA length in octets.
    #[must_use]
    pub const fn actual_len(&self) -> usize {
        self.actual_len
    }
}

impl fmt::Display for AddressRdataParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record_name = match self.record_type {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            _ => "address",
        };
        write!(
            f,
            "{record_name} RDATA must contain exactly {} octets, got {}",
            self.expected_len, self.actual_len
        )
    }
}

impl core::error::Error for AddressRdataParseError {}
