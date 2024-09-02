//! Version 2 of the HAProxy protocol (binary version).
//!
//! See <https://haproxy.org/download/1.8/doc/proxy-protocol.txt>

mod builder;
mod error;
mod model;

pub use crate::proxy::pp::protocol::ip::{IPv4, IPv6};
pub use builder::{Builder, WriteToHeader, Writer};
pub use error::ParseError;
pub use model::{
    AddressFamily, Addresses, Command, Header, Protocol, Type, TypeLengthValue, TypeLengthValues,
    Unix, Version, PROTOCOL_PREFIX,
};
use model::{MINIMUM_LENGTH, MINIMUM_TLV_LENGTH};
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Masks the right 4-bits so only the left 4-bits are present.
const LEFT_MASK: u8 = 0xF0;
/// Masks the left 4-bits so only the right 4-bits are present.
const RIGHT_MASK: u8 = 0x0F;
/// The index of the version-command byte.
const VERSION_COMMAND: usize = PROTOCOL_PREFIX.len();
/// The index of the address family-protocol byte.
const ADDRESS_FAMILY_PROTOCOL: usize = VERSION_COMMAND + 1;
/// The index of the start of the big-endian u16 length.
const LENGTH: usize = ADDRESS_FAMILY_PROTOCOL + 1;

/// Parses the addresses from the header payload.
fn parse_addresses(address_family: AddressFamily, bytes: &[u8]) -> Addresses {
    match address_family {
        AddressFamily::Unspecified => Addresses::Unspecified,
        AddressFamily::IPv4 => {
            let source_address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let destination_address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            let source_port = u16::from_be_bytes([bytes[8], bytes[9]]);
            let destination_port = u16::from_be_bytes([bytes[10], bytes[11]]);

            Addresses::IPv4(IPv4 {
                source_address,
                destination_address,
                source_port,
                destination_port,
            })
        }
        AddressFamily::IPv6 => {
            let mut address = [0; 16];

            address[..].copy_from_slice(&bytes[..16]);
            let source_address = Ipv6Addr::from(address);

            address[..].copy_from_slice(&bytes[16..32]);
            let destination_address = Ipv6Addr::from(address);

            let source_port = u16::from_be_bytes([bytes[32], bytes[33]]);
            let destination_port = u16::from_be_bytes([bytes[34], bytes[35]]);

            Addresses::IPv6(IPv6 {
                source_address,
                destination_address,
                source_port,
                destination_port,
            })
        }
        AddressFamily::Unix => {
            let mut source = [0; 108];
            let mut destination = [0; 108];

            source[..].copy_from_slice(&bytes[..108]);
            destination[..].copy_from_slice(&bytes[108..]);

            Addresses::Unix(Unix {
                source,
                destination,
            })
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = ParseError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        if input.len() < PROTOCOL_PREFIX.len() {
            if PROTOCOL_PREFIX.starts_with(input) {
                return Err(ParseError::Incomplete(input.len()));
            } else {
                return Err(ParseError::Prefix);
            }
        }

        if &input[..VERSION_COMMAND] != PROTOCOL_PREFIX {
            return Err(ParseError::Prefix);
        }

        if input.len() < MINIMUM_LENGTH {
            return Err(ParseError::Incomplete(input.len()));
        }

        let version = match input[VERSION_COMMAND] & LEFT_MASK {
            0x20 => Version::Two,
            v => return Err(ParseError::Version(v)),
        };
        let command = match input[VERSION_COMMAND] & RIGHT_MASK {
            0x00 => Command::Local,
            0x01 => Command::Proxy,
            c => return Err(ParseError::Command(c)),
        };

        let address_family = match input[ADDRESS_FAMILY_PROTOCOL] & LEFT_MASK {
            0x00 => AddressFamily::Unspecified,
            0x10 => AddressFamily::IPv4,
            0x20 => AddressFamily::IPv6,
            0x30 => AddressFamily::Unix,
            a => return Err(ParseError::AddressFamily(a)),
        };
        let protocol = match input[ADDRESS_FAMILY_PROTOCOL] & RIGHT_MASK {
            0x00 => Protocol::Unspecified,
            0x01 => Protocol::Stream,
            0x02 => Protocol::Datagram,
            p => return Err(ParseError::Protocol(p)),
        };

        let length = u16::from_be_bytes([input[LENGTH], input[LENGTH + 1]]) as usize;
        let address_family_bytes = address_family.byte_length().unwrap_or_default();

        if length < address_family_bytes {
            return Err(ParseError::InvalidAddresses(length, address_family_bytes));
        }

        let full_length = MINIMUM_LENGTH + length;

        if input.len() < full_length {
            return Err(ParseError::Partial(input.len() - MINIMUM_LENGTH, length));
        }

        let header = &input[..full_length];
        let addresses = parse_addresses(
            address_family,
            &header[MINIMUM_LENGTH..MINIMUM_LENGTH + address_family_bytes],
        );

        Ok(Header {
            header: Cow::Borrowed(header),
            version,
            command,
            protocol,
            addresses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{Type, TypeLengthValue};

    #[test]
    fn no_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let expected = Header {
            header: Cow::Borrowed(input.as_slice()),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: IPv4::new([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.length(), 12);
        assert_eq!(actual.address_family(), AddressFamily::IPv4);
        assert_eq!(
            actual.address_bytes(),
            &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]
        );
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn no_tlvs_unspec() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x00);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let expected = Header {
            header: input.as_slice().into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            addresses: Addresses::Unspecified,
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.length(), 12);
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert_eq!(
            actual.address_bytes(),
            &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]
        );
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn no_tlvs_unspec_stream() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x01);
        input.extend([0, 8]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);

        let expected = Header {
            header: Cow::Borrowed(input.as_slice()),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: Addresses::Unspecified,
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.length(), 8);
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert_eq!(actual.address_bytes(), &[127, 0, 0, 1, 127, 0, 0, 2]);
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn no_tlvs_unspec_ipv4() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x10);
        input.extend([0, 8]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::InvalidAddresses(8, 12));
    }

    #[test]
    fn invalid_version() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x11);
        input.push(0x11);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Version(0x10));
    }

    #[test]
    fn invalid_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x51);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::AddressFamily(0x50));
    }

    #[test]
    fn invalid_command() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x23);
        input.push(0x11);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Command(0x03));
    }

    #[test]
    fn invalid_protocol() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x17);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);

        let actual = Header::try_from(input.as_slice()).unwrap_err();

        assert_eq!(actual, ParseError::Protocol(0x07));
    }

    #[test]
    fn proxy_with_extra() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);
        input.extend([42]);

        let header = &input[..input.len() - 1];
        let expected = Header {
            header: header.into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: IPv4::new([127, 0, 0, 1], [127, 0, 0, 2], 80, 443).into(),
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.length(), 12);
        assert_eq!(actual.address_family(), AddressFamily::IPv4);
        assert_eq!(
            actual.address_bytes(),
            &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 1, 187]
        );
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), header);
    }

    #[test]
    fn with_tlvs() {
        let source_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF2,
        ];
        let destination_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ];
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend([0, 45]);
        input.extend(source_address);
        input.extend(destination_address);
        input.extend([0, 80]);
        input.extend([1, 187]);
        input.extend([1, 0, 1, 5]);
        input.extend([3, 0, 2, 5, 5]);

        let expected = Header {
            header: input.as_slice().into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: IPv6::new(source_address, destination_address, 80, 443).into(),
        };
        let expected_tlvs = vec![
            Ok(TypeLengthValue::new(Type::ALPN, &[5])),
            Ok(TypeLengthValue::new(Type::CRC32C, &[5, 5])),
        ];

        let actual = Header::try_from(input.as_slice()).unwrap();
        let actual_tlvs: Vec<Result<TypeLengthValue<'_>, ParseError>> = actual.tlvs().collect();

        assert_eq!(actual, expected);
        assert_eq!(actual_tlvs, expected_tlvs);
        assert_eq!(actual.length(), 45);
        assert_eq!(actual.address_family(), AddressFamily::IPv6);
        assert_eq!(
            actual.address_bytes(),
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xF2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xF1, 0, 80, 1, 187
            ]
        );
        assert_eq!(actual.tlv_bytes(), &[1, 0, 1, 5, 3, 0, 2, 5, 5]);
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn tlvs_with_extra() {
        let source_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ];
        let destination_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ];
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x21);
        input.extend([0, 45]);
        input.extend(source_address);
        input.extend(destination_address);
        input.extend([0, 80]);
        input.extend([1, 187]);
        input.extend([1, 0, 1, 5]);
        input.extend([4, 0, 2, 5, 5]);
        input.extend([2, 0, 2, 5, 5]);

        let header = &input[..input.len() - 5];
        let expected = Header {
            header: header.into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Stream,
            addresses: IPv6::new(source_address, destination_address, 80, 443).into(),
        };
        let expected_tlvs = vec![
            Ok(TypeLengthValue::new(Type::ALPN, &[5])),
            Ok(TypeLengthValue::new(Type::NoOp, &[5, 5])),
        ];

        let actual = Header::try_from(input.as_slice()).unwrap();
        let actual_tlvs: Vec<Result<TypeLengthValue<'_>, ParseError>> = actual.tlvs().collect();

        assert_eq!(actual, expected);
        assert_eq!(actual_tlvs, expected_tlvs);
        assert_eq!(actual.length(), 45);
        assert_eq!(actual.address_family(), AddressFamily::IPv6);
        assert_eq!(
            actual.address_bytes(),
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xF1, 0, 80, 1, 187
            ]
        );
        assert_eq!(actual.tlv_bytes(), &[1, 0, 1, 5, 4, 0, 2, 5, 5]);
        assert_eq!(actual.as_bytes(), header);
    }

    #[test]
    fn unix_tlvs_with_extra() {
        let source_address = [0xFFu8; 108];
        let destination_address = [0xAAu8; 108];
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x30);
        input.extend([0, 225]);
        input.extend(source_address);
        input.extend(destination_address);
        input.extend([2, 0, 2, 5, 5]);
        input.extend([48, 0, 1, 5]);
        input.extend([1, 0, 2, 5, 5]);

        let header = &input[..input.len() - 5];
        let expected = Header {
            header: header.into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            addresses: Unix::new(source_address, destination_address).into(),
        };
        let mut expected_address_bytes =
            Vec::with_capacity(source_address.len() + destination_address.len());
        expected_address_bytes.extend(source_address);
        expected_address_bytes.extend(destination_address);

        let expected_tlvs = vec![
            Ok(TypeLengthValue::new(Type::Authority, &[5, 5])),
            Ok(TypeLengthValue::new(Type::NetworkNamespace, &[5])),
        ];

        let actual = Header::try_from(input.as_slice()).unwrap();
        let actual_tlvs: Vec<Result<TypeLengthValue<'_>, ParseError>> = actual.tlvs().collect();

        assert_eq!(actual, expected);
        assert_eq!(actual_tlvs, expected_tlvs);
        assert_eq!(actual.length(), 225);
        assert_eq!(actual.address_family(), AddressFamily::Unix);
        assert_eq!(actual.address_bytes(), expected_address_bytes.as_slice());
        assert_eq!(actual.tlv_bytes(), &[2, 0, 2, 5, 5, 48, 0, 1, 5]);
        assert_eq!(actual.as_bytes(), header);
    }

    #[test]
    fn with_tlvs_without_ports() {
        let source_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ];
        let destination_address = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xF1,
        ];
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x20);
        input.extend([0, 41]);
        input.extend(source_address);
        input.extend(destination_address);
        input.extend([1, 0, 1, 5]);
        input.extend([3, 0, 2, 5, 5]);

        let expected = Header {
            header: input.as_slice().into(),
            version: Version::Two,
            command: Command::Proxy,
            protocol: Protocol::Unspecified,
            addresses: IPv6::new(source_address, destination_address, 256, 261).into(),
        };
        let expected_tlvs = vec![Ok(TypeLengthValue::new(Type::CRC32C, &[5, 5]))];

        let actual = Header::try_from(input.as_slice()).unwrap();
        let actual_tlvs: Vec<Result<TypeLengthValue<'_>, ParseError>> = actual.tlvs().collect();

        assert_eq!(actual, expected);
        assert_eq!(actual_tlvs, expected_tlvs);
        assert_eq!(actual.length(), 41);
        assert_eq!(actual.address_family(), AddressFamily::IPv6);
        assert_eq!(
            actual.address_bytes(),
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xF1, 1, 0, 1, 5
            ]
        );
        assert_eq!(actual.tlv_bytes(), &[3, 0, 2, 5, 5]);
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn partial_tlv() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend([0, 15]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);
        input.extend([1, 0, 1]);

        let header = Header::try_from(input.as_slice()).unwrap();
        let mut tlvs = header.tlvs();

        assert_eq!(tlvs.next().unwrap(), Err(ParseError::InvalidTLV(1, 1)));
        assert_eq!(tlvs.next(), None);
    }

    #[test]
    fn missing_tlvs() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend([0, 17]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([1, 187]);
        input.extend([1, 0, 1]);

        assert_eq!(
            Header::try_from(&input[..]).unwrap_err(),
            ParseError::Partial(15, 17)
        );
    }

    #[test]
    fn partial_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x21);
        input.push(0x11);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);

        assert_eq!(
            Header::try_from(&input[..]).unwrap_err(),
            ParseError::Partial(10, 12)
        );
    }

    #[test]
    fn no_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend([0, 0]);
        input.extend([0, 80]);

        let header = &input[..input.len() - 2];
        let expected = Header {
            header: header.into(),
            version: Version::Two,
            command: Command::Local,
            protocol: Protocol::Datagram,
            addresses: Addresses::Unspecified,
        };

        let actual = Header::try_from(input.as_slice()).unwrap();
        let actual_tlvs: Vec<Result<TypeLengthValue<'_>, ParseError>> = actual.tlvs().collect();

        assert_eq!(actual, expected);
        assert_eq!(actual_tlvs, vec![]);
        assert_eq!(actual.length(), 0);
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert!(actual.address_bytes().is_empty());
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), header);
    }

    #[test]
    fn unspecified_address_family() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x02);
        input.extend([0, 12]);
        input.extend([127, 0, 0, 1]);
        input.extend([127, 0, 0, 2]);
        input.extend([0, 80]);
        input.extend([0xbb, 1]);

        let expected = Header {
            header: input.as_slice().into(),
            version: Version::Two,
            command: Command::Local,
            protocol: Protocol::Datagram,
            addresses: Addresses::Unspecified,
        };
        let actual = Header::try_from(input.as_slice()).unwrap();

        assert_eq!(actual, expected);
        assert!(actual.tlvs().next().is_none());
        assert_eq!(actual.length(), 12);
        assert_eq!(actual.address_family(), AddressFamily::Unspecified);
        assert_eq!(
            actual.address_bytes(),
            &[127, 0, 0, 1, 127, 0, 0, 2, 0, 80, 0xbb, 1]
        );
        assert!(actual.tlv_bytes().is_empty());
        assert_eq!(actual.as_bytes(), input.as_slice());
    }

    #[test]
    fn missing_address() {
        let mut input: Vec<u8> = Vec::with_capacity(PROTOCOL_PREFIX.len());

        input.extend_from_slice(PROTOCOL_PREFIX);
        input.push(0x20);
        input.push(0x22);
        input.extend([0, 0]);
        input.extend([0, 80]);

        assert_eq!(
            Header::try_from(&input[..]).unwrap_err(),
            ParseError::InvalidAddresses(0, AddressFamily::IPv6.byte_length().unwrap_or_default())
        );
    }

    #[test]
    fn not_prefixed() {
        assert_eq!(
            Header::try_from(b"\r\n\r\n\x01\r\nQUIT\n".as_slice()).unwrap_err(),
            ParseError::Prefix
        );
        assert_eq!(
            Header::try_from(b"\r\n\r\n\x01".as_slice()).unwrap_err(),
            ParseError::Prefix
        );
    }

    #[test]
    fn incomplete() {
        assert_eq!(
            Header::try_from([0x0D, 0x0A, 0x0D, 0x0A, 0x00].as_slice()).unwrap_err(),
            ParseError::Incomplete(5)
        );
        assert_eq!(
            Header::try_from(PROTOCOL_PREFIX).unwrap_err(),
            ParseError::Incomplete(PROTOCOL_PREFIX.len())
        );
    }
}
