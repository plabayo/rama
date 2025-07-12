//! Version 1 of the HAProxy protocol (text version).
//!
//! See <https://haproxy.org/download/1.8/doc/proxy-protocol.txt>

mod error;
mod model;

pub use crate::protocol::ip::{IPv4, IPv6};
pub use error::{BinaryParseError, ParseError};
pub use model::{Addresses, Header, SEPARATOR, TCP4, TCP6, UNKNOWN};
pub use model::{PROTOCOL_PREFIX, PROTOCOL_SUFFIX};
use std::borrow::Cow;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::str::{FromStr, from_utf8};

const ZERO: &str = "0";
const NEWLINE: &str = "\n";
const CARRIAGE_RETURN: char = '\r';

/// The maximum length of a header in bytes.
const MAX_LENGTH: usize = 107;
/// The total number of parts in the header.
const PARTS: usize = 7;

/// Parses a text PROXY protocol header.
/// The given string is expected to only include the header and to end in \r\n.
fn parse_header(header: &str) -> Result<Header<'_>, ParseError> {
    if header.is_empty() {
        return Err(ParseError::MissingPrefix);
    } else if header.len() > MAX_LENGTH {
        return Err(ParseError::HeaderTooLong);
    }

    let mut iterator = header
        .splitn(PARTS, [SEPARATOR, CARRIAGE_RETURN])
        .peekable();

    let prefix = iterator.next().ok_or(ParseError::MissingPrefix)?;

    if !prefix.is_empty() && PROTOCOL_PREFIX.starts_with(prefix) && header.ends_with(prefix) {
        return Err(ParseError::Partial);
    } else if prefix != PROTOCOL_PREFIX {
        return Err(ParseError::InvalidPrefix);
    }

    let addresses = match iterator.next() {
        Some(TCP4) => {
            let (source_address, destination_address, source_port, destination_port) =
                parse_addresses::<Ipv4Addr, _>(&mut iterator)?;

            Addresses::Tcp4(IPv4 {
                source_address,
                source_port,
                destination_address,
                destination_port,
            })
        }
        Some(TCP6) => {
            let (source_address, destination_address, source_port, destination_port) =
                parse_addresses::<Ipv6Addr, _>(&mut iterator)?;

            Addresses::Tcp6(IPv6 {
                source_address,
                source_port,
                destination_address,
                destination_port,
            })
        }
        Some(UNKNOWN) => {
            while iterator.next_if(|&s| s != NEWLINE).is_some() {}

            Addresses::Unknown
        }
        Some(protocol) if protocol.is_empty() && iterator.peek().is_none() => {
            return Err(ParseError::MissingProtocol);
        }
        Some(protocol)
            if !protocol.is_empty()
                && header.ends_with(protocol)
                && (TCP4.starts_with(protocol) || UNKNOWN.starts_with(protocol)) =>
        {
            return Err(ParseError::Partial);
        }
        Some(_) => return Err(ParseError::InvalidProtocol),
        None => return Err(ParseError::MissingProtocol),
    };

    let newline = iterator
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(ParseError::MissingNewLine)?;

    if newline != NEWLINE {
        return Err(ParseError::InvalidSuffix);
    }

    Ok(Header {
        header: Cow::Borrowed(header),
        addresses,
    })
}

/// Parses the addresses and ports from a PROXY protocol header for IPv4 and IPv6.
fn parse_addresses<'a, T: FromStr<Err = AddrParseError>, I: Iterator<Item = &'a str>>(
    iterator: &mut I,
) -> Result<(T, T, u16, u16), ParseError> {
    let source_address = iterator.next().ok_or(ParseError::MissingSourceAddress)?;
    let destination_address = iterator
        .next()
        .ok_or(ParseError::MissingDestinationAddress)?;
    let source_port = iterator.next().ok_or(ParseError::MissingSourcePort)?;
    let destination_port = iterator.next().ok_or(ParseError::MissingDestinationPort)?;

    let source_address = source_address
        .parse::<T>()
        .map_err(ParseError::InvalidSourceAddress)?;
    let destination_address = destination_address
        .parse::<T>()
        .map_err(ParseError::InvalidDestinationAddress)?;

    if source_port.starts_with(ZERO) && source_port != ZERO {
        return Err(ParseError::InvalidSourcePort(None));
    }

    let source_port = source_port
        .parse::<u16>()
        .map_err(|e| ParseError::InvalidSourcePort(Some(e)))?;

    if destination_port.starts_with(ZERO) && destination_port != ZERO {
        return Err(ParseError::InvalidDestinationPort(None));
    }

    let destination_port = destination_port
        .parse::<u16>()
        .map_err(|e| ParseError::InvalidDestinationPort(Some(e)))?;

    Ok((
        source_address,
        destination_address,
        source_port,
        destination_port,
    ))
}

impl<'a> TryFrom<&'a str> for Header<'a> {
    type Error = ParseError;

    fn try_from(input: &'a str) -> Result<Self, Self::Error> {
        let length = match input.find(CARRIAGE_RETURN) {
            Some(suffix) => suffix + PROTOCOL_SUFFIX.len(),
            None if input.len() >= MAX_LENGTH => return Err(ParseError::HeaderTooLong),
            None => input.len(),
        };

        parse_header(&input[..length])
    }
}

impl<'a> TryFrom<&'a [u8]> for Header<'a> {
    type Error = BinaryParseError;

    fn try_from(input: &'a [u8]) -> Result<Self, Self::Error> {
        let length = match input.iter().position(|&c| CARRIAGE_RETURN == (c as char)) {
            Some(suffix) => suffix + PROTOCOL_SUFFIX.len(),
            None if input.len() >= MAX_LENGTH => return Err(ParseError::HeaderTooLong.into()),
            None => input.len(),
        };
        let header = from_utf8(&input[..length])?;

        parse_header(header).map_err(BinaryParseError::Parse)
    }
}

impl FromStr for Addresses {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Header::try_from(s)?.addresses)
    }
}

impl FromStr for Header<'static> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Header::try_from(s)?.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(invalid_from_utf8)]
    fn bytes_invalid_utf8() {
        let text = b"Hello \xF0\x90\x80World\r\n";

        assert_eq!(
            Header::try_from(&text[..]).unwrap_err(),
            BinaryParseError::InvalidUtf8(from_utf8(text).unwrap_err())
        );
    }

    #[test]
    fn exact_tcp4() {
        let ip: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp4(ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn valid_tcp4() {
        let ip: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nFoobar";
        let expected = Header::new(
            "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
            Addresses::new_tcp4(ip, ip, port, port),
        );

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_partial() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535";

        assert_eq!(
            Header::try_from(text).unwrap_err(),
            ParseError::MissingNewLine
        );
        assert_eq!(
            Header::try_from(text.as_bytes()).unwrap_err(),
            ParseError::MissingNewLine.into()
        );
    }

    #[test]
    fn parse_tcp4_invalid() {
        let text = "PROXY TCP4 255.255.255.255 256.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidDestinationAddress("".parse::<Ipv4Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_tcp4_leading_zeroes() {
        let text = "PROXY TCP4 255.0255.255.255 255.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourceAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourceAddress("".parse::<Ipv4Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_unknown_connection() {
        let text = "PROXY UNKNOWN\r\nTwo";

        assert_eq!(
            Header::try_from(text),
            Ok(Header::new("PROXY UNKNOWN\r\n", Addresses::default()))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Ok(Header::new("PROXY UNKNOWN\r\n", Addresses::default()))
        );
    }

    #[test]
    fn valid_tcp6() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!";
        let expected = Header::new(
            "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            Addresses::new_tcp6(ip, ip, port, port),
        );

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn valid_tcp6_short() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let port = 65535;
        let short_ip = "::1".parse().unwrap();
        let text = "PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\nHi!";
        let expected = Header::new(
            "PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n",
            Addresses::new_tcp6(short_ip, ip, port, port),
        );

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_tcp6_invalid() {
        let text = "PROXY TCP6 ffff:gggg:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourceAddress(
                "".parse::<Ipv6Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourceAddress("".parse::<Ipv6Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_tcp6_leading_zeroes() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:0ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationAddress(
                "".parse::<Ipv6Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidDestinationAddress("".parse::<Ipv6Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_tcp6_shortened_connection() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff::ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_tcp6_single_zero() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff:ffff:ffff:ffff::ffff:ffff:ffff".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff::ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_tcp6_wildcard() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "::".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 :: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_tcp6_implied() {
        let ip: Ipv6Addr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        let short_ip = "ffff::".parse().unwrap();
        let port = 65535;
        let text = "PROXY TCP6 ffff:: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::new_tcp6(short_ip, ip, port, port));

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_tcp6_over_shortened() {
        let text = "PROXY TCP6 ffff::ffff:ffff:ffff:ffff::ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourceAddress(
                "".parse::<Ipv6Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourceAddress("".parse::<Ipv6Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_worst_case() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        let expected = Header::new(text, Addresses::Unknown);

        assert_eq!(Header::try_from(text), Ok(expected.to_owned()));
        assert_eq!(Header::try_from(text.as_bytes()), Ok(expected));
    }

    #[test]
    fn parse_leading_zeroes_in_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 05535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourcePort(None))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourcePort(None).into())
        );
    }

    #[test]
    fn parse_leading_zeroes_in_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 05535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationPort(None))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidDestinationPort(None).into())
        );
    }

    #[test]
    fn parse_source_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65536 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourcePort(Some(
                "65536".parse::<u16>().unwrap_err()
            )))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourcePort(Some("65536".parse::<u16>().unwrap_err())).into())
        );
    }

    #[test]
    fn parse_destination_port_too_large() {
        let text = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65536\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationPort(Some(
                "65536".parse::<u16>().unwrap_err()
            )))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(
                ParseError::InvalidDestinationPort(Some("65536".parse::<u16>().unwrap_err()))
                    .into()
            )
        );
    }

    #[test]
    fn parse_lowercase_proxy() {
        let text = "proxy UNKNOWN\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidPrefix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidPrefix.into())
        );
    }

    #[test]
    fn parse_lowercase_protocol_family() {
        let text = "PROXY tcp4\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidProtocol));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidProtocol.into())
        );
    }

    #[test]
    fn parse_too_long() {
        let text = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535  \r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::HeaderTooLong));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::HeaderTooLong.into())
        );
    }

    #[test]
    fn parse_more_than_one_space() {
        let text = "PROXY  TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidProtocol));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidProtocol.into())
        );
    }

    #[test]
    fn parse_more_than_one_space_source_address() {
        let text = "PROXY TCP4  255.255.255.255 255.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourceAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourceAddress("".parse::<Ipv4Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_more_than_one_space_destination_address() {
        let text = "PROXY TCP4 255.255.255.255  255.255.255.255 65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationAddress(
                "".parse::<Ipv4Addr>().unwrap_err()
            ))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidDestinationAddress("".parse::<Ipv4Addr>().unwrap_err()).into())
        );
    }

    #[test]
    fn parse_more_than_one_space_source_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255  65535 65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidSourcePort(Some(
                "".parse::<u16>().unwrap_err()
            )))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSourcePort(Some("".parse::<u16>().unwrap_err())).into())
        );
    }

    #[test]
    fn parse_more_than_one_space_destination_port() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535  65535\r\n";

        assert_eq!(
            Header::try_from(text),
            Err(ParseError::InvalidDestinationPort(Some(
                "".parse::<u16>().unwrap_err()
            )))
        );
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidDestinationPort(Some("".parse::<u16>().unwrap_err())).into())
        );
    }

    #[test]
    fn parse_more_than_one_space_end() {
        let text = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 \r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidSuffix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSuffix.into())
        );
    }

    #[test]
    fn parse_partial_prefix() {
        let text = "PROX\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidPrefix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidPrefix.into())
        );
    }

    #[test]
    fn parse_empty_newline() {
        let text = "\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidPrefix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidPrefix.into())
        );
    }

    #[test]
    fn parse_partial_prefix_missing_newline() {
        let text = "PROX";

        assert_eq!(Header::try_from(text), Err(ParseError::Partial));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::Partial.into())
        );
    }

    #[test]
    fn parse_partial_protocol_missing_newline() {
        let text = "PROXY UNKN";

        assert_eq!(Header::try_from(text), Err(ParseError::Partial));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::Partial.into())
        );
    }

    #[test]
    fn parse_partial_protocol_with_newline() {
        let text = "PROXY UNKN\r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidProtocol));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidProtocol.into())
        );
    }

    #[test]
    fn parse_empty_protocol_with_newline() {
        let text = "PROXY \r\n";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidProtocol));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidProtocol.into())
        );
    }

    #[test]
    fn parse_empty() {
        let text = "";

        assert_eq!(Header::try_from(text), Err(ParseError::MissingPrefix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::MissingPrefix.into())
        );
    }

    #[test]
    fn parse_no_new_line() {
        let text = "PROXY TCP4 127.0.0.1 192.168.1.1 80 443\r\t";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidSuffix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidSuffix.into())
        );
    }

    #[test]
    fn parse_invalid_prefix_missing_newline() {
        let text = "PRAX";

        assert_eq!(Header::try_from(text), Err(ParseError::InvalidPrefix));
        assert_eq!(
            Header::try_from(text.as_bytes()),
            Err(ParseError::InvalidPrefix.into())
        );
    }
}
