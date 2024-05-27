// //! This module implements parsing for the Forwarded header as defined by
// //! [RFC 7239] and [RFC 7230].
// //! 
// //! [RFC 7239]: https://tools.ietf.org/html/rfc7239
// //! [RFC 7230]: https://tools.ietf.org/html/rfc7230
// //! 
// //! # Example
// //! 
// //! TODO
// //! 
// //! # Fork
// //! 
// //! This code is forked from [`rust-forwarded-header-value`](https://crates.io/crates/forwarded-header-value):
// //!
// //! - license: <https://github.com/imbolc/axum-client-ip/blob/d2a00f90e1bda709067a2b28d1084540321df93d/LICENSE>
// //! - Original Author: [James Brown](https://github.com/Roguelazer)

// #![warn(missing_docs)]
// #![forbid(unsafe_code)]

// use std::net::{IpAddr, SocketAddr};
// use std::str::FromStr;

// #[derive(Debug, PartialEq, Eq, Clone)]
// #[allow(missing_docs)]
// /// Remote identifier. This can be an IP:port pair, a bare IP, an underscore-prefixed
// /// "obfuscated string", or unknown.
// pub enum Identifier {
//     SocketAddr(SocketAddr),
//     IpAddr(IpAddr),
//     String(String),
//     Unknown,
// }

// impl Identifier {
//     #[cfg(test)]
//     fn for_string<T: ToString>(t: T) -> Self {
//         Identifier::String(t.to_string())
//     }

//     /// Return the IP address for this identifier, if there is one. This will extract it from the
//     /// SocketAddr if necessary
//     pub fn ip(&self) -> Option<IpAddr> {
//         match self {
//             Identifier::SocketAddr(sa) => Some(sa.ip()),
//             Identifier::IpAddr(ip) => Some(*ip),
//             _ => None,
//         }
//     }
// }

// impl FromStr for Identifier {
//     type Err = ForwardedHeaderValueParseError;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         let s = s.trim().trim_matches('"').trim_matches('\'');
//         if s == "unknown" {
//             return Ok(Identifier::Unknown);
//         }
//         if let Ok(socket_addr) = s.parse::<SocketAddr>() {
//             Ok(Identifier::SocketAddr(socket_addr))
//         } else if let Ok(ip_addr) = s.parse::<IpAddr>() {
//             Ok(Identifier::IpAddr(ip_addr))
//         } else if s.starts_with('[') && s.ends_with(']') {
//             if let Ok(ip_addr) = s[1..(s.len() - 1)].parse::<IpAddr>() {
//                 Ok(Identifier::IpAddr(ip_addr))
//             } else {
//                 Err(ForwardedHeaderValueParseError::InvalidAddress)
//             }
//         } else if s.starts_with('_') {
//             Ok(Identifier::String(s.to_string()))
//         } else {
//             Err(ForwardedHeaderValueParseError::InvalidObfuscatedNode(
//                 s.to_string(),
//             ))
//         }
//     }
// }

// #[derive(Debug, Default)]
// /// A single forwarded-for line; there may be a sequence of these in a Forwarded header.
// ///
// /// Any parts not specified will be None
// #[allow(missing_docs)]
// pub struct ForwardedStanza {
//     pub forwarded_by: Option<Identifier>,
//     pub forwarded_for: Option<Identifier>,
//     pub forwarded_host: Option<String>,
//     pub forwarded_proto: Option<Protocol>,
// }

// impl ForwardedStanza {
//     /// Get the forwarded-for IP, if one is present
//     pub fn forwarded_for_ip(&self) -> Option<IpAddr> {
//         self.forwarded_for.as_ref().and_then(|fa| fa.ip())
//     }

//     /// Get the forwarded-by IP, if one is present
//     pub fn forwarded_by_ip(&self) -> Option<IpAddr> {
//         self.forwarded_by.as_ref().and_then(|fa| fa.ip())
//     }
// }

// impl FromStr for ForwardedStanza {
//     type Err = ForwardedHeaderValueParseError;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         let mut rv = ForwardedStanza::default();
//         let s = s.trim();
//         for part in s.split(';') {
//             let part = part.trim();
//             if part.is_empty() {
//                 continue;
//             }
//             if let Some((key, value)) = part.split_once('=') {
//                 match key.to_ascii_lowercase().as_str() {
//                     "by" => rv.forwarded_by = Some(value.parse()?),
//                     "for" => rv.forwarded_for = Some(value.parse()?),
//                     "host" => {
//                         rv.forwarded_host = {
//                             if value.starts_with('"') && value.ends_with('"') {
//                                 Some(
//                                     value[1..(value.len() - 1)]
//                                         .replace("\\\"", "\"")
//                                         .replace("\\\\", "\\"),
//                                 )
//                             } else {
//                                 Some(value.to_string())
//                             }
//                         }
//                     }
//                     "proto" => rv.forwarded_proto = Some(value.parse()?),
//                     _other => continue,
//                 }
//             } else {
//                 return Err(ForwardedHeaderValueParseError::InvalidPart(part.to_owned()));
//             }
//         }
//         Ok(rv)
//     }
// }

// /// Iterator over stanzas in a ForwardedHeaderValue
// pub struct ForwardedHeaderValueIterator<'a> {
//     head: Option<&'a ForwardedStanza>,
//     tail: &'a [ForwardedStanza],
// }

// impl<'a> Iterator for ForwardedHeaderValueIterator<'a> {
//     type Item = &'a ForwardedStanza;

//     fn next(&mut self) -> Option<Self::Item> {
//         if let Some(head) = self.head.take() {
//             Some(head)
//         } else if let Some((first, rest)) = self.tail.split_first() {
//             self.tail = rest;
//             Some(first)
//         } else {
//             None
//         }
//     }
// }

// impl<'a> DoubleEndedIterator for ForwardedHeaderValueIterator<'a> {
//     fn next_back(&mut self) -> Option<Self::Item> {
//         if let Some((last, rest)) = self.tail.split_last() {
//             self.tail = rest;
//             Some(last)
//         } else if let Some(head) = self.head.take() {
//             Some(head)
//         } else {
//             None
//         }
//     }
// }

// impl<'a> ExactSizeIterator for ForwardedHeaderValueIterator<'a> {
//     fn len(&self) -> usize {
//         self.tail.len() + if self.head.is_some() { 1 } else { 0 }
//     }
// }

// impl<'a> core::iter::FusedIterator for ForwardedHeaderValueIterator<'a> {}

// fn values_from_header(header_value: &str) -> impl Iterator<Item = &str> {
//     header_value.trim().split(',').filter_map(|i| {
//         let trimmed = i.trim();
//         if trimmed.is_empty() {
//             None
//         } else {
//             Some(trimmed)
//         }
//     })
// }

// /// This structure represents the contents of the Forwarded header
// ///
// /// It should contain one or more ForwardedStanzas
// #[derive(Debug)]
// pub struct ForwardedHeaderValue {
//     values: NonEmpty<ForwardedStanza>,
// }

// impl ForwardedHeaderValue {
//     /// The number of valid stanzas in this value
//     pub fn len(&self) -> usize {
//         self.values.len()
//     }

//     /// This can never be empty
//     pub fn is_empty(&self) -> bool {
//         false
//     }

//     /// Get the value farthest from this system (the left-most value)
//     ///
//     /// This may represent the remote client
//     pub fn remotest(&self) -> &ForwardedStanza {
//         self.values.first()
//     }

//     /// Get the value farthest from this system (the left-most value), consuming this object
//     ///
//     /// This may represent the remote client
//     pub fn into_remotest(mut self) -> ForwardedStanza {
//         if !self.values.tail.is_empty() {
//             self.values.tail.pop().unwrap()
//         } else {
//             self.values.head
//         }
//     }

//     /// Get the value closest to this system (the right-most value).
//     ///
//     /// This is typically the only trusted value in a well-architected system.
//     pub fn proximate(&self) -> &ForwardedStanza {
//         self.values.last()
//     }

//     /// Get the value closest to this system (the right-most value), consuming this object
//     ///
//     /// This is typically the only trusted value in a well-architected system.
//     pub fn into_proximate(mut self) -> ForwardedStanza {
//         if !self.values.tail.is_empty() {
//             self.values.tail.pop().unwrap()
//         } else {
//             self.values.head
//         }
//     }

//     /// Iterate through all ForwardedStanzas
//     pub fn iter(&self) -> ForwardedHeaderValueIterator {
//         ForwardedHeaderValueIterator {
//             head: Some(&self.values.head),
//             tail: &self.values.tail,
//         }
//     }

//     /// Return the rightmost non-empty forwarded-for IP, if one is present
//     pub fn proximate_forwarded_for_ip(&self) -> Option<IpAddr> {
//         self.iter().rev().find_map(|i| i.forwarded_for_ip())
//     }

//     /// Return the leftmost forwarded-for IP, if one is present
//     pub fn remotest_forwarded_for_ip(&self) -> Option<IpAddr> {
//         self.iter().find_map(|i| i.forwarded_for_ip())
//     }

//     /// Parse the value from a Forwarded header into this structure
//     /// ### Example
//     /// ```rust
//     /// # use forwarded_header_value::{ForwardedHeaderValue, ForwardedHeaderValueParseError};
//     /// # fn main() -> Result<(), ForwardedHeaderValueParseError> {
//     /// let input = "for=1.2.3.4;by=\"[::1]:1234\"";
//     /// let value = ForwardedHeaderValue::from_forwarded(input)?;
//     /// assert_eq!(value.len(), 1);
//     /// assert_eq!(value.remotest_forwarded_for_ip(), Some("1.2.3.4".parse()?));
//     /// # Ok(())
//     /// # }
//     /// ```
//     pub fn from_forwarded(header_value: &str) -> Result<Self, ForwardedHeaderValueParseError> {
//         values_from_header(header_value)
//             .map(|stanza| stanza.parse::<ForwardedStanza>())
//             .collect::<Result<Vec<_>, _>>()
//             .and_then(|v| {
//                 NonEmpty::from_vec(v).ok_or(ForwardedHeaderValueParseError::HeaderIsEmpty)
//             })
//             .map(|v| ForwardedHeaderValue { values: v })
//     }

//     /// Parse the value from an X-Forwarded-For header into this structure
//     /// ### Example
//     /// ```rust
//     /// # use forwarded_header_value::{ForwardedHeaderValue, ForwardedHeaderValueParseError};
//     /// # fn main() -> Result<(), ForwardedHeaderValueParseError> {
//     /// let input = "1.2.3.4, 5.6.7.8";
//     /// let value = ForwardedHeaderValue::from_x_forwarded_for(input)?;
//     /// assert_eq!(value.len(), 2);
//     /// assert_eq!(value.remotest_forwarded_for_ip(), Some("1.2.3.4".parse()?));
//     /// assert_eq!(value.proximate_forwarded_for_ip(), Some("5.6.7.8".parse()?));
//     /// # Ok(())
//     /// # }
//     /// ```
//     pub fn from_x_forwarded_for(
//         header_value: &str,
//     ) -> Result<Self, ForwardedHeaderValueParseError> {
//         values_from_header(header_value)
//             .map(|address| {
//                 let a = address.parse::<IpAddr>()?;
//                 Ok(ForwardedStanza {
//                     forwarded_for: Some(Identifier::IpAddr(a)),
//                     ..Default::default()
//                 })
//             })
//             .collect::<Result<Vec<_>, _>>()
//             .and_then(|v| {
//                 NonEmpty::from_vec(v).ok_or(ForwardedHeaderValueParseError::HeaderIsEmpty)
//             })
//             .map(|v| ForwardedHeaderValue { values: v })
//     }
// }

// impl IntoIterator for ForwardedHeaderValue {
//     type Item = ForwardedStanza;
//     type IntoIter = std::iter::Chain<std::iter::Once<Self::Item>, std::vec::IntoIter<Self::Item>>;

//     fn into_iter(self) -> Self::IntoIter {
//         self.values.into_iter()
//     }
// }

// #[derive(Error, Debug)]
// #[allow(missing_docs)]
// /// Errors that can occur while parsing a ForwardedHeaderValue
// pub enum ForwardedHeaderValueParseError {
//     #[error("Header is empty")]
//     HeaderIsEmpty,
//     #[error("Stanza contained illegal part {0}")]
//     InvalidPart(String),
//     #[error("Stanza specified an invalid protocol")]
//     InvalidProtocol,
//     #[error("Identifier specified an invalid or malformed IP address")]
//     InvalidAddress,
//     #[error("Identifier specified an invalid or malformed port")]
//     InvalidPort,
//     #[error("Identifier specified uses an obfuscated node ({0:?}) that is invalid")]
//     InvalidObfuscatedNode(String),
//     #[error("Identifier specified an invalid or malformed IP address")]
//     IpParseErr(#[from] std::net::AddrParseError),
// }

// impl FromStr for ForwardedHeaderValue {
//     type Err = ForwardedHeaderValueParseError;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         Self::from_forwarded(s)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::{ForwardedHeaderValue, Identifier, Protocol};
//     use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

//     #[test]
//     fn test_basic() {
//         let s: ForwardedHeaderValue =
//             "for=192.0.2.43;proto=https, for=198.51.100.17;by=\"[::1]:1234\";host=\"example.com\""
//                 .parse()
//                 .unwrap();
//         assert_eq!(s.len(), 2);
//         assert_eq!(
//             s.proximate().forwarded_for_ip(),
//             Some("198.51.100.17".parse().unwrap())
//         );
//         assert_eq!(
//             s.proximate().forwarded_by_ip(),
//             Some("::1".parse().unwrap())
//         );
//         assert_eq!(
//             s.proximate().forwarded_host,
//             Some(String::from("example.com")),
//         );
//         assert_eq!(
//             s.remotest().forwarded_for_ip(),
//             Some("192.0.2.43".parse().unwrap())
//         );
//         assert_eq!(s.remotest().forwarded_proto, Some(Protocol::Https));
//     }

//     #[test]
//     fn test_rfc_examples() {
//         let s = "for=\"_gazonk\"".parse::<ForwardedHeaderValue>().unwrap();
//         assert_eq!(
//             s.into_proximate().forwarded_for.unwrap(),
//             Identifier::for_string("_gazonk")
//         );
//         let s = "For=\"[2001:db8:cafe::17]:4711\""
//             .parse::<ForwardedHeaderValue>()
//             .unwrap();
//         assert_eq!(s.len(), 1);
//         assert_eq!(
//             s.into_proximate().forwarded_for.unwrap(),
//             Identifier::SocketAddr(SocketAddr::new(
//                 IpAddr::V6(Ipv6Addr::new(
//                     0x2001, 0xdb8, 0xcafe, 0x0, 0x0, 0x0, 0x0, 0x17
//                 )),
//                 4711
//             ))
//         );
//         let s = "for=192.0.2.60;proto=http;by=203.0.113.43"
//             .parse::<ForwardedHeaderValue>()
//             .unwrap();
//         assert_eq!(s.len(), 1);
//         let proximate = s.into_proximate();
//         assert_eq!(
//             proximate.forwarded_for.unwrap(),
//             Identifier::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60)))
//         );
//         assert_eq!(proximate.forwarded_proto.unwrap(), Protocol::Http);
//         assert_eq!(
//             proximate.forwarded_by.unwrap(),
//             Identifier::IpAddr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43)))
//         );
//         assert_eq!(proximate.forwarded_host, None);

//         let s = ForwardedHeaderValue::from_forwarded(
//             "for=192.0.2.43,for=\"[2001:db8:cafe::17]\",for=unknown",
//         )
//         .unwrap();
//         assert_eq!(
//             s.proximate_forwarded_for_ip().unwrap(),
//             IpAddr::V6(Ipv6Addr::new(
//                 0x2001, 0xdb8, 0xcafe, 0x0, 0x0, 0x0, 0x0, 0x17
//             ))
//         );
//         assert_eq!(
//             s.remotest_forwarded_for_ip().unwrap(),
//             IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43))
//         );
//     }

//     #[test]
//     fn test_garbage() {
//         let s =
//             ForwardedHeaderValue::from_forwarded("for=unknown, for=unknown, for=_poop").unwrap();
//         assert_eq!(s.remotest_forwarded_for_ip(), None);
//         assert_eq!(s.proximate_forwarded_for_ip(), None);
//     }

//     #[test]
//     fn test_weird_identifiers() {
//         let s: ForwardedHeaderValue = "for=unknown, for=_private, for=_secret, ".parse().unwrap();
//         assert_eq!(s.len(), 3);
//         assert_eq!(
//             vec![
//                 Identifier::Unknown,
//                 Identifier::for_string("_private"),
//                 Identifier::for_string("_secret")
//             ],
//             s.into_iter()
//                 .map(|s| s.forwarded_for.unwrap())
//                 .collect::<Vec<Identifier>>()
//         );
//     }

//     #[test]
//     fn test_iter_both_directions() {
//         let s = ForwardedHeaderValue::from_x_forwarded_for("0.0.0.1, 0.0.0.2, 0.0.0.3").unwrap();
//         let forward = s
//             .iter()
//             .map(|s| {
//                 if let Some(IpAddr::V4(i)) = s.forwarded_for_ip() {
//                     i.octets()[3]
//                 } else {
//                     panic!("bad forward")
//                 }
//             })
//             .collect::<Vec<_>>();
//         assert_eq!(forward, vec![1u8, 2u8, 3u8]);
//         let reverse = s
//             .iter()
//             .rev()
//             .map(|s| {
//                 if let Some(IpAddr::V4(i)) = s.forwarded_for_ip() {
//                     i.octets()[3]
//                 } else {
//                     panic!("bad forward")
//                 }
//             })
//             .collect::<Vec<_>>();
//         assert_eq!(reverse, vec![3u8, 2u8, 1u8]);
//     }
// }