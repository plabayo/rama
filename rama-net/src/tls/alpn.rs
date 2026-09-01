//! Application-Layer Protocol Negotiation identifiers.

use rama_core::extensions::Extension;
use rama_utils::collections::smallvec::{SmallVec, smallvec};
use rama_utils::macros::enums::enum_builder;

use crate::Protocol;

fn display_unknown_maybe_as_grease(
    f: &mut core::fmt::Formatter<'_>,
    bytes: &[u8],
) -> Option<core::fmt::Result> {
    if bytes.len() == 2 && bytes[0] == bytes[1] && bytes[0] & 0x0f == 0x0a {
        Some(write!(f, "GREASE (0x{:02x}{:02x})", bytes[0], bytes[1]))
    } else {
        None
    }
}

enum_builder! {
    /// An Application-Layer Protocol Negotiation identifier.
    ///
    /// Known values come from the
    /// [IANA ALPN Protocol IDs registry](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids).
    /// RFC 7301 protocol names contain between one and 255 octets on the wire.
    #[allow(non_camel_case_types)]
    @Bytes
    #[display_unknown = display_unknown_maybe_as_grease]
    pub enum ApplicationProtocol {
        /// HTTP/0.9.
        HTTP_09 => b"http/0.9",
        /// HTTP/1.0.
        HTTP_10 => b"http/1.0",
        /// HTTP/1.1.
        HTTP_11 => b"http/1.1",
        /// SPDY version 1.
        SPDY_1 => b"spdy/1",
        /// SPDY version 2.
        SPDY_2 => b"spdy/2",
        /// SPDY version 3.
        SPDY_3 => b"spdy/3",
        /// Traversal Using Relays around NAT.
        STUN_TURN => b"stun.turn",
        /// NAT discovery using Session Traversal Utilities for NAT.
        STUN_NAT_DISCOVERY => b"stun.nat-discovery",
        /// HTTP/2 over TLS.
        HTTP_2 => b"h2",
        /// Cleartext HTTP/2.
        HTTP_2_TCP => b"h2c",
        /// Web Real-Time Communication.
        WebRTC => b"webrtc",
        /// Confidential Web Real-Time Communication.
        CWebRTC => b"c-webrtc",
        /// File Transfer Protocol.
        FTP => b"ftp",
        /// Internet Message Access Protocol.
        IMAP => b"imap",
        /// Post Office Protocol version 3.
        POP3 => b"pop3",
        /// ManageSieve protocol.
        ManageSieve => b"managesieve",
        /// Constrained Application Protocol over TLS.
        CoAP_TLS => b"coap",
        /// Constrained Application Protocol over DTLS.
        CoAP_DTLS => b"co",
        /// XMPP client-to-server connections.
        XMPP_CLIENT => b"xmpp-client",
        /// XMPP server-to-server connections.
        XMPP_SERVER => b"xmpp-server",
        /// ACME TLS application protocol.
        ACME_TLS => b"acme-tls/1",
        /// Message Queuing Telemetry Transport.
        MQTT => b"mqtt",
        /// DNS over TLS.
        DNS_OVER_TLS => b"dot",
        /// Network Time Security key establishment.
        NTSKE_1 => b"ntske/1",
        /// Sun Remote Procedure Call.
        SunRPC => b"sunrpc",
        /// HTTP/3.
        HTTP_3 => b"h3",
        /// Server Message Block version 2.
        SMB2 => b"smb",
        /// Internet Relay Chat.
        IRC => b"irc",
        /// Network News Transfer Protocol.
        NNTP => b"nntp",
        /// Network News Transfer Protocol historical alias.
        NNSP => b"nnsp",
        /// DNS over QUIC.
        DoQ => b"doq",
        /// Session Initiation Protocol version 2.
        SIP => b"sip/2",
        /// Tabular Data Stream version 8.0.
        TDS_80 => b"tds/8.0",
        /// Digital Imaging and Communications in Medicine.
        DICOM => b"dicom",
        /// PostgreSQL wire protocol.
        PostgreSQL => b"postgresql",
    }
}

/// ALPN protocols to offer during a TLS handshake.
#[derive(Clone, Debug, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
pub struct TlsAlpn(pub SmallVec<[ApplicationProtocol; 2]>);

impl TlsAlpn {
    /// Offer no ALPN protocols.
    #[must_use]
    pub fn empty() -> Self {
        Self(SmallVec::new())
    }

    /// Offer HTTP/2 and HTTP/1.1, in that preference order.
    #[must_use]
    pub fn http_auto() -> Self {
        Self(smallvec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ])
    }

    /// Offer HTTP/1.1 only.
    #[must_use]
    pub fn http_1() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_11])
    }

    /// Offer HTTP/2 only.
    #[must_use]
    pub fn http_2() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_2])
    }
}

/// Return Rama's default TLS ALPN offer for an application protocol.
///
/// HTTP can negotiate HTTP/2 or HTTP/1.1. WebSocket defaults to HTTP/1.1
/// because HTTP/2 WebSocket support cannot be known until after ALPN
/// negotiation; an explicit target HTTP version can opt into HTTP/2.
/// Protocols without a standardized ALPN in Rama return `None`.
#[must_use]
pub fn default_tls_alpn(protocol: &Protocol) -> Option<TlsAlpn> {
    if protocol.is_http() {
        Some(TlsAlpn::http_auto())
    } else if protocol.is_ws() {
        Some(TlsAlpn::http_1())
    } else {
        None
    }
}

#[cfg(feature = "std")]
impl ApplicationProtocol {
    /// Encode one RFC 7301 length-prefixed protocol name.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::InvalidData`] when the identifier is empty
    /// or exceeds 255 octets, and forwards writer errors.
    pub fn encode_wire_format(&self, writer: &mut impl std::io::Write) -> std::io::Result<usize> {
        use rama_core::error::{BoxError, BoxErrorExt as _};

        let bytes = self.as_bytes();
        if bytes.is_empty() || bytes.len() > usize::from(u8::MAX) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                BoxError::from_static_str(
                    "application protocol must contain between 1 and 255 octets",
                ),
            ));
        }

        writer.write_all(&[bytes.len() as u8])?;
        writer.write_all(bytes)?;
        Ok(bytes.len() + 1)
    }

    /// Decode one RFC 7301 length-prefixed protocol name.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::InvalidData`] for an empty identifier and
    /// forwards reader errors.
    pub fn decode_wire_format(reader: &mut impl std::io::Read) -> std::io::Result<Self> {
        use rama_core::error::{BoxError, BoxErrorExt as _};

        let mut length = [0];
        reader.read_exact(&mut length)?;
        if length[0] == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                BoxError::from_static_str("application protocol must not be empty"),
            ));
        }

        let mut buffer = vec![0; usize::from(length[0])];
        reader.read_exact(&mut buffer)?;
        Ok(buffer.into())
    }

    /// Encode consecutive RFC 7301 length-prefixed protocol names.
    ///
    /// An empty slice produces an empty buffer, allowing callers to represent
    /// an omitted ALPN offer.
    ///
    /// # Errors
    ///
    /// Returns an error when any protocol name is invalid or writing fails.
    pub fn encode_alpns(alpns: &[Self]) -> std::io::Result<rama_core::bytes::Bytes> {
        use rama_core::bytes::{BufMut as _, BytesMut};

        let protocols =
            BytesMut::with_capacity(alpns.iter().map(|alpn| alpn.as_bytes().len() + 1).sum());
        let mut writer = protocols.writer();
        for alpn in alpns {
            alpn.encode_wire_format(&mut writer)?;
        }
        Ok(writer.into_inner().freeze())
    }
}

#[cfg(feature = "dial9")]
impl dial9_trace_format::TraceField for ApplicationProtocol {
    fn field_type() -> dial9_trace_format::types::FieldType {
        dial9_trace_format::types::FieldType::Bytes
    }

    fn encode<W: std::io::Write>(
        &self,
        encoder: &mut dial9_trace_format::EventEncoder<'_, W>,
    ) -> std::io::Result<()> {
        encoder.write_bytes(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_known_unknown_and_grease_protocols() {
        assert_eq!("http/1.1", ApplicationProtocol::HTTP_11.to_string());
        assert_eq!(
            "Unknown (h42)",
            ApplicationProtocol::from(b"h42").to_string()
        );
        for high_nibble in 0_u8..=0x0f {
            let byte = (high_nibble << 4) | 0x0a;
            assert_eq!(
                format!("GREASE (0x{byte:02x}{byte:02x})"),
                ApplicationProtocol::from(&[byte, byte]).to_string()
            );
        }
        assert_eq!(
            "Unknown (0x8a9a)",
            ApplicationProtocol::from(&[0x8a, 0x9a]).to_string()
        );
        assert_eq!("Unknown (\0)", ApplicationProtocol::from(&[0]).to_string());
    }

    #[test]
    fn derives_only_known_tls_application_protocols() {
        assert_eq!(
            default_tls_alpn(&Protocol::HTTPS).unwrap(),
            TlsAlpn::http_auto(),
        );
        assert_eq!(default_tls_alpn(&Protocol::WSS).unwrap(), TlsAlpn::http_1(),);
        assert!(default_tls_alpn(&Protocol::ICAPS).is_none());
        assert!(default_tls_alpn(&Protocol::from_static("custom")).is_none());
    }

    #[test]
    fn wire_format_round_trips_boundaries() {
        for bytes in [vec![b'a'], vec![b'x'; 255]] {
            let protocol = ApplicationProtocol::from(bytes.clone());
            let mut encoded = Vec::new();
            assert_eq!(
                protocol.encode_wire_format(&mut encoded).unwrap(),
                bytes.len() + 1
            );
            assert_eq!(usize::from(encoded[0]), bytes.len());
            assert_eq!(&encoded[1..], bytes);
            assert_eq!(
                ApplicationProtocol::decode_wire_format(&mut encoded.as_slice()).unwrap(),
                protocol
            );
        }
    }

    #[test]
    fn wire_format_rejects_empty_and_oversized_names() {
        for bytes in [Vec::new(), vec![b'x'; 256]] {
            let error = ApplicationProtocol::from(bytes)
                .encode_wire_format(&mut Vec::new())
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }

        let error = ApplicationProtocol::decode_wire_format(&mut [0].as_slice()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decodes_consecutive_protocol_names() {
        const INPUT: &[u8] = b"\x02h2\x08http/1.1";
        let mut reader = INPUT;
        assert_eq!(
            ApplicationProtocol::decode_wire_format(&mut reader).unwrap(),
            ApplicationProtocol::HTTP_2
        );
        assert_eq!(
            ApplicationProtocol::decode_wire_format(&mut reader).unwrap(),
            ApplicationProtocol::HTTP_11
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn serializes_known_and_unknown_protocols() {
        for protocol in [
            ApplicationProtocol::HTTP_3,
            ApplicationProtocol::from(b"foobar"),
        ] {
            let encoded = serde_json::to_string(&protocol).unwrap();
            assert_eq!(
                serde_json::from_str::<ApplicationProtocol>(&encoded).unwrap(),
                protocol
            );
        }
    }
}
