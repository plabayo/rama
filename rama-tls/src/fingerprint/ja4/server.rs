use std::fmt;

use rama_core::extensions::Extensions;
use rama_net::tls::ApplicationProtocol;

use super::{
    alpn_markers,
    tls::{Ja4ComputeError, TlsVersion, TransportProtocol},
    write_hash12, write_hex_list,
};
use crate::{CipherSuite, ExtensionId, client::NegotiatedTlsParameters, server::ServerHello};

#[derive(Clone, PartialEq)]
/// Input data for a "ja4s" hash: a server's answer to a ClientHello.
///
/// Computed using [`Ja4S::compute`] or [`Ja4S::compute_from_server_hello`].
pub struct Ja4S {
    protocol: TransportProtocol,
    version: TlsVersion,
    alpn: Option<ApplicationProtocol>,
    cipher_suite: CipherSuite,
    extensions: Vec<ExtensionId>,
}

impl Ja4S {
    /// Compute the [`Ja4S`] of the ServerHello a client connection stored in its
    /// [`NegotiatedTlsParameters`] (see `TlsClientConfig::store_server_hello`).
    ///
    /// As specified by <https://blog.foxio.io/ja4%2B-network-fingerprinting>
    /// and reference implementations found at <https://github.com/FoxIO-LLC/ja4>.
    pub fn compute(ext: &Extensions) -> Result<Self, Ja4ComputeError> {
        let hello = ext
            .get_ref::<NegotiatedTlsParameters>()
            .and_then(|params| params.server_hello.as_ref())
            .ok_or(Ja4ComputeError::MissingServerHello)?;
        Self::compute_from_server_hello(hello)
    }

    /// Compute the [`Ja4S`] of a [`ServerHello`]: its extensions keep the order the server
    /// sent them in, GREASE included.
    pub fn compute_from_server_hello(hello: &ServerHello) -> Result<Self, Ja4ComputeError> {
        Ok(Self {
            protocol: if hello.is_quic() {
                TransportProtocol::Quic
            } else {
                TransportProtocol::Tcp
            },
            version: hello.protocol_version().try_into()?,
            alpn: hello.alpn().cloned(),
            cipher_suite: hello.cipher_suite(),
            extensions: hello.extensions().to_vec(),
        })
    }

    #[inline]
    #[must_use]
    pub fn to_human_string(&self) -> String {
        format!("{self:?}")
    }

    fn write_extensions(&self, writer: &mut (impl fmt::Write + ?Sized)) -> fmt::Result {
        write_hex_list(writer, &self.extensions)
    }

    fn fmt_as(&self, f: &mut fmt::Formatter<'_>, hash_chunks: bool) -> fmt::Result {
        let nr_exts = 99.min(self.extensions.len());
        let (alpn_0, alpn_1) = alpn_markers(self.alpn.as_ref());
        write!(
            f,
            "{}{}{nr_exts:02}{alpn_0}{alpn_1}_{:04x}_",
            self.protocol,
            self.version,
            u16::from(self.cipher_suite)
        )?;
        if hash_chunks {
            write_hash12(f, |writer| self.write_extensions(writer))
        } else {
            self.write_extensions(f)
        }
    }
}

impl fmt::Display for Ja4S {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, true)
    }
}

impl fmt::Debug for Ja4S {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(f, false)
    }
}

rama_utils::macros::serde_str::impl_serde_str!(serialize display Ja4S);

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello(cipher: u16, extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut extensions_bytes = Vec::new();
        for (id, data) in extensions {
            extensions_bytes.extend_from_slice(&id.to_be_bytes());
            extensions_bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            extensions_bytes.extend_from_slice(data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x42; 32]);
        body.push(32);
        body.extend_from_slice(&[0x17; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&u16::try_from(extensions_bytes.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions_bytes);
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut message = vec![2, len[1], len[2], len[3]];
        message.extend_from_slice(&body);
        message
    }

    const TLS13: &[u8] = &[0x03, 0x04];
    const X25519_SHARE: &[u8] = &[
        0x00, 0x1d, 0x00, 0x20, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    ];

    #[test]
    fn tls13_server_hellos_match_the_published_vectors() {
        // FoxIO's examples: the extension order is part of the fingerprint.
        let hello = server_hello(0x1301, &[(0x002b, TLS13), (0x0033, X25519_SHARE)]);
        let ja4s = Ja4S::compute_from_server_hello(&ServerHello::parse_handshake(&hello).unwrap())
            .unwrap();
        assert_eq!(ja4s.to_string(), "t130200_1301_a56c5b993250");
        assert_eq!(ja4s.to_human_string(), "t130200_1301_002b,0033");

        let hello = server_hello(0x1301, &[(0x0033, X25519_SHARE), (0x002b, TLS13)]);
        let ja4s = Ja4S::compute_from_server_hello(&ServerHello::parse_handshake(&hello).unwrap())
            .unwrap();
        assert_eq!(ja4s.to_string(), "t130200_1301_234ea6891581");
    }

    #[test]
    fn a_quic_server_hello_is_marked_as_such() {
        let hello = server_hello(0x1302, &[(0x0033, X25519_SHARE), (0x002b, TLS13)]);
        let ja4s =
            Ja4S::compute_from_server_hello(&ServerHello::parse_quic_handshake(&hello).unwrap())
                .unwrap();
        assert_eq!(ja4s.to_human_string(), "q130200_1302_0033,002b");
    }

    #[test]
    fn a_tls12_server_hello_reports_its_alpn_and_legacy_version() {
        let alpn: &[u8] = &[0x00, 0x03, 0x02, b'h', b'2'];
        let hello = server_hello(0xc02f, &[(0xff01, &[0]), (0x0010, alpn), (0x000b, &[1, 0])]);
        let ja4s = Ja4S::compute_from_server_hello(&ServerHello::parse_handshake(&hello).unwrap())
            .unwrap();
        assert_eq!(ja4s.to_human_string(), "t1203h2_c02f_ff01,0010,000b");
        let hello = server_hello(0x009c, &[]);
        let ja4s = Ja4S::compute_from_server_hello(&ServerHello::parse_handshake(&hello).unwrap())
            .unwrap();
        assert_eq!(ja4s.to_string(), "t120000_009c_000000000000");
    }

    #[test]
    fn a_single_character_alpn_supplies_both_markers() {
        let alpn: &[u8] = &[0x00, 0x02, 0x01, b'x'];
        let hello = server_hello(0x1301, &[(0x002b, TLS13), (0x0010, alpn)]);
        let ja4s = Ja4S::compute_from_server_hello(&ServerHello::parse_handshake(&hello).unwrap())
            .unwrap();
        assert!(ja4s.to_string().starts_with("t1302xx_1301_"), "{ja4s}");
    }

    #[test]
    fn a_connection_reports_the_server_hello_it_stored() {
        let hello = server_hello(0x1301, &[(0x002b, TLS13), (0x0033, X25519_SHARE)]);
        let mut params = NegotiatedTlsParameters {
            protocol_version: crate::ProtocolVersion::TLSv1_3,
            application_layer_protocol: None,
            peer_certificate_chain: None,
            server_name: None,
            resumed: None,
            algorithms: Default::default(),
            server_hello: None,
        };
        let ext = Extensions::new();
        ext.insert(params.clone());
        assert!(matches!(
            Ja4S::compute(&ext),
            Err(Ja4ComputeError::MissingServerHello)
        ));
        params.server_hello = Some(ServerHello::parse_handshake(&hello).unwrap());
        ext.insert(params);
        assert_eq!(
            Ja4S::compute(&ext).unwrap().to_string(),
            "t130200_1301_a56c5b993250"
        );
    }
}
