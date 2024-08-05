use super::ClientHelloExtension;
use crate::error::{ErrorContext, OpaqueError};
use crate::net::address::Domain;
use crate::tls::boring::dep::boring;
use crate::tls::{
    ApplicationProtocol, CipherSuite, ECPointFormat, ProtocolVersion, SignatureScheme,
    SupportedGroup,
};

#[inline]
fn u8_pair_to_u16_enum<T: From<u16>>((msb, lsb): (u8, u8)) -> T {
    let n = ((msb as u16) << 8) | (lsb as u16);
    T::from(n)
}

impl<'ssl> TryFrom<boring::ssl::ClientHello<'ssl>> for super::ClientHello {
    type Error = OpaqueError;

    fn try_from(value: boring::ssl::ClientHello<'ssl>) -> Result<Self, Self::Error> {
        let (_, msg) =
            tls_parser::parse_tls_message_handshake(value.as_bytes()).map_err(|err| {
                OpaqueError::from_display(format!("parse boring client hello: {err:?}"))
            })?;

        let client_hello = match &msg {
            tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(
                hello,
            )) => hello,
            _ => return Err(OpaqueError::from_display("unexpected tls message parsed")),
        };

        let cipher_suites: Vec<_> = client_hello
            .ciphers
            .iter()
            .map(|c| CipherSuite::from(c.0))
            .collect();

        let mut extensions = Vec::new();
        if let Some(mut ext) = client_hello.ext {
            while !ext.is_empty() {
                let (new_ext, parsed_ext) =
                    tls_parser::parse_tls_extension(ext).map_err(|err| {
                        OpaqueError::from_display(format!(
                            "parse boring client hello extension: {err:?}"
                        ))
                    })?;
                match parsed_ext {
                    tls_parser::TlsExtension::SNI(list) => {
                        if list.len() != 1 {
                            return Err(OpaqueError::from_display(
                                "one and only 1 server name expected",
                            ));
                        }
                        if list[0].0 != tls_parser::SNIType::HostName {
                            return Err(OpaqueError::from_display("unexpected SNI type"));
                        }
                        let domain =
                            Domain::try_from(list[0].1).context("parse server name as domain")?;
                        extensions.push(ClientHelloExtension::ServerName(domain));
                    }
                    tls_parser::TlsExtension::EllipticCurves(v) => {
                        extensions.push(ClientHelloExtension::SupportedGroups(
                            v.iter().map(|c| SupportedGroup::from(c.0)).collect(),
                        ));
                    }
                    tls_parser::TlsExtension::EcPointFormats(s) => {
                        extensions.push(ClientHelloExtension::ECPointFormats(
                            s.iter().map(|u| ECPointFormat::from(*u)).collect(),
                        ));
                    }
                    tls_parser::TlsExtension::SignatureAlgorithms(v) => {
                        extensions.push(ClientHelloExtension::SignatureAlgorithms(
                            v.iter().map(|u| SignatureScheme::from(*u)).collect(),
                        ));
                    }
                    tls_parser::TlsExtension::ALPN(v) => {
                        extensions.push(ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                            v.iter().map(|u| ApplicationProtocol::from(*u)).collect(),
                        ));
                    }
                    tls_parser::TlsExtension::SupportedVersions(v) => {
                        extensions.push(ClientHelloExtension::SupportedVersions(
                            v.iter().map(|v| ProtocolVersion::from(v.0)).collect(),
                        ));
                    }
                    _ => {
                        let total_size = ext.len() - new_ext.len();
                        if total_size <= 4 {
                            return Err(OpaqueError::from_display(
                                "unexpected raw tls extension byte lenght",
                            ));
                        }
                        extensions.push(ClientHelloExtension::Opaque {
                            id: u8_pair_to_u16_enum((ext[0], ext[1])),
                            data: ext[4..total_size].to_vec(),
                        });
                    }
                }
                ext = new_ext;
            }
        }

        Ok(Self {
            cipher_suites,
            extensions,
        })
    }
}
