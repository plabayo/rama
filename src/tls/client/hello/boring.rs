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
        parse_client_hello_from_bytes(value.as_bytes()).context("parse boring ssl ClientHello")
    }
}

fn parse_client_hello_from_bytes(
    raw_client_hello: &[u8],
) -> Result<super::ClientHello, OpaqueError> {
    let (rem, tls_handshake) = tls_parser::parse_tls_handshake_msg_client_hello(raw_client_hello)
        .map_err(|err| {
        OpaqueError::from_display(format!("parse raw client hello handshake message: {err:?}"))
    })?;
    if !rem.is_empty() {
        return Err(OpaqueError::from_display("unexpected trailer data (rem>0)"));
    }

    let client_hello = match &tls_handshake {
        tls_parser::TlsMessageHandshake::ClientHello(hello) => hello,
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
            let (new_ext, parsed_ext) = tls_parser::parse_tls_extension(ext).map_err(|err| {
                OpaqueError::from_display(format!("parse client hello extension: {err:?}"))
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
                    // sanity checks
                    let total_size = ext.len() - new_ext.len();
                    if total_size < 4 {
                        return Err(OpaqueError::from_display(
                            "too small raw tls extension byte lenght",
                        ));
                    }
                    if total_size > u16::MAX as usize {
                        return Err(OpaqueError::from_display(
                            "tls extension byte lenght overflow",
                        ));
                    }
                    let reported_size: u16 = u8_pair_to_u16_enum((ext[2], ext[3]));
                    if reported_size != (total_size - 4) as u16 {
                        return Err(OpaqueError::from_display(
                            "unexpected raw tls extension byte lenght",
                        ));
                    }

                    // other then this, all can be
                    extensions.push(ClientHelloExtension::Opaque {
                        id: u8_pair_to_u16_enum((ext[0], ext[1])),
                        data: ext[4..total_size].to_vec(),
                    });
                }
            }
            ext = new_ext;
        }
    }

    Ok(super::ClientHello {
        cipher_suites,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use crate::tls::ExtensionId;

    use super::*;

    #[test]
    fn test_parse_raw_client_hello_zero_bytes_failure() {
        assert!(parse_client_hello_from_bytes(&[]).is_err());
    }

    #[test]
    fn test_parse_raw_client_hello_pcap_dump_apple_itunes_bytes_success() {
        let client_hello = parse_client_hello_from_bytes(&[
            0x03, 0x03, 0x74, 0xbd, 0x2a, 0x45, 0x51, 0x29, 0x95, 0x42, 0x61, 0x17, 0xab, 0x20,
            0x8f, 0xf2, 0x30, 0xea, 0x72, 0x0f, 0x2e, 0xcd, 0x73, 0xff, 0xcb, 0xbc, 0x89, 0x10,
            0x46, 0xc8, 0xb7, 0x3c, 0x31, 0xf0, 0x20, 0x25, 0xea, 0x68, 0xb2, 0x13, 0x62, 0xf7,
            0x4b, 0x0f, 0x82, 0x57, 0xf6, 0xe9, 0x41, 0xc5, 0x28, 0x74, 0xa9, 0xf4, 0x80, 0x73,
            0x90, 0x4f, 0x85, 0xe7, 0xa7, 0xaa, 0x84, 0x37, 0xe8, 0xdf, 0x97, 0x00, 0x2a, 0x7a,
            0x7a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b, 0xcc, 0xa9, 0xc0,
            0x30, 0xc0, 0x2f, 0xcc, 0xa8, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00,
            0x9d, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a, 0x01,
            0x00, 0x01, 0x89, 0x8a, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00,
            0x00, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x2e, 0x69, 0x74, 0x75, 0x6e, 0x65, 0x73, 0x2e,
            0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0xff,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x3a, 0x3a, 0x00, 0x1d,
            0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10,
            0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
            0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
            0x18, 0x00, 0x16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x02, 0x03, 0x08,
            0x05, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00,
            0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x1d,
            0x00, 0x20, 0x49, 0xee, 0x60, 0xa1, 0x29, 0xc0, 0x44, 0x44, 0xc3, 0x02, 0x8a, 0x25,
            0x8c, 0x86, 0x64, 0xc3, 0x3a, 0xc0, 0xec, 0xbb, 0x6c, 0xe7, 0x93, 0xda, 0x51, 0xca,
            0xef, 0x59, 0xc9, 0xee, 0x41, 0x31, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b,
            0x00, 0x0b, 0x0a, 0xda, 0xda, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00,
            0x1b, 0x00, 0x03, 0x02, 0x00, 0x01, 0xda, 0xda, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00,
            0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])
        .expect("to parse");
        assert_eq!(
            client_hello.cipher_suites(),
            &[
                CipherSuite::from(0x7a7a),
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            ]
        );
        assert_eq!(client_hello.extensions().len(), 16);

        assert_eq_opaque_extension(
            &client_hello.extensions()[0],
            ExtensionId::from(0x8a8a),
            &[],
        );
        assert_eq_server_name_extension(
            &client_hello.extensions()[1],
            &Domain::from_static("init.itunes.apple.com"),
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[2],
            ExtensionId::EXTENDED_MASTER_SECRET,
            &[],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[3],
            ExtensionId::RENEGOTIATION_INFO,
            &[0x00],
        );
        assert_eq_supported_groups_extension(
            &client_hello.extensions()[4],
            &[
                SupportedGroup::from(0x3a3a),
                SupportedGroup::X25519,
                SupportedGroup::SECP256R1,
                SupportedGroup::SECP384R1,
                SupportedGroup::SECP521R1,
            ],
        );
        assert_eq_ec_point_formats_extension(
            &client_hello.extensions()[5],
            &[ECPointFormat::Uncompressed],
        );
        assert_eq_alpn_extension(
            &client_hello.extensions()[6],
            &[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[7],
            ExtensionId::STATUS_REQUEST,
            &[0x01, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq_signature_algorithms_extension(
            &client_hello.extensions()[8],
            &[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA1,
            ],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[9],
            ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP,
            &[],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[10],
            ExtensionId::KEY_SHARE,
            &[
                0x00, 0x29, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x49, 0xee, 0x60,
                0xa1, 0x29, 0xc0, 0x44, 0x44, 0xc3, 0x02, 0x8a, 0x25, 0x8c, 0x86, 0x64, 0xc3, 0x3a,
                0xc0, 0xec, 0xbb, 0x6c, 0xe7, 0x93, 0xda, 0x51, 0xca, 0xef, 0x59, 0xc9, 0xee, 0x41,
                0x31,
            ],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[11],
            ExtensionId::PSK_KEY_EXCHANGE_MODES,
            &[0x01, 0x01],
        );
        assert_eq_supported_versions_extension(
            &client_hello.extensions()[12],
            &[
                ProtocolVersion::from(0xdada),
                ProtocolVersion::TLSv1_3,
                ProtocolVersion::TLSv1_2,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_0,
            ],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[13],
            ExtensionId::COMPRESS_CERTIFICATE,
            &[0x02, 0x00, 0x01],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[14],
            ExtensionId::from(0xdada), // GREASE
            &[0x00],
        );
        assert_eq_opaque_extension(
            &client_hello.extensions()[15],
            ExtensionId::from(0x0015), // padding
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00,
            ],
        );
    }

    fn assert_eq_opaque_extension(
        ext: &ClientHelloExtension,
        expected_id: ExtensionId,
        expected_data: &[u8],
    ) {
        match ext {
            ClientHelloExtension::Opaque { id, data } => {
                assert_eq!(*id, expected_id);
                assert_eq!(data, expected_data);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_server_name_extension(ext: &ClientHelloExtension, expected_domain: &Domain) {
        match ext {
            ClientHelloExtension::ServerName(domain) => {
                assert_eq!(domain, expected_domain);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_supported_groups_extension(
        ext: &ClientHelloExtension,
        expected_groups: &[SupportedGroup],
    ) {
        match ext {
            ClientHelloExtension::SupportedGroups(groups) => {
                assert_eq!(groups, expected_groups);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_ec_point_formats_extension(
        ext: &ClientHelloExtension,
        expected_ec_point_formats: &[ECPointFormat],
    ) {
        match ext {
            ClientHelloExtension::ECPointFormats(points) => {
                assert_eq!(points, expected_ec_point_formats);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_alpn_extension(
        ext: &ClientHelloExtension,
        expected_alpn_list: &[ApplicationProtocol],
    ) {
        match ext {
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn_list) => {
                assert_eq!(alpn_list, expected_alpn_list);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_signature_algorithms_extension(
        ext: &ClientHelloExtension,
        expected_signature_algorithms: &[SignatureScheme],
    ) {
        match ext {
            ClientHelloExtension::SignatureAlgorithms(algorithms) => {
                assert_eq!(algorithms, expected_signature_algorithms);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    fn assert_eq_supported_versions_extension(
        ext: &ClientHelloExtension,
        expected_version_list: &[ProtocolVersion],
    ) {
        match ext {
            ClientHelloExtension::SupportedVersions(version_list) => {
                assert_eq!(version_list, expected_version_list);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }
}
