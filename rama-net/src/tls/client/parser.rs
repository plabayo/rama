//! Perma-forked from
//! tls-parser @ 65a2fe0b86f09235515337c501c8a512db1c6dba
//!
//! src and attribution: <https://github.com/rusticata/tls-parser>

use super::hello::{ECHClientHello, ECHClientHelloOuter, HpkeSymmetricCipherSuite};
use super::{ClientHello, ClientHelloExtension};
use crate::address::{Domain, Host};
use crate::tls::{
    ApplicationProtocol, CipherSuite, ExtensionId, ProtocolVersion, enums::CompressionAlgorithm,
};
use nom::{
    IResult, Parser,
    bytes::streaming::take,
    combinator::{complete, cond, map, map_opt, map_parser, opt, verify},
    error::{ErrorKind, make_error},
    multi::{length_data, many0},
    number::streaming::{be_u8, be_u16},
};
use rama_core::error::{BoxError, ErrorExt as _};
use std::str;

/// Parse a [`ClientHello`] from the raw "wire" bytes.
///
/// This function is not infallible, it can return an error if the input is not a valid
/// TLS ClientHello message or if there is unexpected trailing data.
pub fn parse_client_hello(i: &[u8]) -> Result<ClientHello, BoxError> {
    match parse_client_hello_inner(i) {
        Err(err) => Err(BoxError::from("parse client hello handshake message")
            .context_debug_field("err", err.to_owned())),
        Ok((i, hello)) => {
            if i.is_empty() {
                Ok(hello)
            } else {
                Err(BoxError::from(
                    "parse client hello handshake message: unexpected trailer content",
                ))
            }
        }
    }
}

/// Parse a [`ClientHello`] from the raw incoming "wire" client handshake bytes to find the SNI Host value.
///
/// Same as [`extract_sni_from_client_hello_record`] but handles the full handshake bytes, meaning
/// the client hello record itself and the handshake header bytes in front of it.
pub fn extract_sni_from_client_hello_handshake(i: &[u8]) -> Result<Option<Domain>, BoxError> {
    parse_client_hello_handshake_sni_inner(i)
        .map(|(_, domain)| domain)
        .map_err(|err| {
            BoxError::from("parse client hello handshake message to find SNI")
                .context_debug_field("err", err.to_owned())
        })
}

/// Parse a [`ClientHello`] from the raw "wire" bytes to find the SNI Host value.
///
/// This function is optimised to find the SNI value and nothing else.
/// Use [`parse_client_hello`] in case you need other content in the client hello,
/// or the client hello as a whole.
///
/// This function is not infallible, it can return an error if the input is not a valid
/// TLS ClientHello message or if there is unexpected trailing data.
/// It will return None on a value ClientHello without a SNI Host value.
pub fn extract_sni_from_client_hello_record(i: &[u8]) -> Result<Option<Domain>, BoxError> {
    parse_client_hello_record_sni_inner(i)
        .map(|(_, domain)| domain)
        .map_err(|err| {
            BoxError::from("parse client hello record message to find SNI")
                .context_debug_field("err", err.to_owned())
        })
}

fn parse_client_hello_handshake_sni_inner(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    // verify content type and tls version
    let (i, _) = verify(take(3usize), |s: &[u8]| {
        matches!(s, [0x16, 0x03, 0x00..=0x04])
    })
    .parse(i)?;

    // skip record length
    let (i, _) = be_u16(i)?;

    // verify handshake type and drop the handshake length
    let (i, _) = verify(take(4usize), |s: &[u8]| matches!(s, [0x01, ..])).parse(i)?;

    // now it's time for the record
    parse_client_hello_record_sni_inner(i)
}

fn parse_client_hello_record_sni_inner(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    // skip version and random
    let (i, _) = take(34usize)(i)?;

    // skip sid
    let (i, sidlen) = verify(be_u8, |&n| n <= 32).parse(i)?;
    let (i, _) = cond(sidlen > 0, take(sidlen as usize)).parse(i)?;

    // skip ciphers
    let (i, ciphers_len) = be_u16(i)?;
    let (i, _) = take(ciphers_len)(i)?;

    // skip compression algos
    let (i, comp_len) = be_u8(i)?;
    let (i, _) = take(comp_len)(i)?;

    // start the actual search for the SNI... the one to rule them all
    let (_, opt_ext) = opt(complete(length_data(be_u16))).parse(i)?;
    if let Some(mut i) = opt_ext {
        while !i.is_empty() {
            let (new_i, domain) = parse_tls_client_hello_extension_sni_host_or_skip(i)?;
            if let Some(domain) = domain {
                return Ok((new_i, Some(domain)));
            }
            i = new_i;
        }
    }

    // no SNI found...
    Ok((&[], None))
}

fn parse_client_hello_inner(i: &[u8]) -> IResult<&[u8], ClientHello> {
    let (i, version) = be_u16(i)?;
    let (i, _random) = take(32usize)(i)?;
    let (i, sidlen) = verify(be_u8, |&n| n <= 32).parse(i)?;
    let (i, _sid) = cond(sidlen > 0, take(sidlen as usize)).parse(i)?;
    let (i, ciphers_len) = be_u16(i)?;
    let (i, cipher_suites) = parse_cipher_suites(i, ciphers_len as usize)?;
    let (i, comp_len) = be_u8(i)?;
    let (i, compression_algorithms) = parse_compressions_algs(i, comp_len as usize)?;
    let (i, opt_ext) = opt(complete(length_data(be_u16))).parse(i)?;

    let mut extensions = vec![];
    if let Some(mut i) = opt_ext {
        while !i.is_empty() {
            let (new_i, ch_ext) = parse_tls_client_hello_extension(i)?;
            extensions.push(ch_ext);
            i = new_i;
        }
    }

    Ok((
        i,
        ClientHello {
            protocol_version: version.into(),
            cipher_suites,
            compression_algorithms,
            extensions,
        },
    ))
}

fn parse_cipher_suites(i: &[u8], len: usize) -> IResult<&[u8], Vec<CipherSuite>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| CipherSuite::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_compressions_algs(i: &[u8], len: usize) -> IResult<&[u8], Vec<CompressionAlgorithm>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .iter()
        .map(|&it| CompressionAlgorithm::from(it))
        .collect();
    Ok((&i[len..], v))
}

fn parse_tls_client_hello_extension_sni_host_or_skip(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    let (i, ext_type) = be_u16(i)?;
    let id = ExtensionId::from(ext_type);
    let (i, ext_data) = length_data(be_u16).parse(i)?;

    if id == ExtensionId::SERVER_NAME {
        parse_tls_extension_sni(ext_data)
    } else {
        Ok((i, None))
    }
}

fn parse_tls_client_hello_extension(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, ext_type) = be_u16(i)?;
    let id = ExtensionId::from(ext_type);
    let (i, ext_data) = length_data(be_u16).parse(i)?;

    let ext_len = ext_data.len() as u16;

    let (_, ext) = match id {
        ExtensionId::SERVER_NAME => parse_tls_extension_sni_content(ext_data),
        ExtensionId::SUPPORTED_GROUPS => parse_tls_extension_elliptic_curves_content(ext_data),
        ExtensionId::EC_POINT_FORMATS => parse_tls_extension_ec_point_formats_content(ext_data),
        ExtensionId::SIGNATURE_ALGORITHMS => {
            parse_tls_extension_signature_algorithms_content(ext_data)
        }
        ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
            parse_tls_extension_alpn_content(ext_data)
        }
        ExtensionId::SUPPORTED_VERSIONS => {
            parse_tls_extension_supported_versions_content(ext_data, ext_len)
        }
        ExtensionId::COMPRESS_CERTIFICATE => {
            parse_tls_extension_certificate_compression_content(ext_data)
        }
        ExtensionId::DELEGATED_CREDENTIAL => parse_tls_extension_delegated_credentials(ext_data),
        ExtensionId::RECORD_SIZE_LIMIT => {
            let (i, v) = be_u16(ext_data)?;
            Ok((i, ClientHelloExtension::RecordSizeLimit(v)))
        }
        ExtensionId::ENCRYPTED_CLIENT_HELLO => {
            let (i, ech) = parse_ech_client_hello(ext_data)?;
            Ok((i, ClientHelloExtension::EncryptedClientHello(ech)))
        }
        ExtensionId::APPLICATION_SETTINGS | ExtensionId::OLD_APPLICATION_SETTINGS => {
            parse_tls_extension_application_settings_content(ext_data)
        }
        _ => Ok((
            i,
            ClientHelloExtension::Opaque {
                id,
                data: ext_data.to_vec(),
            },
        )),
    }?;
    Ok((i, ext))
}

// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
fn parse_tls_extension_sni_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    let (i, domain) = parse_tls_extension_sni(i)?;
    Ok((i, ClientHelloExtension::ServerName(domain)))
}

// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
fn parse_tls_extension_sni(i: &[u8]) -> IResult<&[u8], Option<Domain>> {
    if i.is_empty() {
        // special case: SNI extension in server can be empty
        return Ok((i, None));
    }
    let (i, list_len) = be_u16(i)?;
    let (i, mut v) = map_parser(
        take(list_len),
        many0(complete(parse_tls_extension_sni_hostname)),
    )
    .parse(i)?;
    if v.len() > 1 {
        return Err(nom::Err::Error(nom::error::Error::new(
            i,
            ErrorKind::TooLarge,
        )));
    }
    Ok((i, v.pop()))
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
fn parse_tls_extension_sni_hostname(i: &[u8]) -> IResult<&[u8], Domain> {
    let (i, nt) = be_u8(i)?;
    if nt != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(i, ErrorKind::IsNot)));
    }
    let (i, v) = length_data(be_u16).parse(i)?;
    let host = str::from_utf8(v)
        .map_err(|_| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?
        .parse()
        .map_err(|_| nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not)))?;

    match host {
        Host::Address(_) => Err(nom::Err::Error(nom::error::Error::new(i, ErrorKind::Not))),
        Host::Name(domain) => Ok((i, domain)),
    }
}

// defined in rfc8422
fn parse_tls_extension_elliptic_curves_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SupportedGroups),
    )
    .parse(i)
}

fn parse_tls_extension_ec_point_formats_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u8_type, ClientHelloExtension::ECPointFormats),
    )
    .parse(i)
}

// TLS 1.3 draft 23
//       struct {
//           select (Handshake.msg_type) {
//               case client_hello:
//                    ProtocolVersion versions<2..254>;
//
//               case server_hello: /* and HelloRetryRequest */
//                    ProtocolVersion selected_version;
//           };
//       } SupportedVersions;
// XXX the content depends on the current message type
// XXX first case has length 1 + 2*n, while the second case has length 2
fn parse_tls_extension_supported_versions_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], ClientHelloExtension> {
    if ext_len == 2 {
        map(be_u16, |x| {
            ClientHelloExtension::SupportedVersions(vec![ProtocolVersion::from(x)])
        })
        .parse(i)
    } else {
        let (i, _) = be_u8(i)?;
        if ext_len == 0 {
            return Err(nom::Err::Error(make_error(i, ErrorKind::Verify)));
        }
        let (i, l) = map_parser(take(ext_len - 1), parse_u16_type).parse(i)?;
        Ok((i, ClientHelloExtension::SupportedVersions(l)))
    }
}

/// Parse 'Signature Algorithms' extension (rfc8446, TLS 1.3 only)
fn parse_tls_extension_signature_algorithms_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::SignatureAlgorithms),
    )
    .parse(i)
}

// Parse 'Delegated credentials' extensions (rfc9345)
fn parse_tls_extension_delegated_credentials(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_u16_type, ClientHelloExtension::DelegatedCredentials),
    )
    .parse(i)
}

/// Defined in [RFC7301]
fn parse_tls_extension_alpn_content(i: &[u8]) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(
            parse_protocol_name_list,
            ClientHelloExtension::ApplicationLayerProtocolNegotiation,
        ),
    )
    .parse(i)
}

fn parse_tls_extension_certificate_compression_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u8),
        map(parse_u16_type, ClientHelloExtension::CertificateCompression),
    )
    .parse(i)
}

fn parse_protocol_name_list(mut i: &[u8]) -> IResult<&[u8], Vec<ApplicationProtocol>> {
    let mut v = vec![];
    while !i.is_empty() {
        let (n, alpn) = map_parser(length_data(be_u8), parse_protocol_name).parse(i)?;
        v.push(alpn);
        i = n;
    }
    Ok((&[], v))
}

fn parse_protocol_name(i: &[u8]) -> IResult<&[u8], ApplicationProtocol> {
    let alpn = ApplicationProtocol::from(i);
    Ok((&[], alpn))
}

fn parse_tls_extension_application_settings_content(
    i: &[u8],
) -> IResult<&[u8], ClientHelloExtension> {
    map_parser(
        length_data(be_u16),
        map(
            parse_protocol_name_list,
            ClientHelloExtension::ApplicationSettings,
        ),
    )
    .parse(i)
}

fn parse_u8_type<T: From<u8>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let v = i.iter().map(|i| T::from(*i)).collect();
    Ok((&[], v))
}

fn parse_u16_type<T: From<u16>>(i: &[u8]) -> IResult<&[u8], Vec<T>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(nom::Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| T::from(((chunk[0] as u16) << 8) | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_ech_client_hello(input: &[u8]) -> IResult<&[u8], ECHClientHello> {
    let (input, is_outer) = map_opt(be_u8, |v| match v {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    })
    .parse(input)?;

    match is_outer {
        true => {
            let (input, (kdf_id, aead_id, config_id)) = (be_u16, be_u16, be_u8).parse(input)?;
            let (input, enc) = length_data(be_u16).parse(input)?;
            let (input, payload) = length_data(be_u16).parse(input)?;

            Ok((
                input,
                ECHClientHello::Outer(ECHClientHelloOuter {
                    cipher_suite: HpkeSymmetricCipherSuite {
                        aead_id: aead_id.into(),
                        kdf_id: kdf_id.into(),
                    },
                    config_id,
                    enc: enc.to_vec(),
                    payload: payload.to_vec(),
                }),
            ))
        }
        false => Ok((input, ECHClientHello::Inner)),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::address::Domain;
    use crate::tls::{
        CertificateCompressionAlgorithm, ECPointFormat, ExtensionId, SignatureScheme,
        SupportedGroup,
    };

    #[test]
    fn test_parse_tls_extension_sni_hostname() {
        let test_cases = [
            ("", None),
            ("\x00", None),
            ("\x00\x00\x05x.com", Some(Domain::from_static("x.com"))),
            (
                "\x00\x00\x10fp.ramaproxy.org",
                Some(Domain::from_static("fp.ramaproxy.org")),
            ),
            ("\x00\x00\x11fp.ramaproxy.org", None),
            ("\x01\x00\x10fp.ramaproxy.org", None),
            ("\x00\x00\x09127.0.0.1", None),
            ("\x00\x00\x276670:2e72:616d:6170:726f:7879:2e6f:7267", None),
        ];
        for (input, expected_output) in test_cases {
            let result = parse_tls_extension_sni_hostname(input.as_bytes());
            match expected_output {
                Some(domain) => assert_eq!(domain, result.unwrap().1),
                None => assert!(result.is_err()),
            }
        }
    }

    #[test]
    fn test_parse_client_hello_zero_bytes_failure() {
        assert!(parse_client_hello(&[]).is_err());
    }

    #[test]
    fn test_parse_client_hello_pcap_dump_apple_itunes_bytes_success() {
        let client_hello = parse_client_hello(&[
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
            Some(&Domain::from_static("init.itunes.apple.com")),
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
        assert_eq_supported_certificate_compression_extension(
            &client_hello.extensions()[13],
            &[CertificateCompressionAlgorithm::Zlib],
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

    fn assert_eq_server_name_extension(
        ext: &ClientHelloExtension,
        expected_domain: Option<&Domain>,
    ) {
        match ext {
            ClientHelloExtension::ServerName(domain) => {
                assert_eq!(domain.as_ref(), expected_domain);
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

    fn assert_eq_supported_certificate_compression_extension(
        ext: &ClientHelloExtension,
        expected_certificate_compression: &[CertificateCompressionAlgorithm],
    ) {
        match ext {
            ClientHelloExtension::CertificateCompression(algorithms) => {
                assert_eq!(algorithms, expected_certificate_compression);
            }
            other => {
                panic!("unexpected extension: {other:?}");
            }
        }
    }

    #[test]
    fn test_extract_sni_from_client_hello_handshake() {
        #[allow(clippy::single_element_loop)]
        for (content, expected_sni) in [(
            &[
                0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x02, 0x15, 0xfd,
                0xe2, 0x92, 0xc0, 0x46, 0x9f, 0x92, 0xbe, 0xd7, 0xe9, 0x1a, 0x3c, 0x50, 0x5e, 0x55,
                0x49, 0x17, 0xa6, 0xf8, 0xa5, 0xca, 0xa4, 0x6d, 0x60, 0xcc, 0xea, 0xf7, 0x25, 0xf0,
                0x6e, 0x20, 0x41, 0x20, 0x18, 0x66, 0x5c, 0xae, 0x08, 0xb0, 0x10, 0x96, 0x3c, 0xad,
                0xb4, 0x13, 0xe1, 0x92, 0xce, 0x96, 0xad, 0x9d, 0x45, 0x05, 0xb7, 0xa6, 0x4c, 0x01,
                0x71, 0x08, 0x74, 0x0d, 0x1f, 0x35, 0x00, 0x2a, 0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02,
                0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x2b, 0xcc, 0xa9, 0xc0, 0x30, 0xc0, 0x2f, 0xcc, 0xa8,
                0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x35,
                0x00, 0x2f, 0xc0, 0x08, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x89, 0xda, 0xda,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00, 0x0f, 0x6f, 0x6e, 0x65,
                0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x2e, 0x6f, 0x6e, 0x65, 0x00, 0x17,
                0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0xfa,
                0xfa, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01,
                0x00, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16,
                0x00, 0x14, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x08, 0x05,
                0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33,
                0x00, 0x2b, 0x00, 0x29, 0xfa, 0xfa, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x00, 0x20, 0x7c,
                0xe1, 0xc6, 0xc2, 0x01, 0x69, 0x42, 0xba, 0x2b, 0xec, 0x07, 0x2f, 0x04, 0xbd, 0xb6,
                0x2a, 0x7e, 0x04, 0x6b, 0x96, 0x98, 0x51, 0x4e, 0x80, 0xb3, 0x2a, 0x4c, 0x4f, 0x1f,
                0x39, 0x82, 0x2b, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a,
                0x6a, 0x6a, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x1b, 0x00, 0x03,
                0x02, 0x00, 0x01, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x15, 0x00, 0xd3, 0x00, 0x00,
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
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            Domain::from_static("one.one.one.one"),
        )] {
            let domain = extract_sni_from_client_hello_handshake(content).unwrap();
            assert_eq!(Some(expected_sni), domain);
        }
    }

    #[test]
    fn test_extract_sni_from_client_hello_record() {
        #[allow(clippy::single_element_loop)]
        for (content, expected_sni) in [(
            &[
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
            ],
            Domain::from_static("init.itunes.apple.com"),
        )] {
            let domain = extract_sni_from_client_hello_record(content).unwrap();
            assert_eq!(Some(expected_sni), domain);
        }
    }
}
