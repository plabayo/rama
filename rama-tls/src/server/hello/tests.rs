use super::*;

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut message = vec![kind, len[1], len[2], len[3]];
    message.extend_from_slice(body);
    message
}

fn extensions(list: &[(u16, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (id, data) in list {
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(data);
    }
    let mut prefixed = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    prefixed.extend_from_slice(&bytes);
    prefixed
}

fn server_hello_body(cipher: u16, list: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&extensions(list));
    body
}

#[test]
fn a_server_hello_reads_its_selection_and_extension_order() {
    let alpn: &[u8] = &[0x00, 0x03, 0x02, b'h', b'2'];
    let message = handshake(
        2,
        &server_hello_body(
            0x1302,
            &[
                (0x0033, &[0, 0x1d, 0, 0]),
                (0x002b, &[3, 4]),
                (0x0010, alpn),
            ],
        ),
    );
    let hello = ServerHello::parse_handshake(&message).unwrap();
    assert_eq!(hello.protocol_version(), ProtocolVersion::TLSv1_3);
    assert_eq!(hello.cipher_suite(), CipherSuite::TLS13_AES_256_GCM_SHA384);
    assert_eq!(hello.alpn(), Some(&ApplicationProtocol::HTTP_2));
    assert_eq!(
        hello.extensions(),
        [
            ExtensionId::KEY_SHARE,
            ExtensionId::SUPPORTED_VERSIONS,
            ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        ]
    );
}

#[test]
fn a_server_hello_without_extensions_uses_its_legacy_version() {
    let hello =
        ServerHello::parse_handshake(&handshake(2, &server_hello_body(0x009c, &[])[..38])).unwrap();
    assert_eq!(hello.protocol_version(), ProtocolVersion::TLSv1_2);
    assert!(hello.extensions().is_empty());
}

#[test]
fn encrypted_extensions_read_in_order() {
    let message = handshake(
        8,
        &extensions(&[(0x0010, &[0, 3, 2, b'h', b'3']), (0x0039, &[1, 2, 3])]),
    );
    assert_eq!(
        parse_encrypted_extensions(&message).unwrap(),
        [
            ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            ExtensionId::QUIC_TRANSPORT_PARAMETERS
        ]
    );
    assert!(
        parse_encrypted_extensions(&handshake(8, &[0, 0]))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn malformed_messages_are_refused() {
    let hello = handshake(2, &server_hello_body(0x1301, &[(0x002b, &[3, 4])]));
    let mut wrong_kind = hello.clone();
    wrong_kind[0] = 8;
    let mut trailing = hello.clone();
    trailing.push(0);
    let mut truncated_extension = hello.clone();
    truncated_extension.truncate(hello.len() - 1);
    for input in [
        &wrong_kind[..],
        &trailing[..],
        &truncated_extension[..],
        &hello[..3],
        &[][..],
    ] {
        ServerHello::parse_handshake(input).unwrap_err();
    }
    let ee = handshake(8, &extensions(&[(0x0010, &[0, 3, 2, b'h', b'3'])]));
    for input in [&ee[..ee.len() - 1], &hello[..]] {
        parse_encrypted_extensions(input).unwrap_err();
    }
}
