use super::EchGrease;
use crate::client::{
    BoringClientConfigExt as _, BoringTlsConnectorConfig, TlsConnectorData, tests::emitted_with,
};
use rama_boring::ssl::GreaseValues;
use rama_tls::client::{ClientHello, ClientHelloExtension, ECHClientHello, TlsClientConfig};

fn captured_hello(aead: u16, payload_len: usize) -> ClientHello {
    let source = emitted_with(&TlsClientConfig::new().with_encrypted_client_hello(true));
    let mut extensions = source.extensions().to_vec();
    for extension in &mut extensions {
        if let ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(outer)) = extension
        {
            outer.cipher_suite.aead_id = aead.into();
            outer.payload.resize(payload_len, 0);
        }
    }
    ClientHello::new(
        source.protocol_version(),
        source.cipher_suites().to_vec(),
        source.compression_algorithms().to_vec(),
        extensions,
    )
}

fn metadata(hello: &ClientHello) -> (u16, u16, usize, usize) {
    hello
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(outer)) => Some((
                outer.cipher_suite.kdf_id.into(),
                outer.cipher_suite.aead_id.into(),
                outer.enc.len(),
                outer.payload.len(),
            )),
            _ => None,
        })
        .expect("ECH GREASE outer extension")
}

#[test]
fn captured_ech_shapes_preserve_metadata_and_refresh_crypto() {
    for (aead, payload_len) in [(1, 144), (2, 208), (3, 145)] {
        let captured = captured_hello(aead, payload_len);
        let config = TlsClientConfig::new_from_client_hello(&captured)
            .with_grease_values(GreaseValues::Seeded(7));
        let first = emitted_with(&config);
        let second = emitted_with(&config);
        assert_eq!(metadata(&first), (1, aead, 32, payload_len));
        assert_eq!(metadata(&second), metadata(&first));
        let outer = |hello: &ClientHello| {
            hello
                .extensions()
                .iter()
                .find_map(|extension| {
                    if let ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(
                        value,
                    )) = extension
                    {
                        Some((value.enc.clone(), value.payload.clone()))
                    } else {
                        None
                    }
                })
                .unwrap()
        };
        let (first_enc, first_payload) = outer(&first);
        let (second_enc, second_payload) = outer(&second);
        // Keep generated crypto out of failure diagnostics.
        assert!(
            first_enc != second_enc,
            "fresh ECH encapsulation per connection"
        );
        assert!(
            first_payload != second_payload,
            "fresh ECH ciphertext per connection"
        );
    }
}

#[test]
fn an_ech_shape_alone_installs_the_atomic_client_hello_shape() {
    let config = TlsClientConfig::new()
        .with_encrypted_client_hello(true)
        .with_ech_grease(EchGrease::Shape {
            kdf_id: 1,
            aead_id: 3,
            encapsulated_key_len: 32,
            payload_len: 145,
        });
    assert_eq!(metadata(&emitted_with(&config)), (1, 3, 32, 145));
}

#[test]
fn unsupported_captured_ech_shapes_fail_before_connecting() {
    for (kdf, aead, enc, payload) in [
        (2, 1, 32, 144),
        (1, 9, 32, 144),
        (1, 1, 31, 144),
        (1, 1, 32, 15),
        (1, 1, 32, 65490),
    ] {
        let source = captured_hello(aead, payload);
        let mut extensions = source.extensions().to_vec();
        for extension in &mut extensions {
            if let ClientHelloExtension::EncryptedClientHello(ECHClientHello::Outer(outer)) =
                extension
            {
                outer.cipher_suite.kdf_id = kdf.into();
                outer.enc.resize(enc, 0);
            }
        }
        let captured = ClientHello::new(
            source.protocol_version(),
            source.cipher_suites().to_vec(),
            source.compression_algorithms().to_vec(),
            extensions,
        );
        let config = TlsClientConfig::new_from_client_hello(&captured);
        assert!(
            TlsConnectorData::try_from(&config).is_err(),
            "unsupported ECH metadata"
        );
    }
}

#[test]
fn ech_shapes_isolate_pools_and_share_security_contexts() {
    let config = |payload_len| {
        TlsClientConfig::new().with_ech_grease(EchGrease::Shape {
            kdf_id: 1,
            aead_id: 1,
            encapsulated_key_len: 32,
            payload_len,
        })
    };
    let one = config(144);
    let two = config(208);
    let one = BoringTlsConnectorConfig::from_extensions(one.as_extensions());
    let two = BoringTlsConnectorConfig::from_extensions(two.as_extensions());
    assert_ne!(one.pool_id(), two.pool_id());
    assert_eq!(one.session_scope(), two.session_scope());
    assert_eq!(one.context_scope(), two.context_scope());
}

#[test]
fn mirroring_clears_an_inherited_ech_shape() {
    let base = TlsClientConfig::new().with_ech_grease(EchGrease::Shape {
        kdf_id: 9,
        aead_id: 9,
        encapsulated_key_len: 1,
        payload_len: 1,
    });
    let source = emitted_with(&TlsClientConfig::new());
    let mirror = TlsClientConfig::new_from_client_hello(&source).with_encrypted_client_hello(true);
    let effective = mirror
        .as_extensions()
        .fork()
        .with_base(base.as_extensions());
    let config = BoringTlsConnectorConfig::from_extensions(&effective);
    assert_eq!(config.ech_grease, Some(&EchGrease::Native));
    TlsConnectorData::try_from(config).unwrap();
}
