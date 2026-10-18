//! Actual emitted requests keep omission, zero and shared contexts distinct.

use super::*;
use rama_core::bytes::Bytes;

fn request(hello: &ClientHello) -> Option<u16> {
    let requests: Vec<_> = hello
        .extensions()
        .iter()
        .filter_map(|extension| match extension {
            ClientHelloExtension::ServerPaddingRequest(bytes) => Some(*bytes),
            _ => None,
        })
        .collect();
    assert!(requests.len() <= 1);
    requests.first().copied()
}

#[test]
fn server_padding_wire_values_and_pool_policy_stay_independent_per_ssl() {
    let base = TlsClientConfig::new();
    let context = TlsConnectorContextBuilder::try_from(&base).unwrap().build();
    let security = BoringTlsConnectorConfig::from_extensions(base.as_extensions()).session_scope();
    let mut pools = Vec::new();
    for bytes in [Some(64), None, Some(0), Some(u16::MAX)] {
        let config = base.clone().with_server_padding_request(bytes);
        let view = BoringTlsConnectorConfig::from_extensions(config.as_extensions());
        assert_eq!(view.session_scope(), security);
        let pool = view.pool_id();
        assert!(pools.iter().all(|previous| *previous != pool));
        pools.push(pool);
        for _ in 0..2 {
            let hello = hello_from_data(context.configure_variant(&view).unwrap());
            assert_eq!(request(&hello), bytes);
        }
    }
    let mut config = base.with_server_padding_request(17);
    config.set_server_padding_request(33);
    assert_eq!(request(&emitted_with(&config)), Some(33));
    config.set_server_padding_request(None);
    assert_eq!(request(&emitted_with(&config)), None);
}

#[test]
fn server_padding_mirroring_preserves_native_value_and_explicit_omission() {
    for bytes in [None, Some(0), Some(32), Some(u16::MAX)] {
        let original = emitted_with(&TlsClientConfig::new().with_server_padding_request(bytes));
        let mirrored = TlsClientConfig::new()
            .with_server_padding_request(99)
            .with_mimic_client_hello(&original);
        assert_eq!(request(&emitted_with(&mirrored)), bytes);
    }
}

#[test]
fn server_padding_cannot_be_installed_as_an_opaque_body() {
    let config = TlsClientConfig::new().with_extension_bodies(vec![(
        ExtensionId::SERVER_PADDING_REQUEST,
        Bytes::from_static(&[0, 32]),
    )]);
    TlsConnectorData::try_from(&config).unwrap_err();
}
