//! Exercise the shared wire compiler against a native QUIC TLS first flight.

use super::*;
use rama_boring::{
    error::ErrorStack,
    ssl::{
        SslCipherRef,
        quic::{EncryptionLevel, HandshakeStatus, QuicConnection, QuicMethod},
    },
};
use rama_tls::{
    ExtensionId, ProtocolVersion,
    client::{
        ClientHello, ClientHelloExtension, ClientHelloHandshakePrefix,
        parse_client_hello_message_prefix,
    },
};
use rama_ua::profile::capture::tls::TlsCapturedExtension;
use wire::TransportShape;

#[derive(Default)]
struct FirstFlight(Mutex<Vec<u8>>);

impl QuicMethod for FirstFlight {
    fn set_read_secret(
        &self,
        _: EncryptionLevel,
        _: &SslCipherRef,
        _: &[u8],
    ) -> Result<(), ErrorStack> {
        panic!("a first ClientHello must not install peer secrets")
    }

    fn set_write_secret(
        &self,
        _: EncryptionLevel,
        _: &SslCipherRef,
        _: &[u8],
    ) -> Result<(), ErrorStack> {
        panic!("a fresh first ClientHello must not install traffic secrets")
    }

    fn add_handshake_data(&self, level: EncryptionLevel, bytes: &[u8]) -> Result<(), ErrorStack> {
        assert_eq!(level, EncryptionLevel::Initial);
        self.0.lock().extend_from_slice(bytes);
        Ok(())
    }

    fn flush_flight(&self) -> Result<(), ErrorStack> {
        Ok(())
    }

    fn send_alert(&self, _: EncryptionLevel, alert: u8) -> Result<(), ErrorStack> {
        panic!("unexpected native QUIC TLS alert: {alert}")
    }
}

fn hello(config: &TlsClientConfig, parameters: &[u8]) -> ClientHello {
    let mut data = TlsConnectorData::try_from(config).unwrap();
    data.server_name = Some(Host::try_from("example.test").unwrap());
    let output = Arc::new(FirstFlight::default());
    let mut connection = QuicConnection::new(data.into_ssl().unwrap(), output.clone()).unwrap();
    connection.set_connect_state();
    connection.set_transport_parameters(parameters).unwrap();
    assert_eq!(connection.handshake().unwrap(), HandshakeStatus::WantRead);
    let ClientHelloHandshakePrefix::Complete(hello) =
        parse_client_hello_message_prefix(&output.0.lock())
    else {
        panic!("native QUIC must emit a complete ClientHello")
    };
    hello
}

fn source(parameters: &[u8]) -> TlsCapture {
    let config = wire_variant()
        .with_alpn(vec![rama_net::tls::ApplicationProtocol::HTTP_3].into())
        .with_min_version(ProtocolVersion::TLSv1_3)
        .with_max_version(ProtocolVersion::TLSv1_3)
        .with_client_hello_padding(rama_boring::ssl::Padding::Off);
    captured(&hello(&config, parameters))
}

fn captured(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

#[test]
fn compiled_quic_offer_uses_fresh_keys_and_current_transport_parameters() {
    // RFC 9000 initial_source_connection_id; identities differ, encoding size does not.
    let source_parameters = [0x0f, 4, 1, 2, 3, 4];
    let current_parameters = [0x0f, 4, 5, 6, 7, 8];
    let source = source(&source_parameters);
    let config = wire::compile(
        TransportShape::Quic {
            parameters_len: current_parameters.len(),
        },
        &source,
        None,
    )
    .unwrap();
    let first = hello(&config, &current_parameters);
    let second = hello(&config, &current_parameters);
    for actual in [&first, &second] {
        assert_eq!(
            source.canonical(TlsCaptureLimits::default()).unwrap().bytes,
            captured(actual)
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes
        );
        let parameters = actual
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                ClientHelloExtension::Opaque { id, data: bytes }
                    if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
                {
                    Some(bytes.as_slice())
                }
                _ => None,
            });
        assert_eq!(parameters, Some(current_parameters.as_slice()));
    }
    let key_share = |hello: &ClientHello| {
        format!(
            "{:?}",
            hello
                .extensions()
                .iter()
                .find(|extension| extension.id() == ExtensionId::KEY_SHARE)
        )
    };
    assert_ne!(
        key_share(&first),
        key_share(&second),
        "native QUIC sessions must generate fresh keys"
    );
}

#[test]
fn quic_wire_compilation_rejects_wrong_transport_lengths_and_version_filtering() {
    let parameters = [0x0f, 4, 1, 2, 3, 4];
    let observation = source(&parameters);
    let binding = TransportShape::Quic {
        parameters_len: parameters.len(),
    };
    wire::compile(TransportShape::Tcp, &observation, None).unwrap_err();
    wire::compile(binding, &capture(), None).unwrap_err();
    wire::compile(
        TransportShape::Quic {
            parameters_len: parameters[..5].len(),
        },
        &observation,
        None,
    )
    .unwrap_err();

    let mut missing = observation.clone();
    missing.extensions = missing
        .extensions
        .into_vec()
        .into_iter()
        .filter(|extension| extension.id != u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS))
        .collect();
    wire::compile(binding, &missing, None).unwrap_err();

    let mut filtered = observation;
    let extension = filtered
        .extensions
        .iter_mut()
        .find(|extension| extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS))
        .unwrap();
    extension.value = TlsCapturedExtensionValue::U16List(
        vec![
            ProtocolVersion::TLSv1_3.into(),
            ProtocolVersion::TLSv1_2.into(),
        ]
        .into(),
    );
    // Keep TCP's version/point-format pairing valid, so only QUIC's native
    // version filtering rejects this otherwise compilable offer.
    let mut fields = filtered.extensions.into_vec();
    fields.push(TlsCapturedExtension {
        id: ExtensionId::EC_POINT_FORMATS.into(),
        value: TlsCapturedExtensionValue::U8List(vec![0].into()),
    });
    filtered.extensions = fields.into();
    wire::compile(binding, &filtered, None).unwrap_err();
}
