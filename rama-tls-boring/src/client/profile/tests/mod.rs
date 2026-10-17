use super::*;
use crate::client::{
    BoringClientConfigExt as _, TlsConnector, TlsConnectorData,
    ech::EchGrease,
    tests::{hello_from_data, wire_variant},
};
use rama_net::client::ConnectRequest;
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    tls::{TlsCapture, TlsCaptureLimits},
};

mod connection;
mod offer;
mod quic;
#[cfg(feature = "http")]
mod reuse;

fn capture() -> TlsCapture {
    // Large enough to avoid destination-dependent native TCP padding. The
    // retained ECH lengths are intentional; native keys and ciphertext are fresh.
    let source = wire_variant()
        .with_encrypted_client_hello(true)
        .with_ech_grease(EchGrease::Shape {
            kdf_id: 1,
            aead_id: 1,
            encapsulated_key_len: 32,
            payload_len: 320,
        });
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Tcp,
        &hello_from_data(TlsConnectorData::try_from(&source).unwrap()),
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

fn input() -> ConnectRequest {
    let request = ConnectRequest::new("prepared.test:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    #[cfg(feature = "http")]
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    request
}
