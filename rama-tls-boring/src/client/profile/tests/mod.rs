use super::{
    compiler::{CompiledConnection, ConnectionProfileCompiler},
    wire,
};
use crate::client::{
    BoringClientConfigExt as _, BoringTlsConnectorConfig, TlsConnector, TlsConnectorData,
    ech::EchGrease,
    tests::{hello_from_data, wire_variant},
};
use parking_lot::Mutex;
use rama_core::extensions::ExtensionsRef;
#[cfg(feature = "http")]
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
};
use rama_net::client::ConnectRequest;
#[cfg(feature = "http")]
use rama_net::http::{TargetHttpVersion, Version};
use rama_net::{Protocol, address::Host};
use rama_tls::client::TlsClientConfig;
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    joint::CapturedSlotKind,
    tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue},
};
use rama_ua::profile::replay::connection::compiler::{
    CompiledConnectionProfile, ConnectionProfileBindings as _, InstalledConnectionProfile,
};
use rama_ua::profile::selection::variants::ConnectionSelection;
#[cfg(feature = "http")]
use rama_ua::{
    layer::emulate::UserAgentEmulateHttpConnectModifier, profile::model::http::HttpProfile,
};
use std::sync::Arc;

#[cfg(feature = "http")]
mod connection;
mod fixture;
mod native;
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
