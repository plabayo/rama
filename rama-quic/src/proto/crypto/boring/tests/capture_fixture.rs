//! Native TLS offers with stable optional layout and real authentication.

use super::*;
use rama_crypto::dep::boring::ssl::Padding;
use rama_tls::client::ClientHello;
use rama_tls_boring::client::BoringClientConfigExt as _;
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
};

pub(super) fn reference(policy: &TlsClientConfig, version: Version) -> TlsCapture {
    let client = BoringTlsProvider
        .client_config(policy, TlsOptions::default())
        .unwrap();
    first_capture(client.crypto, version)
}

pub(super) fn first_capture(client: Arc<dyn crypto::ClientConfig>, version: Version) -> TlsCapture {
    let mut session = client
        .start_session(version, "localhost", &params(Side::Client))
        .unwrap();
    let mut bytes = Vec::new();
    while let Some(event) = session.poll_handshake().unwrap() {
        let HandshakeEvent::Data(_, data) = event else {
            panic!("unexpected first-flight keys");
        };
        bytes.extend_from_slice(&data);
    }
    let ClientHelloHandshakePrefix::Complete(hello) = parse_client_hello_message_prefix(&bytes)
    else {
        panic!("native ClientHello incomplete");
    };
    capture(&hello)
}

pub(super) fn capture(hello: &ClientHello) -> TlsCapture {
    TlsCapture::capture(
        ProfileCaptureCompleteness::Complete,
        TlsCaptureTransport::Quic,
        hello,
        TlsCaptureLimits::default(),
    )
    .unwrap()
}

pub(super) fn policy() -> (TlsClientConfig, TlsServerConfig) {
    let (mut client, server) = configs();
    // The test controls only optional layout choices; authentication stays real.
    client.set_client_hello_padding(Padding::Off);
    client.set_grease(false);
    client.set_permute_extensions(false);
    (client, server)
}
