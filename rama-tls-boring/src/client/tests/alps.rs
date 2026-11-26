//! ALPS offers carried end to end: negotiated or not, the connection still serves requests.

use rama_boring::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslContextBuilder, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use rama_boring_tokio::SslStreamBuilder;
use rama_net::{
    address::Domain,
    tls::{ApplicationProtocol, ServerName},
};
use rama_tls::{
    client::{ServerVerifyMode, TlsClientConfig},
    server::{GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use rama_utils::octets::kib;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::server::TlsAcceptorData;

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nhost: example.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
const SERVER_SETTINGS: &[u8] = b"server settings";

/// What the client saw: the negotiated ALPN protocol and the peer's ALPS settings.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    alpn: Option<Vec<u8>>,
    alps: Option<Vec<u8>>,
}

fn server_auth() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(
        LeafCertRequest::default(),
    ))
    .unwrap()
}

/// A backend server selecting from `h2, http/1.1` that enables ALPS when it selects h2.
fn alps_server() -> Ssl {
    let auth = server_auth();
    let mut server = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    server
        .set_certificate(&X509::from_der(auth.cert_chain[0].as_ref()).unwrap())
        .unwrap();
    server
        .set_private_key(&PKey::private_key_from_der(auth.private_key.secret_der()).unwrap())
        .unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.set_alpn_select_callback(|ssl, client| {
        let selected = select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)?;
        if selected == b"h2" {
            ssl.set_alps_use_new_codepoint(true);
            ssl.add_application_settings_value(b"h2", SERVER_SETTINGS)
                .map_err(|_error| AlpnError::ALERT_FATAL)?;
        }
        Ok(selected)
    });
    Ssl::new(&server.build()).unwrap()
}

/// Rama's own acceptor with its default configuration, plus `alpn` when set.
fn rama_server(alpn: Option<Vec<ApplicationProtocol>>) -> Ssl {
    let mut config = TlsServerConfig::new().with_single_cert(server_auth());
    if let Some(alpn) = alpn {
        config.set_alpn(alpn.into());
    }
    let acceptor = TlsAcceptorData::try_from(&config)
        .unwrap()
        .into_static_acceptor_builder()
        .unwrap()
        .build();
    Ssl::new(acceptor.context()).unwrap()
}

/// Handshake `client` with `server`, then exchange one request and response.
async fn exchange(client: TlsClientConfig, server: Ssl) -> Outcome {
    let mut data =
        TlsConnectorData::try_from(&client.with_server_verify(ServerVerifyMode::Disable)).unwrap();
    data.server_name = Some(ServerName::from(Domain::from_static("example.test")));
    let (client_io, server_io) = tokio::io::duplex(kib(64));
    let server = async move {
        let mut stream = SslStreamBuilder::new(server, server_io)
            .accept()
            .await
            .unwrap();
        let mut request = vec![0; REQUEST.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, REQUEST);
        stream.write_all(RESPONSE).await.unwrap();
    };
    let client = async move {
        let mut stream = SslStreamBuilder::new(data.into_ssl().unwrap(), client_io)
            .connect()
            .await
            .unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let mut response = vec![0; RESPONSE.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, RESPONSE);
        Outcome {
            alpn: stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
            alps: stream.ssl().peer_application_settings().map(<[u8]>::to_vec),
        }
    };
    let ((), outcome) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    outcome
}

fn client(alpn: Vec<ApplicationProtocol>) -> TlsClientConfig {
    TlsClientConfig::new()
        .with_alpn(alpn.into())
        .with_alps(vec![ApplicationProtocol::HTTP_2], true)
}

#[tokio::test]
async fn http1_offer_with_h2_settings_serves_http1_without_alps() {
    let http1 = || client(vec![ApplicationProtocol::HTTP_11]);
    assert_eq!(
        emitted_with(&http1()).ext_alps(),
        Some([ApplicationProtocol::HTTP_2].as_slice())
    );
    // Rama's default acceptor selects no protocol; one that offers ALPN selects http/1.1.
    assert_eq!(
        exchange(http1(), rama_server(None)).await,
        Outcome {
            alpn: None,
            alps: None
        }
    );
    for server in [
        rama_server(Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ])),
        alps_server(),
    ] {
        assert_eq!(
            exchange(http1(), server).await,
            Outcome {
                alpn: Some(b"http/1.1".to_vec()),
                alps: None
            }
        );
    }
}

#[tokio::test]
async fn h2_offer_with_h2_settings_negotiates_h2_and_alps() {
    // The exchange checks the connection carries data, not HTTP/2 framing.
    let offer = client(vec![
        ApplicationProtocol::HTTP_2,
        ApplicationProtocol::HTTP_11,
    ]);
    assert_eq!(
        exchange(offer, alps_server()).await,
        Outcome {
            alpn: Some(b"h2".to_vec()),
            alps: Some(SERVER_SETTINGS.to_vec())
        }
    );
}
