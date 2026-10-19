use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama::{
    Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    extensions::ExtensionsRef as _,
    http::{Version, conn::TargetHttpVersion},
    net::{
        Protocol,
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
        },
        tls::{ApplicationProtocol, TlsAlpn},
    },
    tls::client::{ClientHello, ServerVerifyMode, TlsClientConfig, parse_client_hello_handshake},
    utils::octets::kib,
};
use tokio::io::{AsyncReadExt as _, DuplexStream};

#[cfg(feature = "boring")]
use rama::tls::boring::client::TlsConnector as BoringConnector;
#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
use rama::tls::rustls::client::TlsConnector as RustlsConnector;

/// One in-memory transport; the peer reads the native TLS engine's first record.
#[derive(Clone, Debug)]
struct Dial(Arc<Mutex<Option<DuplexStream>>>);

impl Dial {
    fn new() -> (Self, DuplexStream) {
        let (client, peer) = tokio::io::duplex(kib(16));
        (Self(Arc::new(Mutex::new(Some(client)))), peer)
    }
}

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let client = self.0.lock().take().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("test transport already consumed"),
                ConnectionErrorKind::Internal,
            )
        })?;
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

/// EOF before the first byte distinguishes refusal from a rewritten offer.
async fn first_hello(mut peer: DuplexStream) -> Result<Option<ClientHello>, BoxError> {
    let mut header = [0u8; 5];
    if peer.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    peer.read_exact(&mut header[1..]).await?;
    let mut record = vec![0; 5 + usize::from(u16::from_be_bytes([header[3], header[4]]))];
    record[..5].copy_from_slice(&header);
    peer.read_exact(&mut record[5..]).await?;
    parse_client_hello_handshake(&record).map(Some)
}

async fn observe<C>(
    connector: C,
    input: ConnectRequest,
    peer: DuplexStream,
) -> Result<(ConnectionErrorKind, Option<ClientHello>), BoxError>
where
    C: Service<ConnectRequest, Error = ConnectionError>,
{
    let (result, hello) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(connector.serve(input), first_hello(peer))
    })
    .await?;
    // The recording peer deliberately closes after ClientHello. No complete
    // handshake or successful authentication is claimed by this fixture.
    let error = result.err().ok_or_else(|| {
        BoxError::from_static_str("recording peer unexpectedly completed a handshake")
    })?;
    Ok((error.kind(), hello?))
}

async fn request_offers<C>(make_connector: impl Fn(Dial) -> C) -> Result<(), BoxError>
where
    C: Service<ConnectRequest, Error = ConnectionError>,
{
    let explicit = TlsAlpn(
        [
            ApplicationProtocol::from(b"rama-probe-first"),
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
            ApplicationProtocol::from(b"rama-probe-last"),
        ]
        .into_iter()
        .collect(),
    );
    // Public Unknown variants may carry standard protocol bytes. The native
    // peer parses those bytes back into known variants; the offer must survive.
    let aliases = TlsAlpn(
        explicit
            .0
            .iter()
            .map(|protocol| ApplicationProtocol::Unknown(protocol.as_bytes().to_vec()))
            .collect(),
    );
    for target in [Version::HTTP_11, Version::HTTP_2] {
        let required = ApplicationProtocol::try_from(target)?;
        let other = if target == Version::HTTP_2 {
            ApplicationProtocol::HTTP_11
        } else {
            ApplicationProtocol::HTTP_2
        };
        for (case, offer, expected) in [
            (
                "explicit",
                Some(explicit.clone()),
                explicit.0.clone().into_vec(),
            ),
            (
                "public wire aliases",
                Some(aliases.clone()),
                explicit.0.clone().into_vec(),
            ),
            ("defaults", None, vec![required.clone()]),
            // An offer without the required protocol is lowered to offer it alone.
            ("empty", Some(TlsAlpn::empty()), vec![required.clone()]),
            (
                "excluded",
                Some(TlsAlpn([other].into_iter().collect())),
                vec![required.clone()],
            ),
        ] {
            let (transport, peer) = Dial::new();
            let input = ConnectRequest::new("localhost:443".parse()?)
                .with_application_protocol(Protocol::HTTPS);
            input.extensions().insert(TargetHttpVersion(target));
            let mut settings = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
            if let Some(offer) = &offer {
                settings.set_alpn(offer.0.clone());
            }
            settings.write_to(input.extensions());

            let (_, hello) = observe(make_connector(transport), input, peer).await?;
            let actual = hello.and_then(|hello| hello.ext_alpn().map(<[_]>::to_vec));
            if actual.as_ref() != Some(&expected) {
                return Err(BoxError::from_static_str("native ALPN offer was rewritten")
                    .context_debug_field("case", case)
                    .context_debug_field("target", target)
                    .context_debug_field("expected", expected)
                    .context_debug_field("actual", actual));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "boring")]
#[tokio::test]
async fn boring_request_alpn_survives_native_connection_setup() {
    request_offers(|transport| {
        BoringConnector::secure(transport)
            .with_base_config(TlsClientConfig::new().with_alpn_http_auto())
    })
    .await
    .unwrap();
}

#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
#[tokio::test]
async fn rustls_request_alpn_survives_native_connection_setup() {
    request_offers(|transport| {
        RustlsConnector::secure(transport)
            .with_base_config(TlsClientConfig::new().with_alpn_http_auto())
    })
    .await
    .unwrap();
}
