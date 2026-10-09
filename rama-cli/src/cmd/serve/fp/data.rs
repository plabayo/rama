#![expect(
    clippy::allow_attributes,
    reason = "feature-gated dead_code: variants used by some build configs but not others"
)]

use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::time::Instant;

use rama::{
    error::{BoxError, ErrorContext},
    extensions::Extensions,
    http::{
        self, HeaderMap,
        core::{
            h2::frame::EarlyFrameCapture,
            h3::observation::{H3Observer, SettingsObservation},
        },
        fingerprint::{AkamaiH2, Ja4H},
        proto::{
            h2::PseudoHeaderOrder,
            h3::observation::{H3ObservationSnapshot, H3RequestObservation, SettingsStatus},
        },
        request::HttpRequestParts,
    },
    net::{
        AuthorityInputExt, Protocol, ProtocolInputExt,
        address::ip::geo::{IpGeoDb, IpGeoInfo},
        forwarded::ForwardedClientExt as _,
        stream::SocketInfo,
    },
    quic::proto::capture::{CaptureCompleteness, QuicObservation},
    telemetry::tracing,
    tls::{
        ExtensionId, SecureTransport,
        client::{ClientHello, ClientHelloExtension, ECHClientHello},
        fingerprint::{Ja3, Ja4, PeetPrint},
    },
    ua::{
        UserAgent,
        profile::{Http1Settings, Http2Settings},
    },
};
use serde::Serialize;

use super::{State, StorageAuthorized};

#[derive(Debug, Clone, Default, Serialize)]
#[allow(
    dead_code,
    reason = "deserialize-only fields kept for schema compatibility"
)]
pub(super) enum FetchMode {
    Cors,
    #[default]
    Navigate,
    NoCors,
    SameOrigin,
    WebSocket,
}

impl std::fmt::Display for FetchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cors => write!(f, "cors"),
            Self::Navigate => write!(f, "navigate"),
            Self::NoCors => write!(f, "no-cors"),
            Self::SameOrigin => write!(f, "same-origin"),
            Self::WebSocket => write!(f, "websocket"),
        }
    }
}

impl FromStr for FetchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cors" => Ok(Self::Cors),
            "navigate" => Ok(Self::Navigate),
            "no-cors" => Ok(Self::NoCors),
            "same-origin" => Ok(Self::SameOrigin),
            "websocket" => Ok(Self::WebSocket),
            _ => Err(s.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[allow(
    dead_code,
    reason = "deserialize-only fields kept for schema compatibility"
)]
pub(super) enum ResourceType {
    #[default]
    Document,
    Xhr,
    Form,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document => write!(f, "document"),
            Self::Xhr => write!(f, "xhr"),
            Self::Form => write!(f, "form"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
#[allow(
    dead_code,
    reason = "deserialize-only fields kept for schema compatibility"
)]
pub(super) enum Initiator {
    #[default]
    Navigator,
    Fetch,
    XMLHttpRequest,
    Form,
    Ws,
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Navigator => write!(f, "navigator"),
            Self::Fetch => write!(f, "fetch"),
            Self::XMLHttpRequest => write!(f, "xmlhttprequest"),
            Self::Form => write!(f, "form"),
            Self::Ws => write!(f, "ws"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DataSource {
    pub(super) name: String,
    pub(super) version: String,
}

impl Default for DataSource {
    fn default() -> Self {
        Self {
            name: rama::utils::info::NAME.to_owned(),
            version: rama::utils::info::VERSION.to_owned(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub(super) struct UserAgentInfo {
    pub(super) user_agent: String,
    pub(super) kind: Option<String>,
    pub(super) version: Option<usize>,
    pub(super) platform: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RequestInfo {
    pub(super) version: String,
    pub(super) scheme: String,
    pub(super) authority: String,
    pub(super) method: String,
    pub(super) fetch_mode: FetchMode,
    pub(super) resource_type: ResourceType,
    pub(super) initiator: Initiator,
    pub(super) path: String,
    pub(super) uri: String,
    pub(super) peer_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) geo: Option<IpGeoInfo>,
}

pub(super) async fn get_user_agent_info(extensions: &Extensions) -> UserAgentInfo {
    extensions
        .get_ref()
        .map(|ua: &UserAgent| UserAgentInfo {
            user_agent: ua.header_str().to_owned(),
            kind: ua.info().map(|info| info.kind.to_string()),
            version: ua.info().and_then(|info| info.version),
            platform: ua.platform().map(|v| v.to_string()),
        })
        .unwrap_or_default()
}

pub(super) async fn get_request_info<R>(
    fetch_mode: FetchMode,
    resource_type: ResourceType,
    initiator: Initiator,
    req: &R,
    geo_db: Option<&IpGeoDb>,
) -> Result<RequestInfo, BoxError>
where
    R: HttpRequestParts + AuthorityInputExt + ProtocolInputExt,
{
    let authority = req
        .authority()
        .context("get or compose request authority")?;
    let protocol = req.protocol().unwrap_or(&Protocol::HTTP);
    let mut uri = req.uri().clone();
    let rama::net::address::HostWithOptPort { host, port } =
        authority.clone().without_default_port_for(Some(protocol));
    uri.set_scheme(protocol.clone())
        .set_host(host)
        .set_port(port);

    let client_ip = rama::net::client_ip::client_ip(&req);
    let geo = geo_db.and_then(|db| client_ip.and_then(|ip| db.resolve(ip)));

    Ok(RequestInfo {
        version: format!("{:?}", req.version()),
        scheme: protocol.to_string(),
        authority: authority.to_string(),
        method: req.method().as_str().to_owned(),
        fetch_mode: req
            .headers()
            .get("sec-fetch-mode")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(fetch_mode),
        resource_type,
        initiator,
        path: req.uri().path_or_root().into_owned(),
        uri: uri.to_string(),
        peer_addr: req
            .forwarded_client_socket_addr()
            .map(|addr| addr.to_string())
            .or_else(|| req.forwarded_client_ip().map(|ip| ip.to_string()))
            .or_else(|| SocketInfo::ingress(req.extensions()).map(|v| v.peer_addr().to_string())),
        geo,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Ja4HInfo {
    pub(super) hash: String,
    pub(super) human_str: String,
}

pub(super) fn get_ja4h_info(req: &impl HttpRequestParts) -> Option<Ja4HInfo> {
    Ja4H::compute(req)
        .inspect_err(|err| tracing::error!("ja4h compute failure: {err:?}"))
        .ok()
        .map(|ja4h| Ja4HInfo {
            hash: format!("{ja4h}"),
            human_str: format!("{ja4h:?}"),
        })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AkamaiH2Info {
    pub(super) hash: String,
    pub(super) human_str: String,
}

pub(super) fn get_akamai_h2_info(ext: &Extensions) -> Option<AkamaiH2Info> {
    AkamaiH2::compute(ext)
        .inspect_err(|err| tracing::error!("akamai h2 compute failure: {err:?}"))
        .ok()
        .map(|akamai_h2| AkamaiH2Info {
            hash: format!("{akamai_h2}"),
            human_str: format!("{akamai_h2:?}"),
        })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HttpInfo {
    pub(super) headers: Vec<(String, String)>,
    pub(super) version: http::Version,
    pub(super) initiator: Initiator,
    pub(super) h2_settings: Option<Http2Settings>,
    pub(super) h3: Option<Http3Info>,
    pub(super) quic: Option<Arc<QuicObservation>>,
}

/// The request snapshot remains immutable; fp explicitly waits for connection SETTINGS.
#[derive(Debug, Clone)]
pub(super) struct Http3Info {
    pub(super) request: Arc<H3RequestObservation>,
    pub(super) connection: Arc<H3ObservationSnapshot>,
    pub(super) settings_status: SettingsStatus,
    pub(super) pseudo_headers: Option<PseudoHeaderOrder>,
}

impl Serialize for Http3Info {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.request
            .view(
                &self.connection,
                self.settings_status,
                self.pseudo_headers.as_ref(),
            )
            .serialize(serializer)
    }
}

async fn http3_info(ext: &Extensions) -> Option<Http3Info> {
    let request = ext.get_arc::<H3RequestObservation>()?;
    let (connection, settings_status) = match ext.get_ref::<H3Observer>() {
        Some(observer) => match observer
            .settings(Instant::now() + Duration::from_millis(250))
            .await
        {
            SettingsObservation::Received(value) => (value, SettingsStatus::Received),
            SettingsObservation::TimedOut(value) => (value, SettingsStatus::TimedOut),
            SettingsObservation::Closed { snapshot, .. } => (snapshot, SettingsStatus::Closed),
        },
        None => (request.connection.clone(), SettingsStatus::Unavailable),
    };
    Some(Http3Info {
        request: request.clone(),
        settings_status: settings_status.for_snapshot(&connection),
        connection,
        pseudo_headers: ext.get_ref::<PseudoHeaderOrder>().cloned(),
    })
}

pub(super) async fn get_and_store_http_info(
    state: &State,
    headers: HeaderMap,
    ext: &Extensions,
    http_version: http::Version,
    ua: String,
    initiator: Initiator,
) -> Result<HttpInfo, BoxError> {
    let original_headers = headers;
    let h3 = if http_version == http::Version::HTTP_3 {
        http3_info(ext).await
    } else {
        None
    };
    let quic = ext.get_arc::<QuicObservation>();

    let h2_settings = match http_version {
        http::Version::HTTP_2 => Some(Http2Settings {
            http_pseudo_headers: ext.get_ref::<PseudoHeaderOrder>().cloned(),
            early_frames: ext.get_ref::<EarlyFrameCapture>().cloned(),
        }),
        _ => None,
    };

    if let Some(storage) = state.storage.as_ref() {
        let auth = ext.contains::<StorageAuthorized>();

        match http_version {
            http::Version::HTTP_09 | http::Version::HTTP_10 | http::Version::HTTP_11 => {
                match initiator {
                    Initiator::Navigator => {
                        storage
                            .store_h1_headers_navigate(ua, auth, original_headers.clone())
                            .await
                            .context("store h1 headers navigate")?;
                    }
                    Initiator::Fetch => {
                        storage
                            .store_h1_headers_fetch(ua, auth, original_headers.clone())
                            .await
                            .context("store h1 headers fetch")?;
                    }
                    Initiator::XMLHttpRequest => {
                        if let Some((header_name, _)) = original_headers
                            .ordered_iter()
                            .find(|(name, _)| *name == "x-rama-custom-header-marker")
                        {
                            // Check if the header name is title-cased or not
                            let header_str = header_name.as_str();
                            let title_case_headers = header_str.split('-').all(|part| {
                                part.chars().next().is_none_or(|c| c.is_ascii_uppercase())
                                    && part.chars().skip(1).all(|c| c.is_ascii_lowercase())
                            });

                            tracing::debug!(
                                http.header.name = %header_str,
                                http.header.title_cased = %title_case_headers,
                                "Custom header marker found",
                            );

                            storage
                                .store_h1_settings(
                                    ua.clone(),
                                    auth,
                                    Http1Settings { title_case_headers },
                                )
                                .await
                                .context("store h1 settings")?;
                        }

                        storage
                            .store_h1_headers_xhr(ua, auth, original_headers.clone())
                            .await
                            .context("store h1 headers xhr")?;
                    }
                    Initiator::Form => {
                        storage
                            .store_h1_headers_form(ua, auth, original_headers.clone())
                            .await
                            .context("store h1 headers form")?;
                    }
                    Initiator::Ws => {
                        storage
                            .store_h1_headers_ws(ua, auth, original_headers.clone())
                            .await
                            .context("store h1 headers ws")?;
                    }
                }
            }
            http::Version::HTTP_2 => {
                if let Some(settings) = h2_settings.clone() {
                    storage
                        .store_h2_settings(ua.clone(), auth, settings)
                        .await
                        .context("store h2 settings")?;
                }
                match initiator {
                    Initiator::Navigator => {
                        storage
                            .store_h2_headers_navigate(ua, auth, original_headers.clone())
                            .await
                            .context("store h2 headers navigate")?;
                    }
                    Initiator::Fetch => {
                        storage
                            .store_h2_headers_fetch(ua, auth, original_headers.clone())
                            .await
                            .context("store h2 headers fetch")?;
                    }
                    Initiator::XMLHttpRequest => {
                        storage
                            .store_h2_headers_xhr(ua, auth, original_headers.clone())
                            .await
                            .context("store h2 headers xhr")?;
                    }
                    Initiator::Form => {
                        storage
                            .store_h2_headers_form(ua, auth, original_headers.clone())
                            .await
                            .context("store h2 headers form")?;
                    }
                    Initiator::Ws => {
                        storage
                            .store_h2_headers_ws(ua, auth, original_headers.clone())
                            .await
                            .context("store h2 headers ws")?;
                    }
                }
            }
            // HTTP/3 profiles are not collected yet: such requests are shown, never stored.
            _ => (),
        }
    }

    let headers: Vec<_> = original_headers
        .into_ordered_iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                std::str::from_utf8(value.as_bytes())
                    .map(|s| s.to_owned())
                    .unwrap_or_else(|_| format!("0x{:x?}", value.as_bytes())),
            )
        })
        .collect();

    Ok(HttpInfo {
        headers,
        version: http_version,
        initiator,
        h2_settings,
        h3,
        quic,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TlsDisplayInfo {
    pub(super) transport: &'static str,
    pub(super) completeness: Option<CaptureCompleteness>,
    pub(super) ja4: Ja4DisplayInfo,
    pub(super) ja3: Ja3DisplayInfo,
    pub(super) peet: PeetDisplayInfo,
    pub(super) protocol_version: String,
    pub(super) cipher_suites: Vec<String>,
    pub(super) compression_algorithms: Vec<String>,
    pub(super) extensions: Vec<TlsDisplayInfoExtension>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Ja4DisplayInfo {
    pub(super) full: String,
    pub(super) hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Ja3DisplayInfo {
    pub(super) full: String,
    pub(super) hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PeetDisplayInfo {
    pub(super) full: String,
    pub(super) hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TlsDisplayInfoExtension {
    pub(super) id: String,
    pub(super) data: Option<TlsDisplayInfoExtensionData>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) enum TlsDisplayInfoExtensionData {
    Single(String),
    Multi(Vec<String>),
}

fn multi<T: ToString>(v: &[T]) -> Option<TlsDisplayInfoExtensionData> {
    Some(TlsDisplayInfoExtensionData::Multi(
        v.iter().map(|s| s.to_string()).collect(),
    ))
}

pub(super) async fn get_tls_display_info_and_store(
    state: &State,
    extensions: &Extensions,
    ua: String,
) -> Result<Option<TlsDisplayInfo>, BoxError> {
    let hello: &ClientHello = match extensions
        .get_ref::<SecureTransport>()
        .and_then(|st| st.client_hello())
    {
        Some(hello) => hello,
        None => return Ok(None),
    };

    // A QUIC ClientHello carries transport parameters and differs from the TCP one: it must
    // never replace the TLS profile, which is only collected over TCP.
    let from_quic = hello
        .extensions()
        .iter()
        .any(|ext| ext.id() == ExtensionId::QUIC_TRANSPORT_PARAMETERS);
    if !from_quic && let Some(storage) = state.storage.as_ref() {
        let auth = extensions.contains::<StorageAuthorized>();
        storage
            .store_tls_client_hello(ua, auth, hello.clone())
            .await
            .context("store tls client hello")?;
    }

    let ja4 = Ja4::compute(extensions).context("ja4 compute")?;
    let ja3 = Ja3::compute(extensions).context("ja3 compute")?;
    let peet = PeetPrint::compute(extensions).context("peet print compute")?;

    Ok(Some(TlsDisplayInfo {
        transport: if from_quic { "quic" } else { "tcp" },
        completeness: extensions
            .get_ref::<QuicObservation>()
            .map(|value| value.completeness),
        ja4: Ja4DisplayInfo {
            full: format!("{ja4:?}"),
            hash: format!("{ja4}"),
        },
        ja3: Ja3DisplayInfo {
            full: format!("{ja3}"),
            hash: format!("{ja3:x}"),
        },
        peet: PeetDisplayInfo {
            full: format!("{peet:?}"),
            hash: format!("{peet}"),
        },
        protocol_version: hello.protocol_version().to_string(),
        cipher_suites: hello
            .cipher_suites()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        compression_algorithms: hello
            .compression_algorithms()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        extensions: hello
            .extensions()
            .iter()
            .map(|extension| match extension {
                ClientHelloExtension::ServerName(domain) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: domain
                        .as_ref()
                        .map(|d| TlsDisplayInfoExtensionData::Single(d.to_string())),
                },
                ClientHelloExtension::SignatureAlgorithms(v)
                | ClientHelloExtension::DelegatedCredentials(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: multi(v),
                },
                ClientHelloExtension::SupportedVersions(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: multi(v),
                },
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(v) => {
                    TlsDisplayInfoExtension {
                        id: extension.id().to_string(),
                        data: multi(v),
                    }
                }
                ClientHelloExtension::ApplicationSettings { protocols, .. } => {
                    TlsDisplayInfoExtension {
                        id: extension.id().to_string(),
                        data: multi(protocols),
                    }
                }
                ClientHelloExtension::SupportedGroups(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: multi(v),
                },
                ClientHelloExtension::ECPointFormats(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: multi(v),
                },
                ClientHelloExtension::CertificateCompression(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: multi(v),
                },
                ClientHelloExtension::RecordSizeLimit(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Single(v.to_string())),
                },
                ClientHelloExtension::EncryptedClientHello(ech) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: match ech {
                        ECHClientHello::Outer(hello) => {
                            Some(TlsDisplayInfoExtensionData::Multi(vec![
                                hello.cipher_suite.to_string(),
                                hello.config_id.to_string(),
                                rama::utils::fmt::hex(&hello.enc)
                                    .with_prefix(true)
                                    .to_string(),
                                rama::utils::fmt::hex(&hello.payload)
                                    .with_prefix(true)
                                    .to_string(),
                            ]))
                        }
                        ECHClientHello::Inner => None,
                    },
                },
                ClientHelloExtension::Opaque { id, data } => TlsDisplayInfoExtension {
                    id: id.to_string(),
                    data: if data.is_empty() {
                        None
                    } else {
                        Some(TlsDisplayInfoExtensionData::Single(
                            rama::utils::fmt::hex(data).with_prefix(true).to_string(),
                        ))
                    },
                },
            })
            .collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use rama::{
        Service as _,
        bytes::BytesMut,
        cli::service::echo::EchoServiceBuilder,
        extensions::{ExtensionsRef as _, Ingress},
        http::{
            Body, BodyExtractExt as _, Request, Version,
            core::h3::{
                connection::Config,
                qpack::{Encoder, EncoderConfig},
                server,
            },
            proto::h3::{FrameHeader, FrameType},
            service::web::response::IntoResponse as _,
        },
        net::address::SocketAddress,
        quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
        rt::{Executor, spawn},
        tls::{
            client::TlsClientConfig,
            server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
        },
        udp::test_utils::MemoryDatagramSocket,
    };
    use std::{
        future::{Future as _, poll_fn},
        num::NonZeroUsize,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[tokio::test(start_paused = true)]
    async fn observation_fp_waits_for_settings_and_echo_and_fp_report_ja4_quic() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let identity =
                ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
            let server_tls = TlsServerConfig::new()
                .with_alpn([b"h3".as_slice().into()].into_iter().collect())
                .with_server_auth(identity.clone());
            let client_tls = TlsClientConfig::new()
                .with_alpn([b"h3".as_slice().into()].into_iter().collect())
                .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
                .unwrap();
            let mut server_config =
                ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
            server_config.set_capture(Default::default());
            let mut client_config =
                ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap();
            let mut transport = TransportConfig::default();
            Config::default()
                .configure_transport(&mut transport)
                .unwrap();
            let transport = Arc::new(transport);
            server_config.set_transport_config(transport.clone());
            client_config.set_transport_config(transport);
            let (server_socket, client_socket) = MemoryDatagramSocket::pair(
                SocketAddress::local_ipv4(443),
                SocketAddress::local_ipv4(444),
                NonZeroUsize::MIN,
            );
            let server_endpoint = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .with_datagram_socket(server_socket)
                .unwrap();
            let client_endpoint = Endpoint::build(Executor::new())
                .with_datagram_socket(client_socket)
                .unwrap();
            let accepting = spawn({
                let endpoint = server_endpoint.clone();
                async move { endpoint.accept().await.unwrap().await.unwrap() }
            });
            let client = client_endpoint
                .connect_with(
                    client_config,
                    server_endpoint.local_addr().unwrap(),
                    "localhost",
                )
                .unwrap()
                .await
                .unwrap();
            let connection = accepting.await.unwrap();
            let (mut server, driver) = server::handshake(
                connection.clone(),
                Config {
                    observation: Some(Default::default()),
                    ..Config::default()
                },
            )
            .unwrap();
            spawn(driver.run());
            let (mut send, _receive) = client.open_bi().await.unwrap();
            let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
            let section = encoder
                .encode(
                    u64::from(send.id()),
                    [
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", "localhost"),
                        (":path", "/"),
                    ],
                )
                .unwrap();
            let mut wire = BytesMut::new();
            FrameHeader::new(FrameType::HEADERS, section.len() as u64)
                .encode(&mut wire)
                .unwrap();
            wire.extend_from_slice(&section);
            send.write_all(&wire).await.unwrap();
            send.finish().unwrap();
            let (request, _response) = server.accept().await.unwrap().resolve().await.unwrap();
            request
                .extensions()
                .insert(Ingress(connection.extensions().clone()));
            let ext = request.extensions();
            let timed_out = http3_info(ext).await.unwrap();
            assert!(matches!(
                timed_out.settings_status,
                SettingsStatus::TimedOut
            ));
            let mut waiting = pin!(http3_info(ext));
            assert!(
                poll_fn(|_| Poll::Ready(
                    waiting
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                ))
                .await
            );
            let mut control = client.open_uni().await.unwrap();
            control.write_all(&[0, 4, 0]).await.unwrap();
            let captured = waiting.await.unwrap();
            assert!(matches!(captured.settings_status, SettingsStatus::Received));
            assert!(captured.connection.completeness.settings);
            assert!(captured.request.connection.settings.is_none());
            let state = State {
                data_source: DataSource::default(),
                probe_http3: false,
                storage: None,
                storage_auth: None,
                geo_db: None,
            };
            let tls = get_tls_display_info_and_store(&state, ext, "test/1".to_owned())
                .await
                .unwrap()
                .unwrap();
            assert!(tls.ja4.hash.starts_with('q'), "{}", tls.ja4.hash);
            let echo_request = Request::builder()
                .uri("https://localhost/")
                .version(Version::HTTP_3)
                .body(Body::empty())
                .unwrap();
            echo_request.extensions().insert(Ingress(ext.clone()));
            let response = EchoServiceBuilder::new()
                .build_http(Executor::new())
                .serve(echo_request)
                .await
                .unwrap()
                .into_response();
            let json: serde_json::Value = response.try_into_json().await.unwrap();
            assert!(
                json["tls"]["ja4"]["hash"]
                    .as_str()
                    .unwrap()
                    .starts_with('q')
            );
            client.close(0u32, b"test complete");
            tokio::join!(client_endpoint.shutdown(), server_endpoint.shutdown());
        })
        .await
        .unwrap();
    }
}
