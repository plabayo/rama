use super::{State, StorageAuthorized};
use rama::{
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::Extensions,
    http::{
        self, HeaderMap, HeaderName, Request,
        core::h2::frame::EarlyFrameCapture,
        headers::forwarded::Forwarded,
        proto::{h1::Http1HeaderMap, h2::PseudoHeaderOrder},
        request::Parts,
    },
    net::{
        fingerprint::{AkamaiH2, Ja3, Ja4, Ja4H, PeetPrint},
        http::RequestContext,
        stream::SocketInfo,
        tls::{
            SecureTransport,
            client::{ClientHello, ClientHelloExtension, ECHClientHello},
        },
    },
    telemetry::tracing,
    ua::{
        UserAgent,
        profile::{Http1Settings, Http2Settings},
    },
};
use serde::Serialize;
use std::{str::FromStr, sync::Arc};

#[derive(Debug, Clone, Default, Serialize)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
}

pub(super) async fn get_user_agent_info(extensions: &Extensions) -> UserAgentInfo {
    extensions
        .get()
        .map(|ua: &UserAgent| UserAgentInfo {
            user_agent: ua.header_str().to_owned(),
            kind: ua.info().map(|info| info.kind.to_string()),
            version: ua.info().and_then(|info| info.version),
            platform: ua.platform().map(|v| v.to_string()),
        })
        .unwrap_or_default()
}

pub(super) async fn get_request_info(
    fetch_mode: FetchMode,
    resource_type: ResourceType,
    initiator: Initiator,
    parts: &Parts,
) -> Result<RequestInfo, BoxError> {
    let request_context =
        RequestContext::try_from(parts).context("get or compose RequestContext")?;

    let authority = request_context.authority.to_string();
    let scheme = request_context.protocol.to_string();

    Ok(RequestInfo {
        version: format!("{:?}", parts.version),
        scheme,
        authority,
        method: parts.method.as_str().to_owned(),
        fetch_mode: parts
            .headers
            .get("sec-fetch-mode")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(fetch_mode),
        resource_type,
        initiator,
        path: parts.uri.path().to_owned(),
        uri: parts.uri.to_string(),
        peer_addr: parts
            .extensions
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_socket_addr()
                    .map(|addr| addr.to_string())
                    .or_else(|| f.client_ip().map(|ip| ip.to_string()))
            })
            .or_else(|| {
                parts
                    .extensions
                    .get::<SocketInfo>()
                    .map(|v| v.peer_addr().to_string())
            }),
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Ja4HInfo {
    pub(super) hash: String,
    pub(super) human_str: String,
}

pub(super) fn get_ja4h_info<B>(req: &Request<B>) -> Option<Ja4HInfo> {
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
    pub(super) h2_settings: Option<Http2Settings>,
}

pub(super) async fn get_and_store_http_info(
    headers: HeaderMap,
    ext: &Extensions,
    http_version: http::Version,
    ua: String,
    initiator: Initiator,
) -> Result<HttpInfo, OpaqueError> {
    let original_headers = Http1HeaderMap::new(headers, Some(ext));

    let h2_settings = match http_version {
        http::Version::HTTP_2 => Some(Http2Settings {
            http_pseudo_headers: ext.get::<PseudoHeaderOrder>().cloned(),
            early_frames: ext.get::<EarlyFrameCapture>().cloned(),
        }),
        _ => None,
    };

    if let Some(storage) = ext.get::<Arc<State>>().unwrap().storage.as_ref() {
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
                        if let Some(header_name) = original_headers.get_original_name(
                            &HeaderName::from_static("x-rama-custom-header-marker"),
                        ) {
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
            _ => (),
        }
    }

    let headers: Vec<_> = original_headers
        .into_iter()
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
        h2_settings,
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TlsDisplayInfo {
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

pub(super) async fn get_tls_display_info_and_store(
    extensions: &Extensions,
    ua: String,
) -> Result<Option<TlsDisplayInfo>, OpaqueError> {
    let hello: &ClientHello = match extensions
        .get::<SecureTransport>()
        .and_then(|st| st.client_hello())
    {
        Some(hello) => hello,
        None => return Ok(None),
    };

    if let Some(storage) = extensions.get::<Arc<State>>().unwrap().storage.as_ref() {
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
                ClientHelloExtension::SignatureAlgorithms(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::SupportedVersions(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(v) => {
                    TlsDisplayInfoExtension {
                        id: extension.id().to_string(),
                        data: Some(TlsDisplayInfoExtensionData::Multi(
                            v.iter().map(|s| s.to_string()).collect(),
                        )),
                    }
                }
                ClientHelloExtension::ApplicationSettings(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::SupportedGroups(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::ECPointFormats(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::CertificateCompression(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
                },
                ClientHelloExtension::DelegatedCredentials(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: Some(TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    )),
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
                                format!("0x{}", hex::encode(&hello.enc)),
                                format!("0x{}", hex::encode(&hello.payload)),
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
                        Some(TlsDisplayInfoExtensionData::Single(format!(
                            "0x{}",
                            hex::encode(data)
                        )))
                    },
                },
            })
            .collect::<Vec<_>>(),
    }))
}
