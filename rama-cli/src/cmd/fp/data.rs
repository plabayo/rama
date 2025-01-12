use super::State;
use rama::{
    error::{BoxError, ErrorContext},
    http::{
        dep::http::{request::Parts, Extensions},
        headers::Forwarded,
        proto::{h1::Http1HeaderMap, h2::PseudoHeaderOrder},
        HeaderMap, Request,
    },
    net::{
        fingerprint::{Ja3, Ja4, Ja4H},
        http::RequestContext,
        stream::SocketInfo,
    },
    tls::types::{
        client::{ClientHello, ClientHelloExtension},
        SecureTransport,
    },
    ua::UserAgent,
    Context,
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
    Websocket,
}

impl std::fmt::Display for FetchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cors => write!(f, "cors"),
            Self::Navigate => write!(f, "navigate"),
            Self::NoCors => write!(f, "no-cors"),
            Self::SameOrigin => write!(f, "same-origin"),
            Self::Websocket => write!(f, "websocket"),
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
            "websocket" => Ok(Self::Websocket),
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
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Navigator => write!(f, "navigator"),
            Self::Fetch => write!(f, "fetch"),
            Self::XMLHttpRequest => write!(f, "xmlhttprequest"),
            Self::Form => write!(f, "form"),
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

pub(super) async fn get_user_agent_info(ctx: &Context<Arc<State>>) -> UserAgentInfo {
    ctx.get()
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
    ctx: &mut Context<Arc<State>>,
    parts: &Parts,
) -> Result<RequestInfo, BoxError> {
    let request_context = ctx
        .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, parts).try_into())
        .context("get or compose RequestContext")?;

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
        peer_addr: ctx
            .get::<Forwarded>()
            .and_then(|f| {
                f.client_socket_addr()
                    .map(|addr| addr.to_string())
                    .or_else(|| f.client_ip().map(|ip| ip.to_string()))
            })
            .or_else(|| ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string())),
    })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Ja4HInfo {
    pub(super) hash: String,
    pub(super) human_str: String,
}

pub(super) fn get_ja4h_info<B>(req: &Request<B>) -> Option<Ja4HInfo> {
    Ja4H::compute(req)
        .inspect_err(|err| tracing::error!(?err, "ja4h compute failure"))
        .ok()
        .map(|ja4h| Ja4HInfo {
            hash: format!("{ja4h}"),
            human_str: format!("{ja4h:?}"),
        })
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HttpInfo {
    pub(super) headers: Vec<(String, String)>,
    pub(super) pseudo_headers: Option<Vec<String>>,
}

pub(super) fn get_http_info(headers: HeaderMap, ext: &mut Extensions) -> HttpInfo {
    let headers: Vec<_> = Http1HeaderMap::new(headers, Some(ext))
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

    let pseudo_headers: Option<Vec<_>> = ext
        .get::<PseudoHeaderOrder>()
        .map(|o| o.iter().map(|p| p.to_string()).collect());

    HttpInfo {
        headers,
        pseudo_headers,
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct TlsDisplayInfo {
    pub(super) ja4: Ja4DisplayInfo,
    pub(super) ja3: Ja3DisplayInfo,
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
pub(super) struct TlsDisplayInfoExtension {
    pub(super) id: String,
    pub(super) data: TlsDisplayInfoExtensionData,
}

#[derive(Debug, Clone, Serialize)]
pub(super) enum TlsDisplayInfoExtensionData {
    Single(String),
    Multi(Vec<String>),
}

pub(super) fn get_tls_display_info(ctx: &Context<Arc<State>>) -> Option<TlsDisplayInfo> {
    let hello: &ClientHello = ctx
        .get::<SecureTransport>()
        .and_then(|st| st.client_hello())?;

    let ja4 = Ja4::compute(ctx.extensions())
        .inspect_err(|err| tracing::error!(?err, "ja4 compute failure"))
        .ok()?;

    let ja3 = Ja3::compute(ctx.extensions())
        .inspect_err(|err| tracing::error!(?err, "ja3 compute failure"))
        .ok()?;

    Some(TlsDisplayInfo {
        ja4: Ja4DisplayInfo {
            full: format!("{ja4:?}"),
            hash: format!("{ja4}"),
        },
        ja3: Ja3DisplayInfo {
            full: format!("{ja3}"),
            hash: format!("{ja3:x}"),
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
                    data: TlsDisplayInfoExtensionData::Single(match domain {
                        Some(domain) => domain.to_string(),
                        None => "".to_owned(),
                    }),
                },
                ClientHelloExtension::SignatureAlgorithms(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    ),
                },
                ClientHelloExtension::SupportedVersions(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    ),
                },
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(v) => {
                    TlsDisplayInfoExtension {
                        id: extension.id().to_string(),
                        data: TlsDisplayInfoExtensionData::Multi(
                            v.iter().map(|s| s.to_string()).collect(),
                        ),
                    }
                }
                ClientHelloExtension::SupportedGroups(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    ),
                },
                ClientHelloExtension::ECPointFormats(v) => TlsDisplayInfoExtension {
                    id: extension.id().to_string(),
                    data: TlsDisplayInfoExtensionData::Multi(
                        v.iter().map(|s| s.to_string()).collect(),
                    ),
                },
                ClientHelloExtension::Opaque { id, data } => TlsDisplayInfoExtension {
                    id: id.to_string(),
                    data: TlsDisplayInfoExtensionData::Single(if data.is_empty() {
                        "EMPTY".to_owned()
                    } else {
                        format!("0x{}", hex::encode(data))
                    }),
                },
            })
            .collect::<Vec<_>>(),
    })
}
