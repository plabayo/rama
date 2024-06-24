use super::State;
use rama::{
    http::{dep::http::request::Parts, headers::Forwarded, Request, RequestContext},
    net::stream::SocketInfo,
    service::Context,
    tls::rustls::server::IncomingClientHello,
    ua::UserAgent,
};
use serde::Serialize;
use std::str::FromStr;

#[derive(Debug, Clone, Default, Serialize)]
#[allow(dead_code)]
pub enum FetchMode {
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
pub enum ResourceType {
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
pub enum Initiator {
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
pub struct DataSource {
    pub name: String,
    pub version: String,
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
pub struct UserAgentInfo {
    pub user_agent: String,
    pub kind: Option<String>,
    pub version: Option<usize>,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo {
    pub version: String,
    pub scheme: String,
    pub authority: Option<String>,
    pub method: String,
    pub fetch_mode: FetchMode,
    pub resource_type: ResourceType,
    pub initiator: Initiator,
    pub path: String,
    pub uri: String,
    pub peer_addr: Option<String>,
}

pub async fn get_user_agent_info(ctx: &Context<State>) -> UserAgentInfo {
    ctx.get()
        .map(|ua: &UserAgent| UserAgentInfo {
            user_agent: ua.header_str().to_owned(),
            kind: ua.info().map(|info| info.kind.to_string()),
            version: ua.info().and_then(|info| info.version),
            platform: ua.platform().map(|v| v.to_string()),
        })
        .unwrap_or_default()
}

pub async fn get_request_info(
    fetch_mode: FetchMode,
    resource_type: ResourceType,
    initiator: Initiator,
    ctx: &Context<State>,
    parts: &Parts,
) -> RequestInfo {
    let request_context = ctx.get::<RequestContext>();
    let authority = request_context
        .and_then(|ctx| ctx.authority.as_ref())
        .map(|a| a.to_string());
    let scheme = request_context
        .map(|ctx| ctx.protocol.to_string())
        .unwrap_or_else(|| "http".to_owned());

    RequestInfo {
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
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpInfo {
    pub headers: Vec<(String, String)>,
}

pub fn get_http_info(req: &Request) -> HttpInfo {
    // TODO: get in correct order
    // TODO: get in correct case
    // TODO: get also pseudo headers (or separate?!)
    let headers = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().map(|v| v.to_owned()).unwrap_or_default(),
            )
        })
        .collect();

    HttpInfo { headers }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    pub server_name: Option<String>,
    pub signature_schemes: Vec<String>,
    pub alpn: Option<Vec<Vec<u8>>>,
    pub cipher_suites: Vec<String>,
}

// TODO: important to not extract these as strings, but instead as a custom struct,
// so we can store them in DB as their raw value, for use emulation,
// because unknown for rustls might be known for boringssl, etc...

pub fn get_tls_info(ctx: &Context<State>) -> Option<TlsInfo> {
    let client_hello: &IncomingClientHello = ctx.get()?;

    Some(TlsInfo {
        server_name: client_hello.server_name.clone(),
        signature_schemes: client_hello
            .signature_schemes
            .iter()
            .map(|v| format!("{:?}", v))
            .collect(),
        alpn: client_hello.alpn.clone(),
        cipher_suites: client_hello
            .cipher_suites
            .iter()
            .map(|v| format!("{:?}", v))
            .collect(),
    })
}
