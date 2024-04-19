use super::State;
use rama::{
    http::{dep::http::request::Parts, Request, RequestContext},
    service::Context,
    stream::SocketInfo,
    tls::rustls::server::IncomingClientHello,
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
            name: "rama-fp".to_owned(),
            version: "v0.2".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo {
    pub user_agent: Option<String>,
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

pub async fn get_request_info(
    fetch_mode: FetchMode,
    resource_type: ResourceType,
    initiator: Initiator,
    ctx: &Context<State>,
    parts: &Parts,
) -> RequestInfo {
    let authority = ctx
        .get::<RequestContext>()
        .and_then(RequestContext::authority);

    RequestInfo {
        user_agent: parts
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_owned()),
        version: format!("{:?}", parts.version),
        scheme: parts
            .uri
            .scheme_str()
            .map(|v| v.to_owned())
            .unwrap_or_else(|| {
                if ctx.get::<IncomingClientHello>().is_some() {
                    "https"
                } else {
                    "http"
                }
                .to_owned()
            }),
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
        peer_addr: ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string()),
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
