use std::str::FromStr;

use rama::http::Request;

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub user_agent: Option<String>,
    pub method: String,
    pub fetch_mode: FetchMode,
    pub resource_type: ResourceType,
    pub initiator: Initiator,
    pub path: String,
    pub version: String,
}

pub fn get_request_info(
    fetch_mode: FetchMode,
    resource_type: ResourceType,
    initiator: Initiator,
    req: &Request,
) -> RequestInfo {
    RequestInfo {
        user_agent: req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_owned()),
        method: req.method().as_str().to_owned(),
        fetch_mode: req
            .headers()
            .get("sec-fetch-mode")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(fetch_mode),
        resource_type,
        initiator,
        path: req.uri().path().to_owned(),
        version: format!("{:?}", req.version()),
    }
}

pub fn get_headers(req: &Request) -> Vec<(String, String)> {
    // TODO: get in correct order
    // TODO: get in correct case
    // TODO: get also pseudo headers (or separate?!)
    req.headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().map(|v| v.to_owned()).unwrap_or_default(),
            )
        })
        .collect()
}
