use rama_net::{AuthorityInputExt as _, ProtocolInputExt as _, uri::PathRef};
use rama_utils::str::NonEmptyStr;

use super::*;
use crate::request::Parts;

pub use rama_inspect::Direction;

/// A captured HTTP head or an adapter-supplied message on an upgraded connection.
/// Routing and HTTP values retain their types; upgraded protocols supply their own kind tags.
#[derive(Debug, Clone, Serialize)]
#[serde(remote = "Self")]
pub struct Message {
    pub id: u64,
    pub connection: u64,
    pub connection_display_id: Option<u64>,
    pub exchange: Option<u64>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub method: Method,
    pub url: Uri,
    pub host: Option<Host>,
    pub port: Option<u16>,
    /// Optional protocol-owned application message tag (for example WebSocket
    /// `text` or `binary`). HTTP heads have no kind; custom upgrade adapters may
    /// supply their own nonempty tags without adding a protocol dependency here.
    pub kind: Option<NonEmptyStr>,
    pub headers: HeaderMap,
    pub status: Option<StatusCode>,
    #[serde(serialize_with = "payload::serialize_editor")]
    pub payload: Option<Payload>,
    pub binary: bool,
    pub oversized: bool,
    pub conditional: bool,
    pub http_version: Version,
    pub queued_at: Option<jiff::Timestamp>,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            id: 0,
            connection: 0,
            connection_display_id: None,
            exchange: None,
            protocol: Protocol::HTTP,
            direction: Direction::Ingress,
            method: Method::GET,
            url: Uri::default(),
            host: None,
            port: None,
            kind: None,
            headers: HeaderMap::new(),
            status: None,
            payload: None,
            binary: false,
            oversized: false,
            conditional: false,
            http_version: Version::HTTP_11,
            queued_at: None,
        }
    }
}

impl Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct WithPath<'a> {
            #[serde(flatten, with = "Message")]
            message: &'a Message,
            path: PathRef<'a>,
        }

        WithPath {
            message: self,
            path: self.path(),
        }
        .serialize(serializer)
    }
}

impl Message {
    /// Borrow the request URI's path, defaulting to the origin-form root.
    pub fn path(&self) -> PathRef<'_> {
        self.url.path_ref_or_root()
    }

    pub fn version(&self) -> Version {
        self.http_version
    }

    pub fn is_http(&self) -> bool {
        self.kind.is_none()
    }

    pub(super) fn size(&self) -> usize {
        if self.oversized {
            return MAX_MESSAGE_BYTES + 1;
        }
        self.headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            + self.payload.as_ref().map_or(0, Payload::len)
            + self.url.as_str().len()
            + self.protocol.as_str().len()
            + self.method.as_str().len()
            + self.direction.as_str().len()
            + self.kind.as_ref().map_or(0, |kind| kind.len())
            + 256
    }
}

pub fn http_message(parts: &Parts) -> Message {
    let protocol = parts.protocol().unwrap_or(&Protocol::HTTP);
    let (host, port) = match parts.authority_with_default_port(None) {
        Some(authority) => (Some(authority.host), Some(authority.port)),
        None => (parts.host(), parts.protocol_default_port()),
    };
    Message {
        protocol: protocol.clone(),
        direction: Direction::Ingress,
        method: parts.method.clone(),
        url: parts.uri.clone(),
        host,
        port,
        headers: parts.headers.clone(),
        conditional: matches!(parts.method, Method::GET | Method::HEAD)
            && (parts.headers.contains_key(header::IF_NONE_MATCH)
                || parts.headers.contains_key(header::IF_MODIFIED_SINCE)),
        http_version: parts.version,
        ..Message::default()
    }
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(proxy))]
pub struct HttpUpgradeContext {
    pub connection: ControlConnection,
    pub request: Message,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingSummary {
    pub kind: Option<NonEmptyStr>,
    pub id: u64,
    pub connection: u64,
    pub connection_display_id: Option<u64>,
    pub exchange: Option<u64>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub method: Method,
    pub url: Uri,
    pub status: Option<StatusCode>,
    pub queued_at: Option<jiff::Timestamp>,
}

impl From<&Message> for PendingSummary {
    fn from(m: &Message) -> Self {
        Self {
            kind: m.kind.clone(),
            id: m.id,
            connection: m.connection,
            connection_display_id: m.connection_display_id,
            exchange: m.exchange,
            protocol: m.protocol.clone(),
            direction: m.direction,
            method: m.method.clone(),
            url: m.url.clone(),
            status: m.status,
            queued_at: m.queued_at,
        }
    }
}
