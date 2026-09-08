use super::*;
use rama_utils::str::arcstr::ArcStr;

rama_utils::macros::enums::enum_builder! {
    /// HTTP head direction or a direction supplied by an upgraded protocol.
    /// Unknown adapter tags remain usable without importing that protocol here.
    @String
    pub enum HttpMessageDirection {
        Request => "request",
        Response => "response",
        Ingress => "ingress",
        Egress => "egress",
    }
}

/// A captured HTTP head or an adapter-supplied message on an upgraded connection.
/// Direction and kind are adapter tags; routing and HTTP values retain their types.
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub id: u64,
    pub connection: u64,
    pub connection_display_id: Option<u64>,
    pub exchange: Option<u64>,
    pub protocol: Protocol,
    pub direction: HttpMessageDirection,
    pub method: Method,
    pub url: Uri,
    pub host: Option<Host>,
    pub path: String,
    pub port: Option<u16>,
    pub kind: ArcStr,
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
            direction: HttpMessageDirection::Request,
            method: Method::GET,
            url: Uri::default(),
            host: None,
            path: "/".into(),
            port: None,
            kind: ArcStr::default(),
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
impl Message {
    pub fn version(&self) -> Version {
        self.http_version
    }
    pub fn is_http(&self) -> bool {
        matches!(
            self.direction,
            HttpMessageDirection::Request | HttpMessageDirection::Response
        )
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
            + self.path.len()
            + self.protocol.as_str().len()
            + self.method.as_str().len()
            + self.direction.as_str().len()
            + self.kind.len()
            + 256
    }
}
