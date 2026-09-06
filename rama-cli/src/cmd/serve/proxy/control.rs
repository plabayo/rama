//! Runtime traffic decisions. Protocol adapters own streams; this bounded queue owns only
//! editable messages and one-shot decisions. Capture admission never controls forwarding.

use super::{
    capture::{captured_header_value, headers_to_vec},
    inspection::InspectionState,
};
use arc_swap::ArcSwap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use parking_lot::Mutex;
use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::Extension,
    http::{Body, HeaderMap, HeaderName, Method, Response, StatusCode, Version, header},
    net::address::{Host, HostPattern},
    utils::thirdparty::wildcard::{Wildcard, WildcardBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{oneshot, watch};

const MAX_RULES: usize = 256;
const MAX_HEADERS: usize = 256;
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_HOSTS: usize = 4096;

#[derive(Debug, Clone, Extension)]
#[extension(tags(proxy))]
pub(super) struct ControlConnection(pub Arc<Connection>);

#[derive(Debug)]
pub(super) struct Connection {
    pub id: u64,
    automatic: AtomicBool,
    observed: Mutex<BTreeMap<String, bool>>,
}

impl ControlConnection {
    pub(super) fn new(id: u64) -> Self {
        Self(Arc::new(Connection {
            id,
            automatic: AtomicBool::new(false),
            observed: Mutex::new(BTreeMap::new()),
        }))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Matcher {
    pub host: String,
    pub path: String,
    pub protocol: String,
    pub direction: String,
    pub method: String,
    pub port: Option<u16>,
    pub kind: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Intercept,
    Forward,
    Respond { response: ResponseSpec },
    Drop,
    Close { code: u16, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// Serde does not support deny_unknown_fields on a struct flattening a tagged enum.
pub(super) struct Rule {
    pub name: String,
    pub enabled: bool,
    pub matcher: Matcher,
    #[serde(flatten)]
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Config {
    pub enabled: bool,
    pub queue_limit: usize,
    pub timeout_seconds: u64,
    pub default_response: ResponseSpec,
    pub rules: Vec<Rule>,
    pub presets: Vec<Preset>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_limit: 128,
            timeout_seconds: 300,
            default_response: ResponseSpec::default(),
            rules: vec![],
            presets: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preset {
    pub name: String,
    pub response: ResponseSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ResponseSpec {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Default for ResponseSpec {
    fn default() -> Self {
        Self {
            status: 403,
            headers: vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("cache-control".into(), "no-store".into()),
            ],
            body: "Blocked by Rama proxy.\n".into(),
        }
    }
}

impl ResponseSpec {
    fn validate(&self) -> Result<(), BoxError> {
        let status = StatusCode::from_u16(self.status)?;
        if !(200..=599).contains(&self.status) || status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(BoxError::from_static_str(
                "local responses must have a final HTTP status",
            ));
        }
        if matches!(self.status, 204 | 205 | 304) && !self.body.is_empty() {
            return Err(BoxError::from_static_str(
                "this status does not permit a response body",
            ));
        }
        if self.body.len() > MAX_MESSAGE_BYTES {
            return Err(BoxError::from_static_str("response body is too large"));
        }
        let headers = parse_headers(&self.headers)?;
        if [
            "transfer-encoding",
            "content-length",
            "connection",
            "trailer",
            "upgrade",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "keep-alive",
            "te",
        ]
        .iter()
        .any(|name| headers.contains_key(*name))
        {
            return Err(BoxError::from_static_str(
                "Rama manages local-response framing and proxy headers",
            ));
        }
        if matches!(self.status, 301 | 302 | 303 | 307 | 308)
            && headers
                .get(header::LOCATION)
                .is_none_or(|v| v.as_bytes().is_empty())
        {
            return Err(BoxError::from_static_str(
                "redirect responses require a Location header",
            ));
        }
        Ok(())
    }

    pub(super) fn build(&self, message: &Message) -> Response {
        // Stored configuration and manual decisions are validated before publication.
        let spec = if message.method == "CONNECT" && (200..300).contains(&self.status) {
            Self::error(502, "A local response cannot establish a CONNECT tunnel.")
        } else if self.status == 304 && !message.conditional {
            Self::error(
                412,
                "Not Modified requires a conditional GET or HEAD request.",
            )
        } else {
            self.clone()
        };
        let mut response = Response::new(if message.method == "HEAD" {
            Body::empty()
        } else {
            Body::from(spec.body.clone())
        });
        *response.status_mut() = StatusCode::from_u16(spec.status).unwrap_or(StatusCode::FORBIDDEN);
        *response.version_mut() = message.version();
        *response.headers_mut() = parse_headers(&spec.headers).unwrap_or_default();
        if !matches!(spec.status, 204 | 304) {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, spec.body.len().into());
        }
        // Unread request bodies cannot be reused as the next HTTP/1 request.
        if message.direction == "request" && message.version() != Version::HTTP_2 {
            response.headers_mut().insert(
                header::CONNECTION,
                rama::http::HeaderValue::from_static("close"),
            );
        }
        response
    }

    pub(super) fn error(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.into(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Message {
    pub id: u64,
    pub connection: u64,
    pub connection_display_id: Option<u64>,
    pub exchange: Option<u64>,
    pub protocol: String,
    pub direction: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub port: Option<u16>,
    pub kind: String,
    pub headers: Vec<(String, String)>,
    pub status: Option<u16>,
    pub payload: Option<String>,
    pub binary: bool,
    pub oversized: bool,
    pub conditional: bool,
    pub http2: bool,
    pub queued_at: Option<jiff::Timestamp>,
}

impl Message {
    pub(super) fn version(&self) -> Version {
        if self.http2 {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        }
    }
    pub(super) fn is_http(&self) -> bool {
        matches!(self.direction.as_str(), "request" | "response")
    }
    fn size(&self) -> usize {
        if self.oversized {
            return MAX_MESSAGE_BYTES + 1;
        }
        self.headers
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
            + self.payload.as_ref().map_or(0, String::len)
            + self.url.len()
            + self.host.len()
            + self.path.len()
            + 256
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Decision {
    Forward {
        headers: Option<Vec<(String, String)>>,
        status: Option<u16>,
        payload: Option<String>,
    },
    Connection {
        headers: Option<Vec<(String, String)>>,
        status: Option<u16>,
        payload: Option<String>,
    },
    Block,
    Respond {
        response: ResponseSpec,
    },
    Drop,
    Close {
        code: u16,
        reason: String,
    },
}

impl Decision {
    pub(super) fn forward() -> Self {
        Self::Forward {
            headers: None,
            status: None,
            payload: None,
        }
    }
    fn validate(&self, message: &Message) -> Result<(), BoxError> {
        match self {
            Self::Forward {
                headers,
                status,
                payload,
            }
            | Self::Connection {
                headers,
                status,
                payload,
            } => {
                if let Some(headers) = headers {
                    if !message.is_http() {
                        return Err(BoxError::from_static_str(
                            "WebSocket messages have no HTTP headers",
                        ));
                    }
                    let original = parse_headers(&message.headers)?;
                    let edited = parse_headers(headers)?;
                    // Body, routing and upgrade semantics cannot be changed by a header-only editor.
                    for name in [
                        "host",
                        "content-length",
                        "transfer-encoding",
                        "content-encoding",
                        "connection",
                        "proxy-connection",
                        "keep-alive",
                        "trailer",
                        "te",
                        "upgrade",
                        "proxy-authorization",
                        "proxy-authenticate",
                        "sec-websocket-version",
                        "sec-websocket-key",
                        "sec-websocket-accept",
                        "sec-websocket-extensions",
                        "sec-websocket-protocol",
                    ] {
                        if original
                            .get_all(name)
                            .iter()
                            .ne(edited.get_all(name).iter())
                        {
                            return Err(format!(
                                "{name} is managed by the transport and cannot be changed here"
                            )
                            .into());
                        }
                    }
                }
                if let Some(status) = status
                    && (message.direction != "response"
                        || !(200..=599).contains(status)
                        || matches!(status, 204 | 205 | 304)
                        || matches!(message.status, Some(101 | 204 | 205 | 304))
                        || message.method == "CONNECT")
                {
                    return Err(BoxError::from_static_str(
                        "use Respond locally to change body or upgrade semantics",
                    ));
                }
                if let Some(payload) = payload {
                    if message.is_http() || payload.len() > MAX_MESSAGE_BYTES {
                        return Err(BoxError::from_static_str("invalid message payload"));
                    }
                    if message.binary {
                        BASE64
                            .decode(payload)
                            .context("parse binary message as base64")?;
                    }
                }
            }
            Self::Respond { response } => {
                if !message.is_http() {
                    return Err(BoxError::from_static_str(
                        "an established WebSocket cannot send an HTTP response",
                    ));
                }
                response.validate()?;
                if message.method == "CONNECT" && (200..300).contains(&response.status) {
                    return Err(BoxError::from_static_str(
                        "a local response cannot establish a CONNECT tunnel",
                    ));
                }
                if response.status == 304 && !message.conditional {
                    return Err(BoxError::from_static_str(
                        "304 requires a conditional GET or HEAD request",
                    ));
                }
            }
            Self::Drop | Self::Close { .. } if message.is_http() => {
                return Err(BoxError::from_static_str(
                    "use Block or Respond locally for HTTP messages",
                ));
            }
            Self::Close { code, reason } => validate_close(*code, reason)?,
            _ => (),
        }
        Ok(())
    }
}

fn validate_close(code: u16, reason: &str) -> Result<(), BoxError> {
    if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) || reason.len() > 123 {
        return Err(BoxError::from_static_str(
            "invalid WebSocket close code or reason",
        ));
    }
    Ok(())
}

pub(super) fn parse_headers(values: &[(String, String)]) -> Result<HeaderMap, BoxError> {
    if values.len() > MAX_HEADERS
        || values.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > MAX_MESSAGE_BYTES
    {
        return Err(BoxError::from_static_str("too many or oversized headers"));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(name.parse::<HeaderName>()?, captured_header_value(value)?);
    }
    Ok(headers)
}

#[derive(Clone)]
struct CompiledRule {
    rule: Rule,
    host: Option<HostPattern>,
    path: Option<Wildcard<'static>>,
    headers: Vec<(HeaderName, Wildcard<'static>)>,
}
#[derive(Clone)]
struct Policy {
    revision: u64,
    config: Config,
    rules: Vec<CompiledRule>,
}

impl CompiledRule {
    fn new(rule: Rule) -> Result<Self, BoxError> {
        if rule.name.len() > 128 {
            return Err(BoxError::from_static_str("rule name is too long"));
        }
        let m = &rule.matcher;
        let host = if m.host.is_empty() {
            None
        } else {
            Some(HostPattern::try_new(m.host.clone())?)
        };
        let pattern = |value: &str| -> Result<Wildcard<'static>, BoxError> {
            if value.len() > 1024 {
                return Err(BoxError::from_static_str("pattern is too long"));
            }
            WildcardBuilder::from_owned(value.as_bytes().to_vec())
                .without_one_metasymbol()
                .without_escape()
                .build()
                .context("compile rule pattern")
        };
        if m.headers.len() > 16
            || m.host.len() > 1024
            || m.port == Some(0)
            || m.status.is_some_and(|s| !(100..=599).contains(&s))
            || [&m.protocol, &m.method, &m.direction, &m.kind]
                .iter()
                .any(|v| v.len() > 64)
        {
            return Err(BoxError::from_static_str("rule matcher is too large"));
        }
        let path = (!m.path.is_empty()).then(|| pattern(&m.path)).transpose()?;
        let headers = m
            .headers
            .iter()
            .map(|(k, v)| Ok((k.parse()?, pattern(v)?)))
            .collect::<Result<_, BoxError>>()?;
        match &rule.action {
            Action::Respond { response } => response.validate()?,
            Action::Close { code, reason } => validate_close(*code, reason)?,
            _ => (),
        }
        Ok(Self {
            rule,
            host,
            path,
            headers,
        })
    }
    fn matches(&self, message: &Message) -> bool {
        let m = &self.rule.matcher;
        self.rule.enabled
            && (m.protocol.is_empty() || m.protocol.eq_ignore_ascii_case(&message.protocol))
            && (m.direction.is_empty() || m.direction == message.direction)
            && (m.method.is_empty() || m.method.eq_ignore_ascii_case(&message.method))
            && (m.kind.is_empty() || m.kind == message.kind)
            && m.port.is_none_or(|p| Some(p) == message.port)
            && m.status.is_none_or(|s| Some(s) == message.status)
            && self.host.as_ref().is_none_or(|p| {
                Host::try_from(message.host.as_str()).is_ok_and(|h| p.matches(h.view()))
            })
            && self
                .path
                .as_ref()
                .is_none_or(|p| p.is_match(message.path.as_bytes()))
            && self.headers.iter().all(|(name, pattern)| {
                message.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case(name.as_str()) && pattern.is_match(v.as_bytes())
                })
            })
    }
}

struct Pending {
    message: Arc<Message>,
    connection: ControlConnection,
    reply: oneshot::Sender<Decision>,
}
#[derive(Default)]
struct State {
    next_id: u64,
    pending: BTreeMap<u64, Pending>,
    bytes: usize,
    bypass: BTreeMap<u64, Weak<Connection>>,
    hosts: BTreeMap<String, HostSummary>,
}
struct Inner {
    policy: ArcSwap<Policy>,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    recording: InspectionState,
}
#[derive(Clone)]
pub(super) struct Control(Arc<Inner>);
impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HostSummary {
    pub host: String,
    pub eligible: bool,
    pub connections: u64,
    pub bypassed: u64,
    pub last_seen: jiff::Timestamp,
    pub source: String,
    pub reason: String,
}

#[derive(Serialize)]
pub(super) struct ConnectionSummary {
    pub connection: u64,
    pub connection_display_id: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct Snapshot {
    pub revision: u64,
    pub config: Config,
    pub pending: Vec<PendingSummary>,
    pub hosts: Vec<HostSummary>,
    pub automatic_connections: Vec<ConnectionSummary>,
    pub recording: bool,
}

impl Control {
    pub(super) fn new(recording: InspectionState) -> Self {
        let (changes, _) = watch::channel(0);
        Self(Arc::new(Inner {
            policy: ArcSwap::from_pointee(Policy {
                revision: 0,
                config: Config::default(),
                rules: vec![],
            }),
            state: Mutex::new(State::default()),
            changes,
            recording,
        }))
    }
    pub(super) fn is_active(&self) -> bool {
        let policy = self.0.policy.load();
        self.0.recording.is_enabled() && (policy.config.enabled || !policy.rules.is_empty())
    }
    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }
    fn changed(&self) {
        self.0.changes.send_modify(|v| *v = v.wrapping_add(1));
    }
    pub(super) fn pending_summaries(&self) -> Vec<PendingSummary> {
        self.0
            .state
            .lock()
            .pending
            .values()
            .map(|p| PendingSummary::from(p.message.as_ref()))
            .collect()
    }
    pub(super) fn snapshot(&self) -> Snapshot {
        let mut state = self.0.state.lock();
        let policy = self.0.policy.load();
        state
            .bypass
            .retain(|_, connection| connection.strong_count() > 0);
        Snapshot {
            revision: policy.revision,
            config: policy.config.clone(),
            pending: state
                .pending
                .values()
                .map(|p| PendingSummary::from(p.message.as_ref()))
                .collect(),
            hosts: state.hosts.values().cloned().collect(),
            automatic_connections: state
                .bypass
                .keys()
                .map(|id| ConnectionSummary {
                    connection: *id,
                    connection_display_id: None,
                })
                .collect(),
            recording: self.0.recording.is_enabled(),
        }
    }
    pub(super) fn configure(&self, revision: u64, config: Config) -> Result<(), BoxError> {
        if config.rules.len() > MAX_RULES
            || config.presets.len() > 32
            || !(1..=256).contains(&config.queue_limit)
            || !(1..=3600).contains(&config.timeout_seconds)
        {
            return Err(BoxError::from_static_str(
                "invalid rule, preset, queue or timeout limit",
            ));
        }
        config.default_response.validate()?;
        for preset in &config.presets {
            if preset.name.len() > 128 {
                return Err(BoxError::from_static_str("preset name is too long"));
            }
            preset.response.validate()?;
        }
        let rules = config
            .rules
            .iter()
            .cloned()
            .map(CompiledRule::new)
            .collect::<Result<_, _>>()?;
        let _state = self.0.state.lock();
        if config.enabled && !self.0.recording.is_enabled() {
            return Err(BoxError::from_static_str(
                "Resume the inspector before enabling interception",
            ));
        }
        if self.0.policy.load().revision != revision {
            return Err(BoxError::from_static_str(
                "settings changed in another tab; reload settings before applying",
            ));
        }
        self.0.policy.store(Arc::new(Policy {
            revision: revision + 1,
            config,
            rules,
        }));
        self.changed();
        Ok(())
    }
    pub(super) fn observe(
        &self,
        connection: &ControlConnection,
        host: &str,
        inspected: bool,
        source: &str,
        reason: &str,
    ) {
        let Some(_permit) = self.0.recording.try_capture() else {
            return;
        };
        if host.len() > 255 || host.is_empty() {
            return;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let mut observed = connection.0.observed.lock();
        if observed.len() >= 128 && !observed.contains_key(&host) {
            return;
        }
        let previous = observed.insert(host.clone(), !inspected);
        if previous == Some(true) {
            observed.insert(host.clone(), true);
        }
        let mut state = self.0.state.lock();
        if !state.hosts.contains_key(&host) && state.hosts.len() >= MAX_HOSTS {
            let oldest = state
                .hosts
                .iter()
                .min_by_key(|(_, h)| h.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                state.hosts.remove(&oldest);
            }
        }
        let new_host = !state.hosts.contains_key(&host);
        let first = previous.is_none() || new_host;
        let newly_bypassed = !inspected && (new_host || previous != Some(true));
        let item = state
            .hosts
            .entry(host.clone())
            .or_insert_with(|| HostSummary {
                host,
                eligible: inspected,
                connections: 0,
                bypassed: 0,
                last_seen: jiff::Timestamp::now(),
                source: source.into(),
                reason: reason.into(),
            });
        if first {
            item.connections += 1;
        }
        item.bypassed += u64::from(newly_bypassed);
        item.last_seen = jiff::Timestamp::now();
        item.source = source.into();
        item.reason = reason.into();
        drop(state);
        self.changed();
    }
    pub(super) fn stop_and_forward(&self) {
        let mut state = self.0.state.lock();
        let mut policy = self.0.policy.load().as_ref().clone();
        policy.config.enabled = false;
        policy.revision += 1;
        self.0.policy.store(Arc::new(policy));
        let ids = state.pending.keys().copied().collect::<Vec<_>>();
        for id in ids {
            Self::send(&mut state, id, Decision::forward());
        }
        drop(state);
        self.changed();
    }
    pub(super) fn apply_rule(&self, index: usize, revision: u64) -> Result<(), BoxError> {
        let policy = self.0.policy.load_full();
        if policy.revision != revision {
            return Err(BoxError::from_static_str(
                "settings changed before applying the rule to pending traffic",
            ));
        }
        let rule = policy.rules.get(index).context("rule no longer exists")?;
        let decisions = {
            let state = self.0.state.lock();
            state
                .pending
                .iter()
                .filter(|(_, p)| rule.matches(&p.message))
                .filter_map(|(id, p)| {
                    let decision = match &rule.rule.action {
                        Action::Forward => Decision::forward(),
                        Action::Respond { response } if p.message.is_http() => Decision::Respond {
                            response: response.clone(),
                        },
                        Action::Drop if !p.message.is_http() => Decision::Drop,
                        Action::Close { code, reason } if !p.message.is_http() => Decision::Close {
                            code: *code,
                            reason: reason.clone(),
                        },
                        _ => return None,
                    };
                    Some((*id, decision))
                })
                .collect::<Vec<_>>()
        };
        for (id, decision) in decisions {
            _ = self.resolve(id, decision);
        }
        Ok(())
    }
    pub(super) fn clear_hosts(&self) {
        self.0.state.lock().hosts.clear();
        self.changed();
    }
    pub(super) fn resume_connection(&self, id: u64) {
        if let Some(connection) = self
            .0
            .state
            .lock()
            .bypass
            .remove(&id)
            .and_then(|c| c.upgrade())
        {
            connection.automatic.store(false, Ordering::Release);
        }
        self.changed();
    }
    pub(super) fn pending(&self, id: u64) -> Option<Arc<Message>> {
        self.0
            .state
            .lock()
            .pending
            .get(&id)
            .map(|p| p.message.clone())
    }
    pub(super) fn resolve(&self, id: u64, decision: Decision) -> Result<(), BoxError> {
        let mut state = self.0.state.lock();
        let pending = state
            .pending
            .get(&id)
            .context("message is no longer awaiting approval")?;
        decision.validate(&pending.message)?;
        let decision = if matches!(decision, Decision::Block) && pending.message.is_http() {
            Decision::Respond {
                response: self.0.policy.load().config.default_response.clone(),
            }
        } else {
            decision
        };
        if let Decision::Connection {
            headers,
            status,
            payload,
        } = decision
        {
            let connection = pending.connection.clone();
            connection.0.automatic.store(true, Ordering::Release);
            state
                .bypass
                .insert(connection.0.id, Arc::downgrade(&connection.0));
            let ids = state
                .pending
                .iter()
                .filter(|(_, p)| Arc::ptr_eq(&p.connection.0, &connection.0))
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for other in ids {
                Self::send(
                    &mut state,
                    other,
                    if other == id {
                        Decision::Forward {
                            headers: headers.clone(),
                            status,
                            payload: payload.clone(),
                        }
                    } else {
                        Decision::forward()
                    },
                );
            }
        } else {
            Self::send(&mut state, id, decision);
        }
        drop(state);
        self.changed();
        Ok(())
    }
    fn send(state: &mut State, id: u64, decision: Decision) {
        if let Some(pending) = state.pending.remove(&id) {
            state.bytes -= pending.message.size();
            _ = pending.reply.send(decision);
        }
    }
    pub(super) async fn decide(
        &self,
        connection: &ControlConnection,
        mut message: Message,
    ) -> (Decision, Option<String>) {
        let Some(permit) = self.0.recording.try_capture() else {
            return (Decision::forward(), None);
        };
        let policy = self.0.policy.load_full();
        for rule in &policy.rules {
            if !rule.matches(&message) {
                continue;
            }
            let decision = match &rule.rule.action {
                Action::Respond { response } if message.is_http() => Some(Decision::Respond {
                    response: response.clone(),
                }),
                Action::Drop if !message.is_http() => Some(Decision::Drop),
                Action::Close { code, reason } if !message.is_http() => Some(Decision::Close {
                    code: *code,
                    reason: reason.clone(),
                }),
                _ => None,
            };
            if let Some(decision) = decision {
                return (decision, Some(rule.rule.name.clone()));
            }
        }
        if !policy.config.enabled || connection.0.automatic.load(Ordering::Acquire) {
            return (Decision::forward(), None);
        }
        if let Some(rule) = policy.rules.iter().find(|r| {
            matches!(r.rule.action, Action::Forward | Action::Intercept) && r.matches(&message)
        }) && matches!(rule.rule.action, Action::Forward)
        {
            return (Decision::forward(), Some(rule.rule.name.clone()));
        }
        let (reply, receive) = oneshot::channel();
        let id;
        {
            let mut state = self.0.state.lock();
            // Serialize admission with the connection-wide decision so a concurrent
            // response cannot arrive just after its connection was released.
            if connection.0.automatic.load(Ordering::Acquire)
                || !self.0.policy.load().config.enabled
            {
                return (Decision::forward(), None);
            }
            if state.pending.len() >= policy.config.queue_limit
                || message.size() > MAX_MESSAGE_BYTES
                || state.bytes + message.size() > MAX_QUEUE_BYTES
            {
                return (
                    if message.is_http() {
                        Decision::Respond {
                            response: ResponseSpec::error(503, "Rama interception queue is full."),
                        }
                    } else {
                        Decision::Close {
                            code: 1013,
                            reason: "Interception queue is full".into(),
                        }
                    },
                    Some("queue limit".into()),
                );
            }
            state.next_id += 1;
            id = state.next_id;
            message.id = id;
            message.connection = connection.0.id;
            message.queued_at = Some(jiff::Timestamp::now());
            state.bytes += message.size();
            state.pending.insert(
                id,
                Pending {
                    message: Arc::new(message.clone()),
                    connection: connection.clone(),
                    reply,
                },
            );
        }
        self.changed();
        // A hold must never keep pause waiting on a capture-write permit.
        drop(permit);
        let _guard = PendingGuard {
            control: self.clone(),
            id,
        };
        let decision =
            tokio::time::timeout(Duration::from_secs(policy.config.timeout_seconds), receive).await;
        let decision = match decision {
            Ok(Ok(Decision::Block)) => {
                if message.is_http() {
                    Decision::Respond {
                        response: policy.config.default_response.clone(),
                    }
                } else {
                    Decision::Drop
                }
            }
            Ok(Ok(decision)) => decision,
            _ => {
                if message.is_http() {
                    Decision::Respond {
                        response: ResponseSpec::error(504, "Rama interception approval expired."),
                    }
                } else {
                    Decision::Close {
                        code: 1008,
                        reason: "Interception approval expired".into(),
                    }
                }
            }
        };
        (decision, Some("manual interception".into()))
    }
}

struct PendingGuard {
    control: Control,
    id: u64,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        let mut state = self.control.0.state.lock();
        if let Some(p) = state.pending.remove(&self.id) {
            state.bytes -= p.message.size();
        }
        drop(state);
        self.control.changed();
    }
}

pub(super) fn http_message(parts: &rama::http::request::Parts) -> Message {
    let host = parts
        .uri
        .authority()
        .map(|a| a.host().to_str().into_owned())
        .or_else(|| {
            parts
                .headers
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.parse::<rama::net::address::Authority>().ok())
                .map(|a| a.view().host().to_str().into_owned())
        })
        .unwrap_or_default();
    let secure = parts
        .extensions
        .get_ref::<rama::tls::SecureTransport>()
        .is_some()
        || parts.uri.scheme().is_some_and(|s| s.as_str() == "https");
    Message {
        protocol: if secure { "https" } else { "http" }.into(),
        direction: "request".into(),
        method: parts.method.to_string(),
        url: parts.uri.to_string(),
        host,
        port: parts
            .uri
            .authority()
            .and_then(|a| a.port_u16())
            .or(Some(if secure { 443 } else { 80 })),
        path: parts
            .uri
            .path()
            .map(|p| p.as_encoded_str().into())
            .unwrap_or_else(|| "/".into()),
        headers: headers_to_vec(&parts.headers),
        conditional: matches!(parts.method, Method::GET | Method::HEAD)
            && (parts.headers.contains_key(header::IF_NONE_MATCH)
                || parts.headers.contains_key(header::IF_MODIFIED_SINCE)),
        http2: parts.version == Version::HTTP_2,
        ..Message::default()
    }
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(proxy))]
pub(super) struct WebSocketContext {
    pub connection: ControlConnection,
    pub request: Message,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct PendingSummary {
    pub id: u64,
    pub connection: u64,
    pub connection_display_id: Option<u64>,
    pub exchange: Option<u64>,
    pub protocol: String,
    pub direction: String,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub queued_at: Option<jiff::Timestamp>,
}
impl From<&Message> for PendingSummary {
    fn from(m: &Message) -> Self {
        Self {
            id: m.id,
            connection: m.connection,
            connection_display_id: m.connection_display_id,
            exchange: m.exchange,
            protocol: m.protocol.clone(),
            direction: m.direction.clone(),
            method: m.method.clone(),
            url: m.url.clone(),
            status: m.status,
            queued_at: m.queued_at,
        }
    }
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
