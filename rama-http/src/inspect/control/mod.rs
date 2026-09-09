//! Runtime traffic decisions. Protocol adapters own streams; this bounded queue owns only
//! editable messages and one-shot decisions. Capture admission never controls forwarding.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::Extension,
    futures::{Stream, StreamExt},
};
use rama_inspect::{
    InspectionState,
    intercept::{Interception, QueueLimits},
};
use rama_net::{
    Protocol,
    address::{Host, HostPattern},
    uri::Uri,
};
use rama_utils::thirdparty::wildcard::{Wildcard, WildcardBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{
    Body, HeaderMap, HeaderName, Method, Response, StatusCode, Version, header,
    layer::remove_header::hop_by_hop_header_names,
};

const MAX_RULES: usize = 256;
const MAX_HEADERS: usize = 256;
const MAX_MESSAGE_BYTES: usize = rama_utils::octets::kib(256);
const MAX_QUEUE_BYTES: usize = rama_utils::octets::mib(8);
const MAX_HOSTS: usize = 4096;

#[derive(Debug, Clone, Extension)]
#[extension(tags(proxy))]
pub struct ControlConnection(pub Arc<Connection>);

#[derive(Debug)]
pub struct Connection {
    pub id: u64,
    automatic: AtomicBool,
    observed: Mutex<BTreeMap<Host, bool>>,
}

impl ControlConnection {
    pub fn new(id: u64) -> Self {
        Self(Arc::new(Connection {
            id,
            automatic: AtomicBool::new(false),
            observed: Mutex::new(BTreeMap::new()),
        }))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Matcher {
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
pub enum Action {
    Intercept,
    Forward,
    Respond { response: ResponseSpec },
    Drop,
    Close { code: u16, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
// Serde does not support deny_unknown_fields on a struct flattening a tagged enum.
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    pub matcher: Matcher,
    #[serde(flatten)]
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
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
pub struct Preset {
    pub name: String,
    pub response: ResponseSpec,
}

mod response;
pub use response::ResponseSpec;

mod message;
pub use message::{Direction, HttpUpgradeContext, Message, PendingSummary, http_message};

mod payload;
pub use payload::Payload;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Forward {
        headers: Option<HeaderMap>,
        status: Option<StatusCode>,
        payload: Option<String>,
    },
    Connection {
        headers: Option<HeaderMap>,
        status: Option<StatusCode>,
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
    pub fn forward() -> Self {
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
                    let original = &message.headers;
                    let edited = validate_headers(headers)?;
                    // A head-only edit cannot reconfigure an already selected
                    // route, body codec or upgrade handshake. Preserve those
                    // fields alongside the shared hop-by-hop policy.
                    for name in hop_by_hop_header_names(original).chain([
                        header::HOST,
                        header::CONTENT_LENGTH,
                        header::CONTENT_ENCODING,
                        header::PROXY_AUTHORIZATION,
                        header::PROXY_AUTHENTICATE,
                        header::SEC_WEBSOCKET_VERSION,
                        header::SEC_WEBSOCKET_KEY,
                        header::SEC_WEBSOCKET_ACCEPT,
                        header::SEC_WEBSOCKET_EXTENSIONS,
                        header::SEC_WEBSOCKET_PROTOCOL,
                    ]) {
                        if original
                            .get_all(&name)
                            .iter()
                            .ne(edited.get_all(&name).iter())
                        {
                            return Err(BoxError::from_static_str(
                                "header is managed by the transport and cannot be changed here",
                            )
                            .context_field("header", name));
                        }
                    }
                }
                if let Some(status) = status
                    && (!message.is_http()
                        || !matches!(message.direction, Direction::Egress)
                        || !(200..=599).contains(&status.as_u16())
                        || matches!(status.as_u16(), 204 | 205 | 304)
                        || matches!(
                            message.status.map(|status| status.as_u16()),
                            Some(101 | 204 | 205 | 304)
                        )
                        || message.method == Method::CONNECT)
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
                if message.method == Method::CONNECT && response.status.is_success() {
                    return Err(BoxError::from_static_str(
                        "a local response cannot establish a CONNECT tunnel",
                    ));
                }
                if response.status == StatusCode::NOT_MODIFIED && !message.conditional {
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
    // Match the codes supported by the WebSocket adapter. Its current engine
    // does not support 1014; this is not a statement about IANA registration.
    if !matches!(code, 1000..=1003 | 1007..=1013 | 3000..=4999) || reason.len() > 123 {
        return Err(BoxError::from_static_str(
            "unsupported WebSocket close code or invalid reason",
        ));
    }
    Ok(())
}

fn validate_headers(headers: &HeaderMap) -> Result<&HeaderMap, BoxError> {
    if headers.len() > MAX_HEADERS
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > MAX_MESSAGE_BYTES
    {
        return Err(BoxError::from_static_str("too many or oversized headers"));
    }
    Ok(headers)
}

#[derive(Clone)]
struct CompiledRule {
    rule: Rule,
    host: Option<HostPattern>,
    path: Option<Wildcard<'static>>,
    headers: Vec<(HeaderName, Wildcard<'static>)>,
    protocol: Option<Protocol>,
    method: Option<Method>,
    direction: Option<Direction>,
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
            if value.len() > rama_utils::octets::kib(1) {
                return Err(BoxError::from_static_str("pattern is too long"));
            }
            WildcardBuilder::from_owned(value.as_bytes().to_vec())
                .without_one_metasymbol()
                .without_escape()
                .build()
                .context("compile rule pattern")
        };
        if m.headers.len() > 16
            || m.host.len() > rama_utils::octets::kib(1)
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
        let protocol = (!m.protocol.is_empty())
            .then(|| m.protocol.parse())
            .transpose()?;
        // Standard method misspellings must not silently become extension methods.
        // Genuine custom methods retain their case-sensitive wire spelling.
        if let Some(method) = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::CONNECT,
            Method::OPTIONS,
            Method::TRACE,
            Method::PATCH,
        ]
        .into_iter()
        .find(|method| {
            method.as_str().eq_ignore_ascii_case(&m.method) && method.as_str() != m.method
        }) {
            return Err(
                BoxError::from_static_str("use the canonical HTTP rule method spelling")
                    .context_field("expected", method),
            );
        }
        let method = (!m.method.is_empty())
            .then(|| m.method.parse())
            .transpose()?;
        let direction = (!m.direction.is_empty())
            .then(|| m.direction.parse())
            .transpose()?;
        Ok(Self {
            rule,
            host,
            path,
            headers,
            protocol,
            method,
            direction,
        })
    }

    fn matches(&self, message: &Message) -> bool {
        let m = &self.rule.matcher;
        self.rule.enabled
            && self
                .protocol
                .as_ref()
                .is_none_or(|protocol| protocol == &message.protocol)
            && self
                .direction
                .as_ref()
                .is_none_or(|direction| direction == &message.direction)
            && self
                .method
                .as_ref()
                .is_none_or(|method| method == message.method)
            && (m.kind.is_empty() || message.kind.as_ref().is_some_and(|kind| kind == &m.kind))
            && m.port.is_none_or(|p| Some(p) == message.port)
            && m.status
                .is_none_or(|s| message.status.is_some_and(|status| status.as_u16() == s))
            && self.host.as_ref().is_none_or(|p| {
                message
                    .host
                    .as_ref()
                    .is_some_and(|host| p.matches(host.view()))
            })
            && self
                .path
                .as_ref()
                .is_none_or(|p| p.is_match(message.path().as_encoded_str().as_bytes()))
            && self.headers.iter().all(|(name, pattern)| {
                message
                    .headers
                    .get_all(name)
                    .iter()
                    .any(|value| pattern.is_match(value.as_bytes()))
            })
    }
}

struct Pending {
    message: Arc<Message>,
    connection: ControlConnection,
}

#[derive(Default)]
struct State {
    bypass: BTreeMap<u64, Weak<Connection>>,
    hosts: BTreeMap<Host, HostSummary>,
}

struct Inner {
    policy: ArcSwap<Policy>,
    queue: Interception<Pending, Decision>,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    recording: InspectionState,
}

#[derive(Clone)]
pub struct Control(Arc<Inner>);

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub host: Host,
    pub eligible: bool,
    pub connections: u64,
    pub bypassed: u64,
    pub last_seen: jiff::Timestamp,
    pub source: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ConnectionSummary {
    pub connection: u64,
    pub connection_display_id: Option<u64>,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub revision: u64,
    pub config: Config,
    pub pending: Vec<PendingSummary>,
    pub hosts: Vec<HostSummary>,
    pub automatic_connections: Vec<ConnectionSummary>,
    pub recording: bool,
}

impl Control {
    pub fn new(recording: InspectionState) -> Self {
        let (changes, _) = watch::channel(0);
        Self(Arc::new(Inner {
            policy: ArcSwap::from_pointee(Policy {
                revision: 0,
                config: Config::default(),
                rules: vec![],
            }),
            queue: Interception::with_changes(changes.clone()),
            state: Mutex::new(State::default()),
            changes,
            recording,
        }))
    }

    pub fn is_active(&self) -> bool {
        let policy = self.0.policy.load();
        self.0.recording.is_enabled() && (policy.config.enabled || !policy.rules.is_empty())
    }

    /// Subscribe to initial and updated control content from a native UI or API.
    pub fn subscribe(&self) -> impl Stream<Item = Snapshot> + Send + 'static {
        let control = self.clone();
        rama_inspect::subscription::subscribe(
            self.subscribe_changes(),
            rama_core::service::service_fn(move |()| {
                let snapshot = control.snapshot();
                async move { Ok::<_, std::convert::Infallible>(snapshot) }
            }),
            (),
        )
        .map(|result| match result {
            Ok(value) => value,
            Err(never) => match never {},
        })
    }

    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    fn changed(&self) {
        self.0.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn pending_summaries(&self) -> Vec<PendingSummary> {
        self.0
            .queue
            .entries()
            .iter()
            .map(|(_, p)| PendingSummary::from(p.message.as_ref()))
            .collect()
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut state = self.0.state.lock();
        let policy = self.0.policy.load();
        state
            .bypass
            .retain(|_, connection| connection.strong_count() > 0);
        Snapshot {
            revision: policy.revision,
            config: policy.config.clone(),
            pending: self.pending_summaries(),
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

    pub fn configure(&self, revision: u64, config: Config) -> Result<(), BoxError> {
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

    pub fn observe(
        &self,
        connection: &ControlConnection,
        host: &Host,
        inspected: bool,
        source: &str,
        reason: &str,
    ) {
        let Some(_permit) = self.0.recording.try_capture() else {
            return;
        };
        let host = host.clone();
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
        item.eligible = inspected;
        item.last_seen = jiff::Timestamp::now();
        item.source = source.into();
        item.reason = reason.into();
        drop(state);
        self.changed();
    }

    pub fn stop_and_forward(&self) {
        let state = self.0.state.lock();
        let mut policy = self.0.policy.load().as_ref().clone();
        policy.config.enabled = false;
        policy.revision += 1;
        self.0.policy.store(Arc::new(policy));
        self.0.queue.release_where(|_| Some(Decision::forward()));
        drop(state);
        self.changed();
    }

    pub fn apply_rule(&self, index: usize, revision: u64) -> Result<(), BoxError> {
        let policy = self.0.policy.load_full();
        if policy.revision != revision {
            return Err(BoxError::from_static_str(
                "settings changed before applying the rule to pending traffic",
            ));
        }
        let rule = policy.rules.get(index).context("rule no longer exists")?;
        let decisions = {
            let _state = self.0.state.lock();
            self.0
                .queue
                .entries()
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

    pub fn clear_hosts(&self) {
        self.0.state.lock().hosts.clear();
        self.changed();
    }

    pub fn resume_connection(&self, id: u64) {
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

    pub fn pending(&self, id: u64) -> Option<Arc<Message>> {
        self.0.queue.get(id).map(|p| p.message.clone())
    }

    pub fn resolve(&self, id: u64, decision: Decision) -> Result<(), BoxError> {
        // This lock also serializes admission, policy updates, and connection release.
        let mut state = self.0.state.lock();
        let mut connection_release = None;
        let resolved = self
            .0
            .queue
            .resolve_with(id, |pending| -> Result<Decision, BoxError> {
                decision.validate(&pending.message)?;
                Ok(match decision {
                    Decision::Block if pending.message.is_http() => Decision::Respond {
                        response: self.0.policy.load().config.default_response.clone(),
                    },
                    Decision::Connection {
                        headers,
                        status,
                        payload,
                    } => {
                        let connection = pending.connection.clone();
                        connection.0.automatic.store(true, Ordering::Release);
                        state
                            .bypass
                            .insert(connection.0.id, Arc::downgrade(&connection.0));
                        connection_release = Some(connection);
                        Decision::Forward {
                            headers,
                            status,
                            payload,
                        }
                    }
                    decision => decision,
                })
            })?;
        if !resolved {
            return Err(BoxError::from_static_str(
                "message is no longer awaiting approval",
            ));
        }
        if let Some(connection) = connection_release {
            self.0.queue.release_where(|pending| {
                Arc::ptr_eq(&pending.connection.0, &connection.0).then(Decision::forward)
            });
        }
        drop(state);
        self.changed();
        Ok(())
    }

    pub async fn decide(
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
        let is_http = message.is_http();
        let ticket = {
            let _state = self.0.state.lock();
            // Serialize admission with the connection-wide decision so a concurrent
            // response cannot arrive just after its connection was released.
            if connection.0.automatic.load(Ordering::Acquire)
                || !self.0.policy.load().config.enabled
            {
                return (Decision::forward(), None);
            }
            let size = message.size();
            let queued = self.0.queue.enqueue_with(
                size,
                QueueLimits {
                    messages: policy.config.queue_limit,
                    message_bytes: MAX_MESSAGE_BYTES,
                    bytes: MAX_QUEUE_BYTES,
                },
                |id| {
                    message.id = id;
                    message.connection = connection.0.id;
                    message.queued_at = Some(jiff::Timestamp::now());
                    Pending {
                        message: Arc::new(message),
                        connection: connection.clone(),
                    }
                },
            );
            if let Ok(ticket) = queued {
                ticket
            } else {
                let oversized = size > MAX_MESSAGE_BYTES;
                return (
                    if is_http {
                        Decision::Respond {
                            response: ResponseSpec::error(
                                if oversized {
                                    StatusCode::PAYLOAD_TOO_LARGE
                                } else {
                                    StatusCode::SERVICE_UNAVAILABLE
                                },
                                if oversized {
                                    "Message exceeds the interception editor limit."
                                } else {
                                    "Rama interception queue is full."
                                },
                            ),
                        }
                    } else {
                        Decision::Close {
                            code: if oversized { 1009 } else { 1013 },
                            reason: if oversized {
                                "Message exceeds the interception editor limit"
                            } else {
                                "Interception queue is full"
                            }
                            .into(),
                        }
                    },
                    Some(
                        if oversized {
                            "message limit"
                        } else {
                            "queue limit"
                        }
                        .into(),
                    ),
                );
            }
        };
        // A hold must never keep pause waiting on a capture-write permit.
        drop(permit);
        let decision = ticket
            .wait(Duration::from_secs(policy.config.timeout_seconds))
            .await;
        let decision = match decision {
            Ok(Decision::Block) => {
                if is_http {
                    Decision::Respond {
                        response: policy.config.default_response.clone(),
                    }
                } else {
                    Decision::Drop
                }
            }
            Ok(decision) => decision,
            _ => {
                if is_http {
                    Decision::Respond {
                        response: ResponseSpec::error(
                            StatusCode::GATEWAY_TIMEOUT,
                            "Rama interception approval expired.",
                        ),
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

#[cfg(test)]
mod tests;
