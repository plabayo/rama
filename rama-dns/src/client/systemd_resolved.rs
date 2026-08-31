//! systemd-resolved varlink backend for the Linux DNS resolver.
//!
//! Speaks the native `io.systemd.Resolve` API (JSON frames terminated by a
//! NUL byte, one call per connection) over the daemon's unix socket — the
//! same transport glibc's `nss-resolve` module uses. Unlike the libc paths
//! this is fully async: no blocking-pool worker is held and timeouts cancel
//! the query.
//!
//! Address lookups use `ResolveHostname` for `getaddrinfo` parity (search
//! domains, `/etc/hosts`, synthesized names, CNAME chasing). TXT, SVCB, and
//! HTTPS lookups use `ResolveRecord` (raw wire-format RRs, real TTLs), which
//! older daemons do not implement — a `MethodNotFound` reply pins record
//! lookups to the native backend
//! without affecting address lookups. `ResolveRecord` applies no
//! search-domain expansion, so single-label record names route to the native
//! backend directly and only rooted names treat a negative answer as
//! authoritative: a relative name that comes back negative is retried
//! natively so the resolv.conf search list still applies. Remaining
//! divergence from `res_nsearch`: a positive as-is answer wins even where
//! `ndots` would have preferred a search-list candidate.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _, ErrorExt as _},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_unix::client::default_unix_connect;
use rama_utils::{octets::kib, str::arcstr::ArcStr};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Semaphore,
    time::Instant,
};

pub(super) const DEFAULT_SOCKET_PATH: &str = "/run/systemd/resolve/io.systemd.Resolve";

const METHOD_RESOLVE_HOSTNAME: &str = "io.systemd.Resolve.ResolveHostname";
const METHOD_RESOLVE_RECORD: &str = "io.systemd.Resolve.ResolveRecord";
const ERROR_NO_SUCH_RR: &str = "io.systemd.Resolve.NoSuchResourceRecord";
const ERROR_METHOD_NOT_FOUND: &str = "org.varlink.service.MethodNotFound";
/// Errors in this namespace are varlink protocol failures, not resolution answers.
const VARLINK_ERROR_PREFIX: &str = "org.varlink.";

// The daemon is always Linux; these are its wire values regardless of the
// compilation host (this module also builds on other unixes for tests).
const AF_INET: i64 = 2;
const AF_INET6: i64 = 10;

use super::systemd_resolved_wire::{DNS_CLASS_IN, RrParse, parse_service_binding_rr, parse_txt_rr};
use crate::wire::{RecordType, ServiceBinding, Txt};

/// A probe claim older than this is assumed orphaned and may be re-claimed.
const PROBE_STALE: Duration = Duration::from_secs(15);
/// Replies are per-query record sets; anything bigger is a broken peer.
const MAX_REPLY_SIZE: usize = kib(256);

#[derive(Debug, Clone)]
pub(super) struct Config {
    pub(super) socket_path: PathBuf,
    pub(super) connect_timeout: Duration,
    pub(super) reprobe_interval: Duration,
    pub(super) breaker_threshold: u32,
    pub(super) max_concurrency: usize,
    pub(super) hostname_ttl: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.into(),
            // a healthy local daemon accepts near-instantly; anything slower
            // is backlogged and should feed the breaker quickly
            connect_timeout: Duration::from_secs(1),
            reprobe_interval: Duration::from_secs(30),
            breaker_threshold: 4,
            // stays below resolved's varlink server default of 128 connections
            // per UID, a budget shared with other same-UID clients (nss-resolve)
            max_concurrency: 112,
            // ResolveHostname replies carry no TTLs; keep our cache entries
            // short so the daemon's own TTL-accurate cache stays authoritative
            hostname_ttl: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Untested,
    Probing { since: Instant, generation: u64 },
    Available,
    Unavailable { since: Instant },
}

#[derive(Debug)]
struct Availability {
    phase: Phase,
    /// consecutive soft transport failures while available
    failures: u32,
    /// Monotonic identity for probe ownership. Reports from a probe that was
    /// reclaimed after [`PROBE_STALE`] must not overwrite its successor.
    next_probe_generation: u64,
}

/// Availability tracking: the first lookup doubles as the probe
/// (single-flight), transport failures feed a consecutive-failure breaker,
/// and an unavailable daemon is re-probed at most once per
/// [`Config::reprobe_interval`]. Lookups never wait on a probe: whoever does
/// not hold the claim reports [`ResolvedLookup::Unavailable`] so the caller
/// uses the native backend instead. Transitions go through one mutex (its
/// critical sections are a few loads/stores) so a success and a concurrent
/// failure can never interleave into a wrong breaker verdict.
#[derive(Debug)]
pub(super) struct SystemdResolved {
    config: Config,
    state: Mutex<Availability>,
    record_supported: AtomicBool,
    permits: Semaphore,
}

pub(super) enum ResolvedLookup<T> {
    /// Records with their DNS or configured cache TTL in seconds.
    ///
    /// `None` is reserved for ResolveHostname, whose reply has no wire TTL,
    /// when its configured synthetic TTL is zero. Raw records always carry
    /// `Some(ttl)`, including a wire TTL of zero.
    Records(Vec<(T, Option<u32>)>),
    /// Authoritative "no such record" answer.
    Negative,
    /// Resolution failed upstream: surface it; falling back would usually
    /// re-ask the same daemon through its slower 127.0.0.53 stub.
    Failed(BoxError),
    /// resolved is not usable for this lookup; use the native backend.
    Unavailable,
}

enum ParsedRecord<T> {
    One { ttl: u32, value: T },
    Other,
    Malformed,
}

#[derive(Clone, Copy)]
struct Claim {
    probe_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    /// Unambiguous daemon absence (missing socket, refused): flip immediately.
    Hard,
    /// Daemon misbehavior or timeout mid-exchange: feeds the breaker.
    Soft,
    /// Local saturation (no permit within the deadline): the daemon never saw
    /// the query, so it must neither feed the breaker nor hold a probe slot.
    Overload,
}

struct TransportFailure {
    kind: FailureKind,
    error: BoxError,
}

impl TransportFailure {
    fn soft(error: impl Into<BoxError>) -> Self {
        Self {
            kind: FailureKind::Soft,
            error: error.into(),
        }
    }

    fn hard(error: impl Into<BoxError>) -> Self {
        Self {
            kind: FailureKind::Hard,
            error: error.into(),
        }
    }

    fn overload(error: impl Into<BoxError>) -> Self {
        Self {
            kind: FailureKind::Overload,
            error: error.into(),
        }
    }
}

impl SystemdResolved {
    pub(super) fn new(config: Config) -> Self {
        let permits = Semaphore::new(config.max_concurrency.max(1));
        Self {
            config,
            state: Mutex::new(Availability {
                phase: Phase::Untested,
                failures: 0,
                next_probe_generation: 0,
            }),
            record_supported: AtomicBool::new(true),
            permits,
        }
    }

    pub(super) async fn lookup_ipv4(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
    ) -> ResolvedLookup<Ipv4Addr> {
        self.lookup_hostname(domain, AF_INET, timeout, |raw| {
            <[u8; 4]>::try_from(raw).ok().map(Ipv4Addr::from)
        })
        .await
    }

    pub(super) async fn lookup_ipv6(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
    ) -> ResolvedLookup<Ipv6Addr> {
        self.lookup_hostname(domain, AF_INET6, timeout, |raw| {
            <[u8; 16]>::try_from(raw).ok().map(Ipv6Addr::from)
        })
        .await
    }

    pub(super) async fn lookup_txt(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
    ) -> ResolvedLookup<Txt> {
        self.lookup_record(domain, timeout, RecordType::TXT, |raw| {
            match parse_txt_rr(&raw) {
                RrParse::Record { ttl, value } => ParsedRecord::One { ttl, value },
                RrParse::Other => ParsedRecord::Other,
                RrParse::Malformed => ParsedRecord::Malformed,
            }
        })
        .await
    }

    pub(super) async fn lookup_svcb(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
    ) -> ResolvedLookup<ServiceBinding> {
        self.lookup_service_binding(domain, timeout, RecordType::SVCB)
            .await
    }

    pub(super) async fn lookup_https(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
    ) -> ResolvedLookup<ServiceBinding> {
        self.lookup_service_binding(domain, timeout, RecordType::HTTPS)
            .await
    }

    async fn lookup_service_binding(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
        record_type: RecordType,
    ) -> ResolvedLookup<ServiceBinding> {
        self.lookup_record(
            domain,
            timeout,
            record_type,
            move |raw| match parse_service_binding_rr(&raw, record_type) {
                RrParse::Record { ttl, value } => ParsedRecord::One { ttl, value },
                RrParse::Other => ParsedRecord::Other,
                RrParse::Malformed => ParsedRecord::Malformed,
            },
        )
        .await
    }

    async fn lookup_record<T, P>(
        self: &Arc<Self>,
        domain: &Domain,
        timeout: Duration,
        record_type: RecordType,
        parser: P,
    ) -> ResolvedLookup<T>
    where
        T: Send + 'static,
        P: Fn(Bytes) -> ParsedRecord<T> + Send + Sync + 'static,
    {
        let name = wire_name(domain);
        // fast path: single-label names always need the search list, which
        // ResolveRecord never applies — skip the guaranteed-useless roundtrip
        if !name.contains('.') {
            return ResolvedLookup::Unavailable;
        }
        // only a rooted name may treat a negative answer as authoritative;
        // relative ones are retried natively so the search list applies
        let rooted = domain.is_fqdn();
        let Some(claim) = self.claim() else {
            return ResolvedLookup::Unavailable;
        };
        // read after claim(): its recovery-reprobe arm resets this pin
        if !self.record_supported.load(Ordering::Acquire) {
            // the daemon never saw a query: hand back any probe slot
            self.report_transport_failure(claim, FailureKind::Overload);
            return ResolvedLookup::Unavailable;
        }
        let this = self.clone();
        join(tokio::spawn(async move {
            this.record_query(claim, name, rooted, timeout, record_type, parser)
                .await
        }))
        .await
    }

    async fn lookup_hostname<T: Send + 'static>(
        self: &Arc<Self>,
        domain: &Domain,
        family: i64,
        timeout: Duration,
        decode: fn(&[u8]) -> Option<T>,
    ) -> ResolvedLookup<T> {
        let Some(claim) = self.claim() else {
            return ResolvedLookup::Unavailable;
        };
        let this = self.clone();
        let name = wire_name(domain);
        join(tokio::spawn(async move {
            this.hostname_query(claim, name, family, timeout, decode)
                .await
        }))
        .await
    }

    async fn hostname_query<T>(
        self: Arc<Self>,
        claim: Claim,
        name: String,
        family: i64,
        timeout: Duration,
        decode: fn(&[u8]) -> Option<T>,
    ) -> ResolvedLookup<T> {
        let envelope = match self
            .call(
                METHOD_RESOLVE_HOSTNAME,
                &HostnameParams {
                    name: &name,
                    family,
                },
                timeout,
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(failure) => return self.transport_failed(claim, failure),
        };
        if let Some(error) = envelope.error.as_deref() {
            return self.classify_reply_error(claim, error, false);
        }
        let reply = match serde_json::from_value::<HostnameReply>(envelope.parameters) {
            Ok(reply) => reply,
            Err(err) => {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft(err.context("invalid ResolveHostname reply")),
                );
            }
        };
        let ttl = hostname_cache_ttl_secs(self.config.hostname_ttl);
        let mut records = Vec::with_capacity(reply.addresses.len());
        for entry in reply.addresses {
            if entry.family != family {
                continue;
            }
            let Some(value) = decode(&entry.address) else {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft("invalid address payload in ResolveHostname reply"),
                );
            };
            records.push((value, ttl));
        }
        if records.is_empty() {
            // a correct daemon answers NoSuchResourceRecord instead
            return self.transport_failed(
                claim,
                TransportFailure::soft("empty ResolveHostname success reply"),
            );
        }
        self.report_success(claim);
        ResolvedLookup::Records(records)
    }

    async fn record_query<T, P>(
        self: Arc<Self>,
        claim: Claim,
        name: String,
        rooted: bool,
        timeout: Duration,
        record_type: RecordType,
        parser: P,
    ) -> ResolvedLookup<T>
    where
        P: Fn(Bytes) -> ParsedRecord<T>,
    {
        let envelope = match self
            .call(
                METHOD_RESOLVE_RECORD,
                &RecordParams {
                    name: &name,
                    r#type: record_type.into(),
                    class: DNS_CLASS_IN,
                },
                timeout,
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(failure) => return self.transport_failed(claim, failure),
        };
        if let Some(error) = envelope.error.as_deref() {
            if !rooted && error == ERROR_NO_SUCH_RR {
                // not authoritative for a relative name: the native backend
                // may still resolve it through the resolv.conf search list
                self.report_success(claim);
                return ResolvedLookup::Unavailable;
            }
            return self.classify_reply_error(claim, error, true);
        }
        let reply = match serde_json::from_value::<RecordReply>(envelope.parameters) {
            Ok(reply) => reply,
            Err(err) => {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft(err.context("invalid ResolveRecord reply")),
                );
            }
        };
        if reply.rrs.is_empty() {
            // a correct daemon answers NoSuchResourceRecord instead
            return self.transport_failed(
                claim,
                TransportFailure::soft("empty ResolveRecord success reply"),
            );
        }
        let mut records = Vec::new();
        for entry in &reply.rrs {
            let Ok(raw) = BASE64.decode(&entry.raw) else {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft("invalid base64 rr in ResolveRecord reply"),
                );
            };
            match parser(Bytes::from(raw)) {
                ParsedRecord::One { ttl, value } => records.push((value, Some(ttl))),
                // e.g. CNAME chain entries included alongside the target RRset
                ParsedRecord::Other => {}
                ParsedRecord::Malformed => {
                    return self.transport_failed(
                        claim,
                        TransportFailure::soft("malformed rr in ResolveRecord reply"),
                    );
                }
            }
        }
        if records.is_empty() {
            // A successful ResolveRecord reply should contain the requested
            // RRset. If it only contains ancillary records (for example a
            // CNAME chain), let the native backend decide instead of turning
            // an incomplete daemon reply into an authoritative negative.
            self.report_success(claim);
            ResolvedLookup::Unavailable
        } else {
            self.report_success(claim);
            ResolvedLookup::Records(records)
        }
    }

    fn classify_reply_error<T>(
        &self,
        claim: Claim,
        error: &str,
        record_query: bool,
    ) -> ResolvedLookup<T> {
        if error == ERROR_NO_SUCH_RR {
            self.report_success(claim);
            return ResolvedLookup::Negative;
        }
        if record_query && error == ERROR_METHOD_NOT_FOUND {
            // daemon reachable but too old for ResolveRecord: pin raw record
            // lookups to the native backend; address lookups keep flowing
            if self.report_success(claim) {
                self.record_supported.store(false, Ordering::Release);
                tracing::debug!(
                    "dns::systemd-resolved: ResolveRecord not implemented; record lookups use the native backend"
                );
            }
            return ResolvedLookup::Unavailable;
        }
        if error.starts_with(VARLINK_ERROR_PREFIX) {
            return self.transport_failed(
                claim,
                TransportFailure::soft(
                    BoxError::from_static_str("varlink protocol error")
                        .context_str_field("error", error),
                ),
            );
        }
        self.report_success(claim);
        ResolvedLookup::Failed(
            SystemdResolvedError::message(format!("systemd-resolved lookup failed: {error}"))
                .into(),
        )
    }

    fn transport_failed<T>(&self, claim: Claim, failure: TransportFailure) -> ResolvedLookup<T> {
        let TransportFailure { kind, error } = failure;
        tracing::debug!(
            err = %error,
            ?kind,
            "dns::systemd-resolved: transport failure",
        );
        self.report_transport_failure(claim, kind);
        ResolvedLookup::Unavailable
    }

    fn claim(&self) -> Option<Claim> {
        let mut state = self.state.lock();
        match state.phase {
            Phase::Available => Some(Claim {
                probe_generation: None,
            }),
            Phase::Untested => Some(begin_probe(&mut state)),
            // a probe claim older than the stale bound is assumed orphaned
            // (its task died without reporting) and may be re-claimed
            Phase::Probing { since, .. } => {
                (since.elapsed() > PROBE_STALE).then(|| begin_probe(&mut state))
            }
            Phase::Unavailable { since } => {
                (since.elapsed() >= self.config.reprobe_interval).then(|| {
                    // A daemon replacement may implement methods that the
                    // previous instance did not. Re-test raw-record support
                    // whenever transport recovery starts a new probe generation.
                    self.record_supported.store(true, Ordering::Release);
                    begin_probe(&mut state)
                })
            }
        }
    }

    /// Report a successful exchange, returning whether this claim still owns
    /// the state transition. Callers must guard claim-specific side effects
    /// (such as capability pins) with the result.
    fn report_success(&self, claim: Claim) -> bool {
        let became_available = {
            let mut state = self.state.lock();
            if !claim_is_current(&state, claim) {
                return false;
            }
            state.failures = 0;
            !matches!(
                std::mem::replace(&mut state.phase, Phase::Available),
                Phase::Available,
            )
        };
        if became_available {
            tracing::debug!("dns::systemd-resolved: available");
        }
        true
    }

    fn report_transport_failure(&self, claim: Claim, kind: FailureKind) {
        let flipped = {
            let mut state = self.state.lock();
            if !claim_is_current(&state, claim) {
                return;
            }
            match kind {
                FailureKind::Overload => {
                    if claim.probe_generation.is_some() {
                        state.phase = Phase::Untested;
                    }
                    false
                }
                FailureKind::Hard => mark_unavailable(&mut state),
                FailureKind::Soft => {
                    if claim.probe_generation.is_some() {
                        mark_unavailable(&mut state)
                    } else {
                        state.failures += 1;
                        if state.failures >= self.config.breaker_threshold {
                            mark_unavailable(&mut state)
                        } else {
                            false
                        }
                    }
                }
            }
        };
        if flipped {
            tracing::debug!(
                reprobe_interval = ?self.config.reprobe_interval,
                "dns::systemd-resolved: unavailable; lookups use the native backend",
            );
        }
    }

    async fn call<P: Serialize>(
        &self,
        method: &'static str,
        parameters: &P,
        timeout: Duration,
    ) -> Result<Envelope, TransportFailure> {
        let started = Instant::now();
        let permit = match tokio::time::timeout(timeout, self.permits.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(err)) => {
                return Err(TransportFailure::soft(
                    err.context("varlink semaphore closed"),
                ));
            }
            Err(_) => {
                return Err(TransportFailure::overload(no_slot_error(timeout)));
            }
        };
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(TransportFailure::overload(no_slot_error(timeout)));
        }
        let result =
            match tokio::time::timeout(remaining, self.call_inner(method, parameters)).await {
                Ok(result) => result,
                Err(_) => Err(TransportFailure::soft(
                    BoxError::from_static_str("varlink call timed out")
                        .context_field("method", method)
                        .context_debug_field("timeout", timeout),
                )),
            };
        drop(permit);
        result
    }

    async fn call_inner<P: Serialize>(
        &self,
        method: &'static str,
        parameters: &P,
    ) -> Result<Envelope, TransportFailure> {
        let (mut stream, _info) = match tokio::time::timeout(
            self.config.connect_timeout,
            default_unix_connect(self.config.socket_path.clone()),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            // immediate connect errors (missing socket, refused) are unambiguous
            Ok(Err(err)) => return Err(TransportFailure::hard(err)),
            Err(_) => {
                return Err(TransportFailure::soft(
                    BoxError::from_static_str("varlink connect timed out")
                        .context_debug_field("timeout", self.config.connect_timeout),
                ));
            }
        };

        let mut frame = serde_json::to_vec(&Call { method, parameters })
            .map_err(|err| TransportFailure::soft(err.context("encode varlink call")))?;
        frame.push(0);
        stream
            .write_all(&frame)
            .await
            .map_err(|err| TransportFailure::soft(err.context("write varlink call")))?;

        let mut buf = Vec::with_capacity(1024);
        let mut scanned = 0;
        loop {
            let n = stream
                .read_buf(&mut buf)
                .await
                .map_err(|err| TransportFailure::soft(err.context("read varlink reply")))?;
            if n == 0 {
                return Err(TransportFailure::soft(
                    "connection closed before varlink reply",
                ));
            }
            if let Some(pos) = buf[scanned..].iter().position(|byte| *byte == 0) {
                let frame = &buf[..scanned + pos];
                if frame.len() > MAX_REPLY_SIZE {
                    return Err(TransportFailure::soft("varlink reply exceeds size bound"));
                }
                return serde_json::from_slice(frame)
                    .map_err(|err| TransportFailure::soft(err.context("decode varlink reply")));
            }
            scanned = buf.len();
            if buf.len() > MAX_REPLY_SIZE {
                return Err(TransportFailure::soft("varlink reply exceeds size bound"));
            }
        }
    }
}

fn begin_probe(state: &mut Availability) -> Claim {
    let generation = state.next_probe_generation;
    state.next_probe_generation = state.next_probe_generation.wrapping_add(1);
    state.phase = Phase::Probing {
        since: Instant::now(),
        generation,
    };
    Claim {
        probe_generation: Some(generation),
    }
}

fn claim_is_current(state: &Availability, claim: Claim) -> bool {
    match claim.probe_generation {
        None => true,
        Some(claim_generation) => matches!(
            state.phase,
            Phase::Probing { generation, .. } if generation == claim_generation
        ),
    }
}

/// Detached task so a dropped consumer (e.g. `race_connect`) can never orphan
/// a probe claim or lose breaker accounting.
async fn join<T>(task: tokio::task::JoinHandle<ResolvedLookup<T>>) -> ResolvedLookup<T> {
    match task.await {
        Ok(outcome) => outcome,
        Err(err) => {
            tracing::debug!(%err, "dns::systemd-resolved: lookup task failed to join");
            ResolvedLookup::Unavailable
        }
    }
}

fn mark_unavailable(state: &mut Availability) -> bool {
    state.failures = 0;
    !matches!(
        std::mem::replace(
            &mut state.phase,
            Phase::Unavailable {
                since: Instant::now(),
            },
        ),
        Phase::Unavailable { .. },
    )
}

fn wire_name(domain: &Domain) -> String {
    domain.as_str().trim_end_matches('.').to_owned()
}

fn no_slot_error(timeout: Duration) -> BoxError {
    BoxError::from_static_str("no varlink slot within the lookup deadline")
        .context_debug_field("timeout", timeout)
}

/// Positive sub-second TTLs round up to one second instead of expiring immediately.
fn hostname_cache_ttl_secs(ttl: Duration) -> Option<u32> {
    if ttl.is_zero() {
        None
    } else {
        Some(u32::try_from(ttl.as_secs().max(1)).unwrap_or(u32::MAX))
    }
}

#[derive(Serialize)]
struct Call<'a, P> {
    method: &'static str,
    parameters: &'a P,
}

#[derive(Serialize)]
struct HostnameParams<'a> {
    name: &'a str,
    family: i64,
}

#[derive(Serialize)]
struct RecordParams<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    r#type: u16,
    class: u16,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct HostnameReply {
    addresses: Vec<AddressEntry>,
}

#[derive(Deserialize)]
struct AddressEntry {
    family: i64,
    address: Vec<u8>,
}

#[derive(Deserialize)]
struct RecordReply {
    rrs: Vec<RecordEntry>,
}

#[derive(Deserialize)]
struct RecordEntry {
    raw: String,
}

#[derive(Debug)]
struct SystemdResolvedError(ArcStr);

impl SystemdResolvedError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SystemdResolvedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SystemdResolvedError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::UnixListener;

    static SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_socket_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "rama-dns-rvl-{}-{}.sock",
            std::process::id(),
            SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[derive(Clone)]
    enum Behavior {
        Reply(serde_json::Value),
        RawReply(Vec<u8>),
        ChunkedReply(serde_json::Value),
        DelayedReply(Duration, serde_json::Value),
        CloseImmediately,
        Hang,
    }

    struct FakeResolved {
        path: PathBuf,
        connections: Arc<AtomicUsize>,
        concurrent_peak: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl FakeResolved {
        fn spawn(behaviors: Vec<Behavior>) -> Self {
            Self::spawn_at(test_socket_path(), behaviors)
        }

        fn spawn_at(path: PathBuf, behaviors: Vec<Behavior>) -> Self {
            _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind fake resolved socket");
            let connections = Arc::new(AtomicUsize::new(0));
            let concurrent_peak = Arc::new(AtomicUsize::new(0));
            let conn_count = connections.clone();
            let peak = concurrent_peak.clone();
            let handle = tokio::spawn(async move {
                let live = Arc::new(AtomicUsize::new(0));
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let index = conn_count.fetch_add(1, Ordering::SeqCst);
                    let behavior = behaviors
                        .get(index)
                        .or_else(|| behaviors.last())
                        .cloned()
                        .expect("at least one behavior");
                    let live = live.clone();
                    let peak = peak.clone();
                    tokio::spawn(async move {
                        let current = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(current, Ordering::SeqCst);
                        serve_connection(stream, behavior).await;
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
            Self {
                path,
                connections,
                concurrent_peak,
                handle,
            }
        }

        fn connections(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }
    }

    impl Drop for FakeResolved {
        fn drop(&mut self) {
            self.handle.abort();
            _ = std::fs::remove_file(&self.path);
        }
    }

    async fn serve_connection(mut stream: tokio::net::UnixStream, behavior: Behavior) {
        let mut buf = Vec::new();
        loop {
            let Ok(n) = stream.read_buf(&mut buf).await else {
                return;
            };
            if n == 0 || buf.contains(&0) {
                break;
            }
        }
        match behavior {
            Behavior::CloseImmediately => {}
            Behavior::Hang => tokio::time::sleep(Duration::from_secs(60)).await,
            Behavior::RawReply(raw) => {
                _ = stream.write_all(&raw).await;
            }
            Behavior::ChunkedReply(reply) => {
                let mut frame = serde_json::to_vec(&reply).expect("serialize reply");
                frame.push(0);
                let split = frame.len() / 2;
                _ = stream.write_all(&frame[..split]).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                _ = stream.write_all(&frame[split..]).await;
            }
            Behavior::DelayedReply(delay, reply) => {
                tokio::time::sleep(delay).await;
                write_reply(&mut stream, &reply).await;
            }
            Behavior::Reply(reply) => write_reply(&mut stream, &reply).await,
        }
    }

    async fn write_reply(stream: &mut tokio::net::UnixStream, reply: &serde_json::Value) {
        let mut frame = serde_json::to_vec(reply).expect("serialize reply");
        frame.push(0);
        _ = stream.write_all(&frame).await;
    }

    fn test_config(path: PathBuf) -> Config {
        Config {
            socket_path: path,
            connect_timeout: Duration::from_millis(250),
            reprobe_interval: Duration::from_secs(60),
            breaker_threshold: 2,
            max_concurrency: 8,
            hostname_ttl: Duration::from_secs(15),
        }
    }

    fn resolver(path: PathBuf) -> Arc<SystemdResolved> {
        Arc::new(SystemdResolved::new(test_config(path)))
    }

    fn domain() -> Domain {
        "example.com".try_into().expect("valid domain")
    }

    fn phase(resolved: &SystemdResolved) -> Phase {
        resolved.state.lock().phase
    }

    fn assert_available(resolved: &SystemdResolved) {
        assert!(matches!(phase(resolved), Phase::Available));
    }

    fn assert_unavailable(resolved: &SystemdResolved) {
        assert!(matches!(phase(resolved), Phase::Unavailable { .. }));
    }

    fn hostname_reply(addresses: &serde_json::Value) -> serde_json::Value {
        json!({ "parameters": { "addresses": addresses, "name": "example.com", "flags": 1 } })
    }

    fn error_reply(id: &str) -> serde_json::Value {
        json!({ "error": id, "parameters": {} })
    }

    fn build_rr(labels: &[&str], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        for label in labels {
            raw.push(u8::try_from(label.len()).expect("short label"));
            raw.extend_from_slice(label.as_bytes());
        }
        raw.push(0);
        raw.extend_from_slice(&rtype.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        raw.extend_from_slice(&ttl.to_be_bytes());
        raw.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("short rdata")
                .to_be_bytes(),
        );
        raw.extend_from_slice(rdata);
        raw
    }

    fn txt_rdata(segments: &[&[u8]]) -> Vec<u8> {
        let mut rdata = Vec::new();
        for segment in segments {
            rdata.push(u8::try_from(segment.len()).expect("short segment"));
            rdata.extend_from_slice(segment);
        }
        rdata
    }

    fn service_binding_rdata(port: u16) -> Vec<u8> {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        rdata
    }

    #[tokio::test]
    async fn resolve_hostname_returns_matching_family_records() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(hostname_reply(&json!([
            { "ifindex": 2, "family": 2, "address": [93, 184, 216, 34] },
            { "family": 10, "address": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] },
            { "family": 2, "address": [10, 0, 0, 1] },
        ])))]);
        let resolved = resolver(server.path.clone());
        match resolved
            .lookup_ipv4(&domain(), Duration::from_secs(2))
            .await
        {
            ResolvedLookup::Records(records) => assert_eq!(
                records,
                vec![
                    (Ipv4Addr::new(93, 184, 216, 34), Some(15)),
                    (Ipv4Addr::new(10, 0, 0, 1), Some(15)),
                ],
            ),
            _ => panic!("expected records"),
        }
        assert_eq!(server.connections(), 1);
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn resolve_hostname_ipv6() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(hostname_reply(&json!([
            { "family": 10, "address": [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] },
        ])))]);
        let resolved = resolver(server.path.clone());
        match resolved
            .lookup_ipv6(&domain(), Duration::from_secs(2))
            .await
        {
            ResolvedLookup::Records(records) => assert_eq!(
                records,
                vec![(
                    "2001:db8::1".parse::<Ipv6Addr>().expect("valid ipv6"),
                    Some(15)
                )],
            ),
            _ => panic!("expected records"),
        }
    }

    #[tokio::test]
    async fn no_such_record_is_negative_and_keeps_backend_available() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(error_reply(ERROR_NO_SUCH_RR))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Negative,
        ));
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Negative,
        ));
        assert_eq!(
            server.connections(),
            2,
            "negatives must keep routing via varlink"
        );
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn resolution_errors_surface_without_fallback() {
        let server = FakeResolved::spawn(vec![
            Behavior::Reply(hostname_reply(
                &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
            )),
            Behavior::Reply(error_reply("io.systemd.Resolve.QueryTimedOut")),
        ]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Records(_),
        ));
        match resolved
            .lookup_ipv4(&domain(), Duration::from_secs(2))
            .await
        {
            ResolvedLookup::Failed(err) => {
                assert!(err.to_string().contains("QueryTimedOut"), "got: {err}")
            }
            _ => panic!("expected failed lookup"),
        }
        assert_available(&resolved);
        assert_eq!(resolved.state.lock().failures, 0);
    }

    #[tokio::test]
    async fn missing_socket_flips_unavailable_and_skips_daemon() {
        let path = test_socket_path();
        let resolved = resolver(path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);

        // a daemon appearing now is not contacted before the re-probe interval
        let server =
            FakeResolved::spawn_at(path, vec![Behavior::Reply(hostname_reply(&json!([])))]);
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(server.connections(), 0);
    }

    #[tokio::test]
    async fn reprobe_recovers_after_interval() {
        let path = test_socket_path();
        let mut config = test_config(path.clone());
        config.reprobe_interval = Duration::from_millis(50);
        let resolved = Arc::new(SystemdResolved::new(config));

        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));

        let server = FakeResolved::spawn_at(
            path,
            vec![Behavior::Reply(hostname_reply(
                &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
            ))],
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Records(_),
        ));
        assert_eq!(server.connections(), 1);
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn probe_is_single_flight() {
        let server = FakeResolved::spawn(vec![Behavior::DelayedReply(
            Duration::from_millis(300),
            hostname_reply(&json!([{ "family": 2, "address": [1, 2, 3, 4] }])),
        )]);
        let resolved = resolver(server.path.clone());

        let prober = {
            let resolved = resolved.clone();
            tokio::spawn(async move {
                resolved
                    .lookup_ipv4(&domain(), Duration::from_secs(2))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        // while the probe is in flight, other lookups fall back immediately
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert!(matches!(
            resolved
                .lookup_ipv6(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(server.connections(), 1);

        assert!(matches!(
            prober.await.expect("probe task"),
            ResolvedLookup::Records(_),
        ));
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn breaker_trips_after_consecutive_soft_failures() {
        let server = FakeResolved::spawn(vec![
            Behavior::Reply(hostname_reply(
                &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
            )),
            Behavior::CloseImmediately,
            Behavior::CloseImmediately,
        ]);
        let resolved = resolver(server.path.clone());

        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Records(_),
        ));
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert!(
            matches!(phase(&resolved), Phase::Available),
            "one failure below the threshold must not trip the breaker",
        );
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);

        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(
            server.connections(),
            3,
            "tripped breaker must skip the daemon"
        );
    }

    #[tokio::test]
    async fn hard_failure_flips_immediately() {
        let path = test_socket_path();
        let mut config = test_config(path.clone());
        config.breaker_threshold = 100;
        let resolved = Arc::new(SystemdResolved::new(config));

        let server = FakeResolved::spawn_at(
            path,
            vec![Behavior::Reply(hostname_reply(
                &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
            ))],
        );
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Records(_),
        ));

        drop(server); // socket file removed: connect now fails hard
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn txt_records_parse_raw_wire_format() {
        let cname = build_rr(&["example", "com"], 5, 60, &[0]);
        let txt = build_rr(
            &["example", "com"],
            RecordType::TXT.into(),
            123,
            &txt_rdata(&[b"hello", b"world"]),
        );
        let server = FakeResolved::spawn(vec![Behavior::Reply(json!({
            "parameters": {
                "rrs": [
                    { "raw": BASE64.encode(&cname) },
                    { "ifindex": 2, "raw": BASE64.encode(&txt) },
                ],
                "flags": 0,
            },
        }))]);
        let resolved = resolver(server.path.clone());
        match resolved.lookup_txt(&domain(), Duration::from_secs(2)).await {
            ResolvedLookup::Records(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].1, Some(123));
                assert_eq!(
                    records[0].0.iter().collect::<Vec<_>>(),
                    [b"hello".as_slice(), b"world".as_slice()],
                );
            }
            _ => panic!("expected records"),
        }
    }

    #[tokio::test]
    async fn service_binding_records_parse_raw_wire_format() {
        let cname = build_rr(&["example", "com"], 5, 60, &[0]);
        let svcb = build_rr(
            &["example", "com"],
            RecordType::SVCB.into(),
            123,
            &service_binding_rdata(8443),
        );
        let https = build_rr(
            &["example", "com"],
            RecordType::HTTPS.into(),
            321,
            &service_binding_rdata(443),
        );
        let server = FakeResolved::spawn(vec![
            Behavior::Reply(json!({
                "parameters": {
                    "rrs": [
                        { "raw": BASE64.encode(&cname) },
                        { "raw": BASE64.encode(&https) },
                        { "raw": BASE64.encode(&svcb) },
                    ],
                    "flags": 0,
                },
            })),
            Behavior::Reply(json!({
                "parameters": {
                    "rrs": [{ "raw": BASE64.encode(&https) }],
                    "flags": 0,
                },
            })),
        ]);
        let resolved = resolver(server.path.clone());

        match resolved
            .lookup_svcb(&domain(), Duration::from_secs(2))
            .await
        {
            ResolvedLookup::Records(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].0.port(), Some(8443));
                assert_eq!(records[0].1, Some(123));
            }
            _ => panic!("expected SVCB records"),
        }
        match resolved
            .lookup_https(&domain(), Duration::from_secs(2))
            .await
        {
            ResolvedLookup::Records(records) => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].0.port(), Some(443));
                assert_eq!(records[0].1, Some(321));
            }
            _ => panic!("expected HTTPS records"),
        }
    }

    #[tokio::test]
    async fn cname_only_record_reply_falls_back_without_tripping_backend() {
        let cname = build_rr(&["example", "com"], 5, 60, &[0]);
        let server = FakeResolved::spawn(vec![Behavior::Reply(json!({
            "parameters": {
                "rrs": [{ "raw": BASE64.encode(&cname) }],
                "flags": 0,
            },
        }))]);
        let resolved = resolver(server.path.clone());

        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(2)).await,
            ResolvedLookup::Unavailable,
        ));
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn record_method_not_found_pins_native_backend() {
        let server = FakeResolved::spawn(vec![
            Behavior::Reply(error_reply(ERROR_METHOD_NOT_FOUND)),
            Behavior::Reply(hostname_reply(
                &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
            )),
        ]);
        let resolved = resolver(server.path.clone());

        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(1)).await,
            ResolvedLookup::Unavailable,
        ));
        assert_available(&resolved);

        // Sticky for every ResolveRecord-backed family: no further daemon roundtrip.
        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(1)).await,
            ResolvedLookup::Unavailable,
        ));
        assert!(matches!(
            resolved
                .lookup_https(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(server.connections(), 1);

        // address lookups keep flowing
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Records(_),
        ));
        assert_eq!(server.connections(), 2);
    }

    #[tokio::test]
    async fn hung_daemon_times_out_and_flips_unavailable() {
        let server = FakeResolved::spawn(vec![Behavior::Hang]);
        let resolved = resolver(server.path.clone());
        let started = Instant::now();
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_millis(100))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn garbage_reply_is_transport_failure() {
        let server = FakeResolved::spawn(vec![Behavior::RawReply(b"not json\0".to_vec())]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn reply_split_across_writes_is_reassembled() {
        let server = FakeResolved::spawn(vec![Behavior::ChunkedReply(hostname_reply(
            &json!([{ "family": 2, "address": [1, 2, 3, 4] }]),
        ))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Records(_),
        ));
    }

    #[tokio::test]
    async fn concurrency_is_capped() {
        let path = test_socket_path();
        let mut config = test_config(path.clone());
        config.max_concurrency = 1;
        let resolved = Arc::new(SystemdResolved::new(config));

        let good = hostname_reply(&json!([{ "family": 2, "address": [1, 2, 3, 4] }]));
        let server = FakeResolved::spawn_at(
            path,
            vec![
                Behavior::Reply(good.clone()),
                Behavior::DelayedReply(Duration::from_millis(150), good.clone()),
                Behavior::DelayedReply(Duration::from_millis(150), good),
            ],
        );

        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Records(_),
        ));

        let domain = domain();
        let (a, b) = tokio::join!(
            resolved.lookup_ipv4(&domain, Duration::from_secs(2)),
            resolved.lookup_ipv4(&domain, Duration::from_secs(2)),
        );
        assert!(matches!(a, ResolvedLookup::Records(_)));
        assert!(matches!(b, ResolvedLookup::Records(_)));
        assert!(
            server.concurrent_peak.load(Ordering::SeqCst) <= 1,
            "semaphore must serialize daemon connections",
        );
    }

    #[test]
    fn claim_state_machine() {
        let resolved = SystemdResolved::new(test_config("/nonexistent".into()));

        let claim = resolved.claim().expect("first claim probes");
        assert!(claim.probe_generation.is_some());
        assert!(resolved.claim().is_none(), "probe is single-flight");

        resolved.report_success(claim);
        assert!(
            resolved
                .claim()
                .expect("available")
                .probe_generation
                .is_none()
        );

        resolved.report_transport_failure(
            Claim {
                probe_generation: None,
            },
            FailureKind::Soft,
        );
        assert!(
            resolved.claim().is_some(),
            "below the breaker threshold the backend stays available",
        );
        resolved.report_transport_failure(
            Claim {
                probe_generation: None,
            },
            FailureKind::Soft,
        );
        assert!(
            resolved.claim().is_none(),
            "breaker tripped, reprobe not due"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stale_probe_claim_is_reclaimed() {
        let resolved = SystemdResolved::new(test_config("/nonexistent".into()));
        let original = resolved.claim().expect("probe claim");
        assert!(original.probe_generation.is_some());
        assert!(resolved.claim().is_none(), "fresh probe is not reclaimable");

        tokio::time::advance(PROBE_STALE + Duration::from_secs(1)).await;
        let replacement = resolved.claim().expect("stale probe reclaimed");
        assert!(replacement.probe_generation.is_some());
        assert_ne!(replacement.probe_generation, original.probe_generation);
    }

    #[tokio::test(start_paused = true)]
    async fn superseded_probe_reports_do_not_reset_or_flip_replacement() {
        let resolved = SystemdResolved::new(test_config("/nonexistent".into()));
        let original = resolved.claim().expect("probe claim");
        assert!(original.probe_generation.is_some());
        tokio::time::advance(PROBE_STALE + Duration::from_secs(1)).await;
        let replacement = resolved.claim().expect("replacement probe");

        resolved.report_transport_failure(original, FailureKind::Overload);
        assert!(
            claim_is_current(&resolved.state.lock(), replacement),
            "an old overload must not reset the replacement probe",
        );

        resolved.report_transport_failure(original, FailureKind::Hard);
        assert!(
            claim_is_current(&resolved.state.lock(), replacement),
            "an old failure must not mark a recovered daemon unavailable",
        );
        assert!(matches!(
            resolved.classify_reply_error::<Bytes>(original, ERROR_METHOD_NOT_FOUND, true),
            ResolvedLookup::Unavailable,
        ));
        assert!(
            resolved.record_supported.load(Ordering::Acquire),
            "a superseded probe must not pin capabilities on its replacement",
        );

        resolved.report_success(replacement);
        assert_available(&resolved);
        resolved.report_transport_failure(original, FailureKind::Soft);
        assert_available(&resolved);
    }

    #[test]
    fn zero_reprobe_interval_reprobes_immediately() {
        let mut config = test_config("/nonexistent".into());
        config.reprobe_interval = Duration::ZERO;
        let resolved = SystemdResolved::new(config);

        let claim = resolved.claim().expect("probe claim");
        resolved.report_transport_failure(claim, FailureKind::Hard);
        assert!(
            resolved
                .claim()
                .expect("immediate reprobe")
                .probe_generation
                .is_some()
        );
    }

    #[test]
    fn recovery_probe_rechecks_pinned_record_capability() {
        let mut config = test_config("/nonexistent".into());
        config.reprobe_interval = Duration::ZERO;
        let resolved = SystemdResolved::new(config);

        let initial = resolved.claim().expect("initial probe");
        resolved.report_success(initial);
        resolved.record_supported.store(false, Ordering::Release);
        resolved.report_transport_failure(
            Claim {
                probe_generation: None,
            },
            FailureKind::Hard,
        );
        assert!(!resolved.record_supported.load(Ordering::Acquire));

        let reprobe = resolved.claim().expect("recovery probe");
        assert!(reprobe.probe_generation.is_some());
        assert!(resolved.record_supported.load(Ordering::Acquire));
    }

    #[test]
    fn parse_txt_rr_multi_segment() {
        let rdata = txt_rdata(&[b"v=spf1 -all", b""]);
        let raw = Bytes::from(build_rr(
            &["example", "com"],
            RecordType::TXT.into(),
            300,
            &rdata,
        ));
        let rdata_ptr = raw.as_ptr().wrapping_add(raw.len() - rdata.len());
        match parse_txt_rr(&raw) {
            RrParse::Record {
                ttl,
                value: segments,
            } => {
                assert_eq!(ttl, 300);
                assert_eq!(segments.as_wire().as_ptr(), rdata_ptr);
                assert_eq!(
                    segments.iter().collect::<Vec<_>>(),
                    [b"v=spf1 -all".as_slice(), b"".as_slice()],
                );
            }
            _ => panic!("expected txt"),
        }
    }

    #[test]
    fn parse_txt_rr_skips_other_types() {
        let raw = build_rr(&["example", "com"], 5, 300, &[0]);
        assert!(matches!(parse_txt_rr(&Bytes::from(raw)), RrParse::Other));
    }

    #[test]
    fn parse_txt_rr_rejects_malformed() {
        // truncated header
        assert!(matches!(
            parse_txt_rr(&Bytes::from_static(&[0, 0, 16])),
            RrParse::Malformed
        ));
        // compression pointer in the owner name
        assert!(matches!(
            parse_txt_rr(&Bytes::from_static(&[0xC0, 0x0C, 0, 16])),
            RrParse::Malformed
        ));
        // rdata segment length pointing past the buffer
        let mut raw = build_rr(&["example", "com"], RecordType::TXT.into(), 60, &[200]);
        assert!(matches!(
            parse_txt_rr(&Bytes::from(raw.clone())),
            RrParse::Malformed
        ));
        // TXT rdata must carry at least one character-string
        raw = build_rr(&["example", "com"], RecordType::TXT.into(), 60, &[]);
        assert!(matches!(
            parse_txt_rr(&Bytes::from(raw.clone())),
            RrParse::Malformed
        ));
        // rdlen pointing past the buffer
        raw = build_rr(
            &["example", "com"],
            RecordType::TXT.into(),
            60,
            &txt_rdata(&[b"ok"]),
        );
        raw.truncate(raw.len() - 1);
        assert!(matches!(
            parse_txt_rr(&Bytes::from(raw.clone())),
            RrParse::Malformed
        ));
        // bytes after the declared rdata are not part of a standalone RR
        raw = build_rr(
            &["example", "com"],
            RecordType::TXT.into(),
            60,
            &txt_rdata(&[b"ok"]),
        );
        raw.push(0);
        assert!(matches!(
            parse_txt_rr(&Bytes::from(raw)),
            RrParse::Malformed
        ));
    }

    #[test]
    fn parse_service_binding_rr_is_typed_validated_and_zero_copy() {
        let rdata = [0, 1, 0, 0, 100, 0, 3, 1, 2, 3];
        let raw = Bytes::from(build_rr(
            &["example", "com"],
            RecordType::SVCB.into(),
            300,
            &rdata,
        ));
        let value_ptr = raw.as_ptr().wrapping_add(raw.len() - rdata.len() + 7);

        match parse_service_binding_rr(&raw, RecordType::SVCB) {
            RrParse::Record { ttl, value } => {
                assert_eq!(ttl, 300);
                match &value.params()[0] {
                    crate::wire::SvcParam::Unknown { value, .. } => {
                        assert_eq!(value.as_ptr(), value_ptr);
                        assert_eq!(value.as_ref(), [1, 2, 3]);
                    }
                    _ => panic!("expected unknown parameter"),
                }
            }
            _ => panic!("expected service binding"),
        }
        assert!(matches!(
            parse_service_binding_rr(&raw, RecordType::HTTPS),
            RrParse::Other,
        ));

        let malformed = Bytes::from(build_rr(
            &["example", "com"],
            RecordType::SVCB.into(),
            300,
            &[0, 1],
        ));
        assert!(matches!(
            parse_service_binding_rr(&malformed, RecordType::SVCB),
            RrParse::Malformed,
        ));
    }

    #[test]
    fn hostname_cache_ttl_preserves_unknown_zero_and_rounds_up_subsecond() {
        assert_eq!(hostname_cache_ttl_secs(Duration::ZERO), None);
        assert_eq!(hostname_cache_ttl_secs(Duration::from_millis(500)), Some(1));
        assert_eq!(hostname_cache_ttl_secs(Duration::from_secs(15)), Some(15));
    }

    #[tokio::test]
    async fn dropped_consumer_probe_still_settles_state() {
        let server = FakeResolved::spawn(vec![Behavior::DelayedReply(
            Duration::from_millis(150),
            hostname_reply(&json!([{ "family": 2, "address": [1, 2, 3, 4] }])),
        )]);
        let resolved = resolver(server.path.clone());

        let lookup = {
            let resolved = resolved.clone();
            tokio::spawn(async move {
                resolved
                    .lookup_ipv4(&domain(), Duration::from_secs(2))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        lookup.abort(); // consumer gone mid-probe; the detached query task lives on

        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(phase(&resolved), Phase::Available) {
            assert!(Instant::now() < deadline, "probe never settled state");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(server.connections(), 1);
    }

    #[tokio::test]
    async fn relative_txt_negative_falls_back_without_authority() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(error_reply(ERROR_NO_SUCH_RR))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(1)).await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(server.connections(), 1, "the daemon is still asked first");
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn rooted_txt_negative_is_authoritative() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(error_reply(ERROR_NO_SUCH_RR))]);
        let resolved = resolver(server.path.clone());
        let rooted: Domain = "example.com.".try_into().expect("valid domain");
        assert!(matches!(
            resolved.lookup_txt(&rooted, Duration::from_secs(1)).await,
            ResolvedLookup::Negative,
        ));
        assert_available(&resolved);
    }

    #[tokio::test]
    async fn single_label_txt_stays_on_native_backend() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(error_reply(ERROR_NO_SUCH_RR))]);
        let resolved = resolver(server.path.clone());
        let single: Domain = "printer".try_into().expect("valid domain");
        assert!(matches!(
            resolved.lookup_txt(&single, Duration::from_secs(1)).await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(
            server.connections(),
            0,
            "search-domain candidates must be left to res_nsearch",
        );
    }

    #[tokio::test]
    async fn missing_addresses_field_is_transport_failure() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(json!({ "parameters": {} }))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn invalid_address_length_is_transport_failure() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(hostname_reply(&json!([
            { "family": 2, "address": [1, 2, 3, 4, 5] },
        ])))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn empty_success_replies_are_transport_failures() {
        let server = FakeResolved::spawn(vec![
            Behavior::Reply(hostname_reply(&json!([]))),
            Behavior::Reply(json!({ "parameters": { "rrs": [], "flags": 0 } })),
        ]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);

        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(1)).await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    /// Valid hostname reply padded to exactly `target_len` JSON bytes.
    fn padded_hostname_frame(target_len: usize) -> Vec<u8> {
        let build = |pad: String| {
            serde_json::to_vec(&json!({
                "parameters": {
                    "addresses": [{ "family": 2, "address": [1, 2, 3, 4] }],
                    "pad": pad,
                },
            }))
            .expect("serialize padded reply")
        };
        let overhead = build(String::new()).len();
        let mut raw = build("a".repeat(target_len - overhead));
        assert_eq!(raw.len(), target_len);
        raw.push(0);
        raw
    }

    #[tokio::test]
    async fn oversized_reply_is_transport_failure() {
        // an otherwise perfectly valid reply: only the size bound may reject it
        let server = FakeResolved::spawn(vec![Behavior::RawReply(padded_hostname_frame(
            MAX_REPLY_SIZE + 1,
        ))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_unavailable(&resolved);
    }

    #[tokio::test]
    async fn reply_at_size_bound_is_accepted() {
        let server = FakeResolved::spawn(vec![Behavior::RawReply(padded_hostname_frame(
            MAX_REPLY_SIZE,
        ))]);
        let resolved = resolver(server.path.clone());
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Records(_),
        ));
    }

    #[tokio::test]
    async fn txt_resolution_errors_surface_without_pinning() {
        let server = FakeResolved::spawn(vec![Behavior::Reply(error_reply(
            "io.systemd.Resolve.QueryTimedOut",
        ))]);
        let resolved = resolver(server.path.clone());
        match resolved.lookup_txt(&domain(), Duration::from_secs(1)).await {
            ResolvedLookup::Failed(err) => {
                assert!(err.to_string().contains("QueryTimedOut"), "got: {err}")
            }
            _ => panic!("expected failed lookup"),
        }
        // Only MethodNotFound may pin raw-record lookups to the native backend.
        match resolved.lookup_txt(&domain(), Duration::from_secs(1)).await {
            ResolvedLookup::Failed(_) => {}
            _ => panic!("expected failed lookup"),
        }
        assert_eq!(server.connections(), 2);
    }

    #[tokio::test]
    async fn queue_timeout_does_not_feed_breaker() {
        let path = test_socket_path();
        let mut config = test_config(path.clone());
        config.max_concurrency = 1;
        config.breaker_threshold = 1; // any counted soft failure would flip
        let resolved = Arc::new(SystemdResolved::new(config));

        let good = hostname_reply(&json!([{ "family": 2, "address": [1, 2, 3, 4] }]));
        let server = FakeResolved::spawn_at(
            path,
            vec![
                Behavior::Reply(good.clone()),
                Behavior::DelayedReply(Duration::from_millis(300), good),
            ],
        );

        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(2))
                .await,
            ResolvedLookup::Records(_),
        ));

        // occupy the single permit, then let another lookup expire in the queue
        let slow = {
            let resolved = resolved.clone();
            tokio::spawn(async move {
                resolved
                    .lookup_ipv4(&domain(), Duration::from_secs(2))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_millis(100))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_available(&resolved);
        assert_eq!(resolved.state.lock().failures, 0, "overload must not count");

        assert!(matches!(
            slow.await.expect("slow lookup"),
            ResolvedLookup::Records(_),
        ));
        assert_eq!(server.connections(), 2);
    }
}
