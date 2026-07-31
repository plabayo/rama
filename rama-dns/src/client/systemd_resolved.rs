//! systemd-resolved varlink backend for the Linux DNS resolver.
//!
//! Speaks the native `io.systemd.Resolve` API (JSON frames terminated by a
//! NUL byte, one call per connection) over the daemon's unix socket — the
//! same transport glibc's `nss-resolve` module uses. Unlike the libc paths
//! this is fully async: no blocking-pool worker is held and timeouts cancel
//! the query.
//!
//! Address lookups use `ResolveHostname` for `getaddrinfo` parity (search
//! domains, `/etc/hosts`, synthesized names, CNAME chasing). TXT lookups use
//! `ResolveRecord` (raw wire-format RRs, real TTLs), which older daemons do
//! not implement — a `MethodNotFound` reply pins TXT to the native backend
//! without affecting address lookups.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rama_core::{bytes::Bytes, error::BoxError, telemetry::tracing};
use rama_net::address::Domain;
use rama_unix::client::default_unix_connect;
use rama_utils::{octets::kib, str::arcstr::ArcStr};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Semaphore,
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

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_TXT: u16 = 16;

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
        }
    }
}

const UNTESTED: u8 = 0;
const PROBING: u8 = 1;
const AVAILABLE: u8 = 2;
const UNAVAILABLE: u8 = 3;

/// Lock-free availability tracking: the first lookup doubles as the probe
/// (single-flight via CAS), transport failures feed a consecutive-failure
/// breaker, and an unavailable daemon is re-probed at most once per
/// [`Config::reprobe_interval`]. Lookups never wait on a probe: whoever does
/// not hold the claim reports [`ResolvedLookup::Unavailable`] so the caller
/// uses the native backend instead.
#[derive(Debug)]
pub(super) struct SystemdResolved {
    config: Config,
    epoch: Instant,
    state: AtomicU8,
    /// ms since `epoch`: probe claim time while probing, flip time while unavailable
    stamp: AtomicU64,
    failures: AtomicU32,
    txt_supported: AtomicBool,
    permits: Semaphore,
}

pub(super) enum ResolvedLookup<T> {
    /// Records with their DNS TTL in seconds (`0` = unknown).
    Records(Vec<(T, u32)>),
    /// Authoritative "no such record" answer.
    Negative,
    /// Resolution failed upstream: surface it; falling back would re-ask the
    /// same daemon through its slower 127.0.0.53 stub.
    Failed(BoxError),
    /// resolved is not usable for this lookup; use the native backend.
    Unavailable,
}

#[derive(Clone, Copy)]
struct Claim {
    probing: bool,
}

struct TransportFailure {
    hard: bool,
    error: BoxError,
}

impl TransportFailure {
    fn soft(error: impl Into<BoxError>) -> Self {
        Self {
            hard: false,
            error: error.into(),
        }
    }

    fn hard(error: impl Into<BoxError>) -> Self {
        Self {
            hard: true,
            error: error.into(),
        }
    }
}

impl SystemdResolved {
    pub(super) fn new(config: Config) -> Self {
        let permits = Semaphore::new(config.max_concurrency.max(1));
        Self {
            config,
            epoch: Instant::now(),
            state: AtomicU8::new(UNTESTED),
            stamp: AtomicU64::new(0),
            failures: AtomicU32::new(0),
            txt_supported: AtomicBool::new(true),
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
    ) -> ResolvedLookup<Bytes> {
        if !self.txt_supported.load(Ordering::Acquire) {
            return ResolvedLookup::Unavailable;
        }
        let Some(claim) = self.claim() else {
            return ResolvedLookup::Unavailable;
        };
        let this = self.clone();
        let name = wire_name(domain);
        join(tokio::spawn(async move {
            this.record_query(claim, name, timeout).await
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
        match serde_json::from_value::<HostnameReply>(envelope.parameters) {
            Ok(reply) => {
                self.report_success();
                ResolvedLookup::Records(
                    reply
                        .addresses
                        .into_iter()
                        .filter(|entry| entry.family == family)
                        .filter_map(|entry| decode(&entry.address).map(|value| (value, 0)))
                        .collect(),
                )
            }
            Err(err) => self.transport_failed(
                claim,
                TransportFailure::soft(format!("invalid ResolveHostname reply: {err}")),
            ),
        }
    }

    async fn record_query(
        self: Arc<Self>,
        claim: Claim,
        name: String,
        timeout: Duration,
    ) -> ResolvedLookup<Bytes> {
        let envelope = match self
            .call(
                METHOD_RESOLVE_RECORD,
                &RecordParams {
                    name: &name,
                    r#type: DNS_TYPE_TXT,
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
            return self.classify_reply_error(claim, error, true);
        }
        let reply = match serde_json::from_value::<RecordReply>(envelope.parameters) {
            Ok(reply) => reply,
            Err(err) => {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft(format!("invalid ResolveRecord reply: {err}")),
                );
            }
        };
        let mut records = Vec::new();
        for entry in &reply.rrs {
            let Ok(raw) = BASE64.decode(&entry.raw) else {
                return self.transport_failed(
                    claim,
                    TransportFailure::soft("invalid base64 rr in ResolveRecord reply"),
                );
            };
            match parse_txt_rr(&raw) {
                RrParse::Txt { ttl, segments } => {
                    records.extend(segments.into_iter().map(|segment| (segment, ttl)));
                }
                // e.g. CNAME chain entries included alongside the target RRset
                RrParse::Other => {}
                RrParse::Malformed => {
                    return self.transport_failed(
                        claim,
                        TransportFailure::soft("malformed rr in ResolveRecord reply"),
                    );
                }
            }
        }
        self.report_success();
        if records.is_empty() {
            ResolvedLookup::Negative
        } else {
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
            self.report_success();
            return ResolvedLookup::Negative;
        }
        if record_query && error == ERROR_METHOD_NOT_FOUND {
            // daemon reachable but too old for ResolveRecord: pin TXT to the
            // native backend, address lookups keep flowing
            self.report_success();
            self.txt_supported.store(false, Ordering::Release);
            tracing::debug!(
                "dns::systemd-resolved: ResolveRecord not implemented; txt lookups use the native backend"
            );
            return ResolvedLookup::Unavailable;
        }
        if error.starts_with(VARLINK_ERROR_PREFIX) {
            return self.transport_failed(
                claim,
                TransportFailure::soft(format!("varlink protocol error: {error}")),
            );
        }
        self.report_success();
        ResolvedLookup::Failed(
            SystemdResolvedError::message(format!("systemd-resolved lookup failed: {error}"))
                .into(),
        )
    }

    fn transport_failed<T>(&self, claim: Claim, failure: TransportFailure) -> ResolvedLookup<T> {
        let TransportFailure { hard, error } = failure;
        tracing::debug!(
            err = %error,
            hard,
            "dns::systemd-resolved: transport failure",
        );
        self.report_transport_failure(claim, hard);
        ResolvedLookup::Unavailable
    }

    fn claim(&self) -> Option<Claim> {
        let now = self.now_ms();
        match self.state.load(Ordering::Acquire) {
            AVAILABLE => Some(Claim { probing: false }),
            UNTESTED => self
                .state
                .compare_exchange(UNTESTED, PROBING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then(|| {
                    self.stamp.store(now, Ordering::Release);
                    Claim { probing: true }
                }),
            PROBING => {
                let stamped = self.stamp.load(Ordering::Acquire);
                (now.saturating_sub(stamped) > ms(PROBE_STALE)
                    && self
                        .stamp
                        .compare_exchange(stamped, now, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok())
                .then_some(Claim { probing: true })
            }
            _ => {
                let stamped = self.stamp.load(Ordering::Acquire);
                if now.saturating_sub(stamped) >= ms(self.config.reprobe_interval)
                    && self
                        .stamp
                        .compare_exchange(stamped, now, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    self.state.store(PROBING, Ordering::Release);
                    Some(Claim { probing: true })
                } else {
                    None
                }
            }
        }
    }

    fn report_success(&self) {
        self.failures.store(0, Ordering::Release);
        if self.state.swap(AVAILABLE, Ordering::AcqRel) != AVAILABLE {
            tracing::debug!("dns::systemd-resolved: available");
        }
    }

    fn report_transport_failure(&self, claim: Claim, hard: bool) {
        if claim.probing || hard {
            self.mark_unavailable();
            return;
        }
        if self.failures.fetch_add(1, Ordering::AcqRel) + 1 >= self.config.breaker_threshold {
            self.mark_unavailable();
        }
    }

    fn mark_unavailable(&self) {
        self.failures.store(0, Ordering::Release);
        self.stamp.store(self.now_ms(), Ordering::Release);
        if self.state.swap(UNAVAILABLE, Ordering::AcqRel) != UNAVAILABLE {
            tracing::debug!(
                reprobe_interval = ?self.config.reprobe_interval,
                "dns::systemd-resolved: unavailable; lookups use the native backend",
            );
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    async fn call<P: Serialize>(
        &self,
        method: &'static str,
        parameters: &P,
        timeout: Duration,
    ) -> Result<Envelope, TransportFailure> {
        match tokio::time::timeout(timeout, self.call_inner(method, parameters)).await {
            Ok(result) => result,
            Err(_) => Err(TransportFailure::soft(format!(
                "{method} timed out after {timeout:?}"
            ))),
        }
    }

    async fn call_inner<P: Serialize>(
        &self,
        method: &'static str,
        parameters: &P,
    ) -> Result<Envelope, TransportFailure> {
        let _permit =
            self.permits.acquire().await.map_err(|err| {
                TransportFailure::soft(format!("varlink semaphore closed: {err}"))
            })?;

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
                return Err(TransportFailure::soft(format!(
                    "connect timed out after {:?}",
                    self.config.connect_timeout
                )));
            }
        };

        let mut frame = serde_json::to_vec(&Call { method, parameters })
            .map_err(|err| TransportFailure::soft(format!("encode varlink call: {err}")))?;
        frame.push(0);
        stream
            .write_all(&frame)
            .await
            .map_err(|err| TransportFailure::soft(format!("write varlink call: {err}")))?;

        let mut buf = Vec::with_capacity(1024);
        let mut scanned = 0;
        loop {
            let n = stream
                .read_buf(&mut buf)
                .await
                .map_err(|err| TransportFailure::soft(format!("read varlink reply: {err}")))?;
            if n == 0 {
                return Err(TransportFailure::soft(
                    "connection closed before varlink reply",
                ));
            }
            if let Some(pos) = buf[scanned..].iter().position(|byte| *byte == 0) {
                let frame = &buf[..scanned + pos];
                return serde_json::from_slice(frame)
                    .map_err(|err| TransportFailure::soft(format!("decode varlink reply: {err}")));
            }
            scanned = buf.len();
            if buf.len() > MAX_REPLY_SIZE {
                return Err(TransportFailure::soft("varlink reply exceeds size bound"));
            }
        }
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

fn wire_name(domain: &Domain) -> String {
    domain.as_str().trim_end_matches('.').to_owned()
}

fn ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
    #[serde(default)]
    addresses: Vec<AddressEntry>,
}

#[derive(Deserialize)]
struct AddressEntry {
    family: i64,
    address: Vec<u8>,
}

#[derive(Deserialize)]
struct RecordReply {
    #[serde(default)]
    rrs: Vec<RecordEntry>,
}

#[derive(Deserialize)]
struct RecordEntry {
    raw: String,
}

enum RrParse {
    Txt { ttl: u32, segments: Vec<Bytes> },
    Other,
    Malformed,
}

/// Parse one wire-format RR as produced by `ResolveRecord`'s `raw` field.
/// Owner names are standalone here, so compression pointers cannot be
/// resolved and are treated as malformed.
fn parse_txt_rr(raw: &[u8]) -> RrParse {
    let Some(mut offset) = skip_uncompressed_name(raw) else {
        return RrParse::Malformed;
    };
    let Some(header) = raw.get(offset..offset + 10) else {
        return RrParse::Malformed;
    };
    let rtype = u16::from_be_bytes([header[0], header[1]]);
    let class = u16::from_be_bytes([header[2], header[3]]);
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let rdlen = u16::from_be_bytes([header[8], header[9]]) as usize;
    offset += 10;
    let Some(rdata) = raw.get(offset..offset + rdlen) else {
        return RrParse::Malformed;
    };
    if rtype != DNS_TYPE_TXT || class != DNS_CLASS_IN {
        return RrParse::Other;
    }
    let mut segments = Vec::new();
    let mut cursor = 0;
    while cursor < rdata.len() {
        let len = rdata[cursor] as usize;
        cursor += 1;
        let Some(segment) = rdata.get(cursor..cursor + len) else {
            return RrParse::Malformed;
        };
        segments.push(Bytes::copy_from_slice(segment));
        cursor += len;
    }
    RrParse::Txt { ttl, segments }
}

fn skip_uncompressed_name(raw: &[u8]) -> Option<usize> {
    let mut offset = 0;
    loop {
        let len = *raw.get(offset)?;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset += 1 + len as usize;
    }
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
        }
    }

    fn resolver(path: PathBuf) -> Arc<SystemdResolved> {
        Arc::new(SystemdResolved::new(test_config(path)))
    }

    fn domain() -> Domain {
        "example.com".try_into().expect("valid domain")
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
                    (Ipv4Addr::new(93, 184, 216, 34), 0),
                    (Ipv4Addr::new(10, 0, 0, 1), 0),
                ],
            ),
            _ => panic!("expected records"),
        }
        assert_eq!(server.connections(), 1);
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);
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
                vec![("2001:db8::1".parse::<Ipv6Addr>().expect("valid ipv6"), 0)],
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);
        assert_eq!(resolved.failures.load(Ordering::SeqCst), 0);
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), UNAVAILABLE);

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
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);
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
        assert_eq!(
            resolved.state.load(Ordering::SeqCst),
            AVAILABLE,
            "one failure below the threshold must not trip the breaker",
        );
        assert!(matches!(
            resolved
                .lookup_ipv4(&domain(), Duration::from_secs(1))
                .await,
            ResolvedLookup::Unavailable,
        ));
        assert_eq!(resolved.state.load(Ordering::SeqCst), UNAVAILABLE);

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
        assert_eq!(resolved.state.load(Ordering::SeqCst), UNAVAILABLE);
    }

    #[tokio::test]
    async fn txt_records_parse_raw_wire_format() {
        let cname = build_rr(&["example", "com"], 5, 60, &[0]);
        let txt = build_rr(
            &["example", "com"],
            DNS_TYPE_TXT,
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
            ResolvedLookup::Records(records) => assert_eq!(
                records,
                vec![
                    (Bytes::from_static(b"hello"), 123),
                    (Bytes::from_static(b"world"), 123),
                ],
            ),
            _ => panic!("expected records"),
        }
    }

    #[tokio::test]
    async fn txt_method_not_found_pins_native_backend() {
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), AVAILABLE);

        // sticky: no further daemon roundtrip for txt
        assert!(matches!(
            resolved.lookup_txt(&domain(), Duration::from_secs(1)).await,
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), UNAVAILABLE);
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
        assert_eq!(resolved.state.load(Ordering::SeqCst), UNAVAILABLE);
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
        assert!(claim.probing);
        assert!(resolved.claim().is_none(), "probe is single-flight");

        resolved.report_success();
        assert!(!resolved.claim().expect("available").probing);

        resolved.report_transport_failure(Claim { probing: false }, false);
        assert!(
            resolved.claim().is_some(),
            "below the breaker threshold the backend stays available",
        );
        resolved.report_transport_failure(Claim { probing: false }, false);
        assert!(
            resolved.claim().is_none(),
            "breaker tripped, reprobe not due"
        );
    }

    #[test]
    fn zero_reprobe_interval_reprobes_immediately() {
        let mut config = test_config("/nonexistent".into());
        config.reprobe_interval = Duration::ZERO;
        let resolved = SystemdResolved::new(config);

        let claim = resolved.claim().expect("probe claim");
        resolved.report_transport_failure(claim, true);
        assert!(resolved.claim().expect("immediate reprobe").probing);
    }

    #[test]
    fn parse_txt_rr_multi_segment() {
        let raw = build_rr(
            &["example", "com"],
            DNS_TYPE_TXT,
            300,
            &txt_rdata(&[b"v=spf1 -all", b""]),
        );
        match parse_txt_rr(&raw) {
            RrParse::Txt { ttl, segments } => {
                assert_eq!(ttl, 300);
                assert_eq!(
                    segments,
                    vec![Bytes::from_static(b"v=spf1 -all"), Bytes::new()],
                );
            }
            _ => panic!("expected txt"),
        }
    }

    #[test]
    fn parse_txt_rr_skips_other_types() {
        let raw = build_rr(&["example", "com"], 5, 300, &[0]);
        assert!(matches!(parse_txt_rr(&raw), RrParse::Other));
    }

    #[test]
    fn parse_txt_rr_rejects_malformed() {
        // truncated header
        assert!(matches!(parse_txt_rr(&[0, 0, 16]), RrParse::Malformed));
        // compression pointer in the owner name
        assert!(matches!(
            parse_txt_rr(&[0xC0, 0x0C, 0, 16]),
            RrParse::Malformed
        ));
        // rdata segment length pointing past the buffer
        let mut raw = build_rr(&["example", "com"], DNS_TYPE_TXT, 60, &[200]);
        assert!(matches!(parse_txt_rr(&raw), RrParse::Malformed));
        // rdlen pointing past the buffer
        raw = build_rr(&["example", "com"], DNS_TYPE_TXT, 60, &txt_rdata(&[b"ok"]));
        raw.truncate(raw.len() - 1);
        assert!(matches!(parse_txt_rr(&raw), RrParse::Malformed));
    }
}
