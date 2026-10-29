use std::{
    cmp::Ordering as CmpOrdering,
    collections::BinaryHeap,
    fmt,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::extensions::Extensions;
use rama_net::{address::SocketAddress, user::UserId};
use rama_utils::macros::generate_set_and_with;
use tokio::time::Instant;

/// Who a CONNECT-UDP tunnel is accounted to.
///
/// By default ([`PrincipalKey::from_request`]): the user an authentication layer in front
/// identified; else the IP the request came from (IPv6 by its /64); else one shared
/// anonymous principal. Forwarding headers are never trusted for it.
///
/// Its `Debug` output names the kind only, never a username or token.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PrincipalKey(Principal);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Principal {
    Username(Box<str>),
    Token(Box<[u8]>),
    Ip(IpAddr),
    Anonymous,
}

impl PrincipalKey {
    /// The principal everyone without an identity shares.
    pub const ANONYMOUS: Self = Self(Principal::Anonymous);

    /// The principal of an authenticated user; [`UserId::Anonymous`] is
    /// [`PrincipalKey::ANONYMOUS`].
    #[must_use]
    pub fn user(user: &UserId) -> Self {
        Self(match user {
            UserId::Username(name) => Principal::Username(name.as_str().into()),
            UserId::Token(token) => Principal::Token(token.as_slice().into()),
            UserId::Anonymous => Principal::Anonymous,
        })
    }

    /// The principal of a client IP: IPv4 as is, IPv6 by its /64 prefix.
    #[must_use]
    pub fn ip(ip: IpAddr) -> Self {
        Self(Principal::Ip(match ip.to_canonical() {
            IpAddr::V6(ip) => IpAddr::V6((ip.to_bits() & !u128::from(u64::MAX)).into()),
            ip @ IpAddr::V4(_) => ip,
        }))
    }

    /// The default principal of a request with these extensions, from `peer`.
    #[must_use]
    pub fn from_request(extensions: &Extensions, peer: Option<SocketAddress>) -> Self {
        match extensions.get_ref::<UserId>() {
            Some(user @ (UserId::Username(_) | UserId::Token(_))) => Self::user(user),
            _ => peer.map_or(Self::ANONYMOUS, |peer| Self::ip(peer.ip_addr)),
        }
    }
}

impl fmt::Debug for PrincipalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Principal::Username(_) => f.write_str("PrincipalKey::Username(..)"),
            Principal::Token(_) => f.write_str("PrincipalKey::Token(..)"),
            Principal::Ip(ip) => write!(f, "PrincipalKey::Ip({ip})"),
            Principal::Anonymous => f.write_str("PrincipalKey::Anonymous"),
        }
    }
}

/// How many CONNECT-UDP tunnels a proxy runs: in total and per [`PrincipalKey`].
///
/// A tunnel takes its place before the proxy resolves or connects anything and holds it
/// until it ends, however it ends. Clones share the places, so every clone of a
/// [`ConnectUdpService`](super::ConnectUdpService) counts against the same limits.
///
/// Principals are tracked only when a per-principal limit is set, in a map of at most
/// [`ConnectUdpLimits::with_max_principals`] entries. An entry is dropped only once no
/// tunnel holds it and it has been idle for [`ConnectUdpLimits::with_principal_idle_timeout`];
/// while the map is full of entries that cannot be dropped, tunnels of a new principal are
/// refused rather than letting a principal start over.
#[derive(Debug, Clone)]
pub struct ConnectUdpLimits {
    max_tunnels: Option<usize>,
    max_tunnels_per_principal: Option<usize>,
    max_principals: usize,
    principal_idle_timeout: Duration,
    state: Arc<LimitsState>,
}

impl Default for ConnectUdpLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// A tunnel limit was reached: total, per principal, or the principal map is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelLimitReached;

impl fmt::Display for TunnelLimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("connect-udp tunnel limit reached")
    }
}

impl std::error::Error for TunnelLimitReached {}

impl ConnectUdpLimits {
    /// No limits: every tunnel is admitted, and principals are not tracked.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_tunnels: None,
            max_tunnels_per_principal: None,
            max_principals: 65_536,
            principal_idle_timeout: Duration::from_mins(1),
            state: Arc::default(),
        }
    }

    generate_set_and_with! {
        /// The most tunnels the proxy runs at once.
        pub fn max_tunnels(mut self, max: Option<usize>) -> Self {
            self.max_tunnels = max;
            self
        }
    }

    generate_set_and_with! {
        /// The most tunnels one principal runs at once.
        pub fn max_tunnels_per_principal(mut self, max: Option<usize>) -> Self {
            self.max_tunnels_per_principal = max;
            self
        }
    }

    generate_set_and_with! {
        /// The most principals tracked at once (default 65 536).
        pub fn max_principals(mut self, max: usize) -> Self {
            self.max_principals = max;
            self
        }
    }

    generate_set_and_with! {
        /// How long a principal without tunnels stays tracked (default one minute).
        pub fn principal_idle_timeout(mut self, timeout: Duration) -> Self {
            self.principal_idle_timeout = timeout;
            self
        }
    }

    /// The tunnels running now.
    #[must_use]
    pub fn live_tunnels(&self) -> usize {
        self.state.live.load(Ordering::Acquire)
    }

    /// The principals tracked now.
    #[must_use]
    pub fn tracked_principals(&self) -> usize {
        self.state.principals.lock().entries.len()
    }

    fn tracks_principals(&self) -> bool {
        self.max_tunnels_per_principal.is_some()
    }

    /// Take a tunnel's place for `principal`, held until the returned lease drops.
    pub fn try_acquire(&self, principal: PrincipalKey) -> Result<TunnelLease, TunnelLimitReached> {
        increment_below(&self.state.live, self.max_tunnels)?;
        // From here the lease gives the place back on every exit, refusals included.
        let mut lease = TunnelLease {
            state: self.state.clone(),
            principal: None,
        };
        if self.tracks_principals() {
            let entry = self.principal(principal)?;
            increment_below(&entry.live, self.max_tunnels_per_principal)?;
            lease.principal = Some(entry);
        }
        Ok(lease)
    }

    fn principal(&self, key: PrincipalKey) -> Result<Arc<PrincipalEntry>, TunnelLimitReached> {
        let now = Instant::now();
        let mut principals = self.state.principals.lock();
        if let Some(entry) = principals.entries.get(&key) {
            return Ok(entry.clone());
        }
        principals.expire_idle(now, self.principal_idle_timeout);
        if principals.entries.len() >= self.max_principals {
            return Err(TunnelLimitReached);
        }
        let entry = Arc::new(PrincipalEntry {
            live: AtomicUsize::new(0),
            last_used: Mutex::new(now),
        });
        principals.entries.insert(key.clone(), entry.clone());
        principals.expirations.push(Expiration {
            at: expiration_at(now, self.principal_idle_timeout),
            key,
        });
        Ok(entry)
    }
}

/// Add one to `counter` unless that would pass `max`.
fn increment_below(counter: &AtomicUsize, max: Option<usize>) -> Result<(), TunnelLimitReached> {
    let Some(max) = max else {
        counter.fetch_add(1, Ordering::AcqRel);
        return Ok(());
    };
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
            (live < max).then_some(live + 1)
        })
        .map(drop)
        .map_err(|_live| TunnelLimitReached)
}

/// A tunnel's place among the proxy's [`ConnectUdpLimits`], given back when dropped.
#[derive(Debug)]
pub struct TunnelLease {
    state: Arc<LimitsState>,
    principal: Option<Arc<PrincipalEntry>>,
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        if let Some(principal) = self.principal.take() {
            *principal.last_used.lock() = Instant::now();
            principal.live.fetch_sub(1, Ordering::AcqRel);
        }
        self.state.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Default)]
struct LimitsState {
    live: AtomicUsize,
    principals: Mutex<PrincipalMap>,
}

#[derive(Debug)]
struct PrincipalEntry {
    /// Tunnels admitted for the principal that have not ended, including ones still
    /// being set up.
    live: AtomicUsize,
    last_used: Mutex<Instant>,
}

#[derive(Debug, Default)]
struct PrincipalMap {
    entries: HashMap<PrincipalKey, Arc<PrincipalEntry>>,
    expirations: BinaryHeap<Expiration>,
}

impl PrincipalMap {
    /// Drop the entries no lease holds that have been idle for `idle_timeout`.
    fn expire_idle(&mut self, now: Instant, idle_timeout: Duration) {
        while self
            .expirations
            .peek()
            .is_some_and(|expiry| expiry.at <= now)
        {
            let Some(expiry) = self.expirations.pop() else {
                break;
            };
            let Some(entry) = self.entries.get(&expiry.key) else {
                continue;
            };
            // Only the map holds an entry no lease uses; a held one is never dropped, and is
            // looked at again strictly later, so this sweep ends whatever the idle timeout.
            if Arc::strong_count(entry) > 1 {
                self.expirations.push(Expiration {
                    at: expiration_at(now, idle_timeout.max(Duration::from_nanos(1))),
                    key: expiry.key,
                });
                continue;
            }
            let at = expiration_at(*entry.last_used.lock(), idle_timeout);
            if at > now {
                self.expirations.push(Expiration {
                    at,
                    key: expiry.key,
                });
            } else {
                self.entries.remove(&expiry.key);
            }
        }
    }
}

#[derive(Debug)]
struct Expiration {
    at: Instant,
    key: PrincipalKey,
}

impl PartialEq for Expiration {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl Eq for Expiration {}

impl PartialOrd for Expiration {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for Expiration {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reversed: the heap pops the earliest expiration first.
        other.at.cmp(&self.at)
    }
}

/// `now + timeout`, shortened only when the platform cannot represent it.
fn expiration_at(now: Instant, mut timeout: Duration) -> Instant {
    loop {
        if let Some(at) = now.checked_add(timeout) {
            return at;
        }
        timeout /= 2;
    }
}

#[cfg(test)]
mod tests;
