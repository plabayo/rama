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
use rama_core::{error::BoxError, extensions::ExtensionsRef};
use rama_http::Request;
use rama_net::{
    rate::{ClientIpRateKey, InputToRateKey, RateKey},
    user::UserId,
};
use rama_utils::macros::generate_set_and_with;
use tokio::time::Instant;

use super::budget::{PrincipalBudget, PrincipalSpend, QuotaWindowState};

/// Who a CONNECT-UDP tunnel is accounted to: the key [`UserOrClientIpKey`] derives.
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

    /// The principal of a client IP, as given: a keyer aggregates it first, as
    /// [`ClientIpRateKey`] does.
    #[must_use]
    pub const fn ip(ip: IpAddr) -> Self {
        Self(Principal::Ip(ip))
    }
}

impl RateKey for PrincipalKey {}

/// The default [`InputToRateKey`] of [`ConnectUdpLimits`]: the user an authentication layer in
/// front identified; else the client IP, by [`ClientIpRateKey`] (an IPv6 client by its /64 by
/// default, a `Forwarded` address only when a trusted layer set it); else
/// [`PrincipalKey::ANONYMOUS`]. It always yields a key.
#[derive(Debug, Clone, Default)]
pub struct UserOrClientIpKey {
    ip: ClientIpRateKey,
}

impl UserOrClientIpKey {
    /// Users, then client IPs as [`ClientIpRateKey::new`] keys them.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// How client IPs are keyed, such as their IPv6 aggregation prefix.
        pub fn client_ip(mut self, key: ClientIpRateKey) -> Self {
            self.ip = key;
            self
        }
    }
}

impl<Input> InputToRateKey<Input> for UserOrClientIpKey
where
    Input: ExtensionsRef + Send + Sync + 'static,
{
    type Key = PrincipalKey;

    fn rate_key(&self, input: &Input) -> Result<Option<PrincipalKey>, BoxError> {
        if let Some(user @ (UserId::Username(_) | UserId::Token(_))) =
            input.extensions().get_ref::<UserId>()
        {
            return Ok(Some(PrincipalKey::user(user)));
        }
        let ip = self.ip.rate_key(input)?;
        Ok(Some(ip.map_or(PrincipalKey::ANONYMOUS, PrincipalKey::ip)))
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

/// How many CONNECT-UDP tunnels a proxy runs: in total and per principal.
///
/// A principal is the key the keyer `X` derives from a CONNECT-UDP request
/// ([`InputToRateKey`], closures included): by default [`UserOrClientIpKey`]; rama-net's
/// [`ClientIpRateKey`] keys by client IP alone ([`ConnectUdpLimits::with_keyer`]), and any keyer
/// can derive its own key type, such as a tenant ID, from the request's headers and extensions.
/// The keyer is asked only when a per-principal limit or budget is set, as nothing else needs a
/// principal; then a request it yields no key for, or fails on, is refused.
///
/// A tunnel takes its place before the proxy resolves or connects anything and holds it
/// until it ends, however it ends. Clones share the places, so every clone of a
/// [`ConnectUdpService`](super::ConnectUdpService) counts against the same limits.
///
/// Principals are tracked only when a per-principal limit or budget is set, in a map of at
/// most [`ConnectUdpLimits::with_max_principals`] entries. An entry is dropped only once no
/// tunnel holds it, it has been idle for [`ConnectUdpLimits::with_principal_idle_timeout`] or
/// for as long as its [`PrincipalBudget`] rates take to refill if that is longer, and its quota
/// window has ended; while the map is full of entries that cannot be dropped, tunnels of a new
/// principal are refused rather than letting a principal start over.
pub struct ConnectUdpLimits<X = UserOrClientIpKey, K = PrincipalKey> {
    max_tunnels: Option<usize>,
    max_tunnels_per_principal: Option<usize>,
    max_principals: usize,
    principal_idle_timeout: Duration,
    principal_budget: Option<PrincipalBudget>,
    keyer: Arc<X>,
    live: Arc<AtomicUsize>,
    principals: Arc<Mutex<PrincipalMap<K>>>,
}

impl<X, K> Clone for ConnectUdpLimits<X, K> {
    fn clone(&self) -> Self {
        Self {
            max_tunnels: self.max_tunnels,
            max_tunnels_per_principal: self.max_tunnels_per_principal,
            max_principals: self.max_principals,
            principal_idle_timeout: self.principal_idle_timeout,
            principal_budget: self.principal_budget,
            keyer: self.keyer.clone(),
            live: self.live.clone(),
            principals: self.principals.clone(),
        }
    }
}

impl<X: fmt::Debug, K> fmt::Debug for ConnectUdpLimits<X, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpLimits")
            .field("max_tunnels", &self.max_tunnels)
            .field("max_tunnels_per_principal", &self.max_tunnels_per_principal)
            .field("max_principals", &self.max_principals)
            .field("principal_idle_timeout", &self.principal_idle_timeout)
            .field("principal_budget", &self.principal_budget)
            .field("keyer", &self.keyer)
            .finish_non_exhaustive()
    }
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

/// Why a tunnel was not admitted.
#[derive(Debug)]
pub(crate) enum Refused {
    /// A tunnel limit was reached.
    LimitReached,
    /// The keyer derived no principal for the request.
    NoPrincipal,
    /// The keyer failed.
    Keyer,
}

impl ConnectUdpLimits {
    /// No limits: every tunnel is admitted, and principals are not tracked. Principals are
    /// keyed by [`UserOrClientIpKey`] once a per-principal limit is set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_tunnels: None,
            max_tunnels_per_principal: None,
            max_principals: 65_536,
            principal_idle_timeout: Duration::from_mins(1),
            principal_budget: None,
            keyer: Arc::new(UserOrClientIpKey::new()),
            live: Arc::default(),
            principals: Arc::default(),
        }
    }
}

impl<X, K> ConnectUdpLimits<X, K> {
    /// Key principals with `keyer` instead, from each CONNECT-UDP request.
    #[must_use]
    pub fn with_keyer<X2>(self, keyer: X2) -> ConnectUdpLimits<X2, X2::Key>
    where
        X2: InputToRateKey<Request>,
    {
        ConnectUdpLimits {
            max_tunnels: self.max_tunnels,
            max_tunnels_per_principal: self.max_tunnels_per_principal,
            max_principals: self.max_principals,
            principal_idle_timeout: self.principal_idle_timeout,
            principal_budget: self.principal_budget,
            keyer: Arc::new(keyer),
            live: self.live,
            principals: Arc::default(),
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

    generate_set_and_with! {
        /// What all the tunnels of one principal may move together.
        pub fn principal_budget(mut self, budget: Option<PrincipalBudget>) -> Self {
            self.principal_budget = budget;
            self
        }
    }

    /// The tunnels running now.
    #[must_use]
    pub fn live_tunnels(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// The principals tracked now.
    #[must_use]
    pub fn tracked_principals(&self) -> usize {
        self.principals.lock().entries.len()
    }

    fn tracks_principals(&self) -> bool {
        self.max_tunnels_per_principal.is_some() || self.principal_budget.is_some()
    }

    /// How long a principal without tunnels stays tracked at least.
    fn retention(&self) -> Duration {
        self.principal_budget
            .map_or(Duration::ZERO, |budget| budget.refill_time())
            .max(self.principal_idle_timeout)
    }

    /// Take a tunnel's place for the principal `request` is keyed to, held until the returned
    /// lease drops; the request is keyed only when a per-principal limit or budget is set.
    pub(crate) fn admit<Input>(&self, request: &Input) -> Result<TunnelLease, Refused>
    where
        X: InputToRateKey<Input, Key = K>,
        K: RateKey,
    {
        if !self.tracks_principals() {
            return self
                .try_acquire_untracked()
                .map_err(|TunnelLimitReached| Refused::LimitReached);
        }
        match self.keyer.rate_key(request) {
            Ok(Some(key)) => self
                .try_acquire(key)
                .map_err(|TunnelLimitReached| Refused::LimitReached),
            Ok(None) => Err(Refused::NoPrincipal),
            Err(_) => Err(Refused::Keyer),
        }
    }

    /// Take a tunnel's place for `principal`, held until the returned lease drops.
    pub fn try_acquire(&self, principal: K) -> Result<TunnelLease, TunnelLimitReached>
    where
        K: RateKey,
    {
        let mut lease = self.try_acquire_untracked()?;
        if self.tracks_principals() {
            let entry = self.principal(principal)?;
            increment_below(&entry.live, self.max_tunnels_per_principal)?;
            lease.principal = Some(entry);
        }
        Ok(lease)
    }

    /// A place among all tunnels; from here the lease gives it back on every exit.
    fn try_acquire_untracked(&self) -> Result<TunnelLease, TunnelLimitReached> {
        increment_below(&self.live, self.max_tunnels)?;
        Ok(TunnelLease {
            live: self.live.clone(),
            principal: None,
        })
    }

    fn principal(&self, key: K) -> Result<Arc<PrincipalEntry>, TunnelLimitReached>
    where
        K: RateKey,
    {
        let now = Instant::now();
        let mut principals = self.principals.lock();
        if let Some(entry) = principals.entries.get(&key) {
            return Ok(entry.clone());
        }
        let retention = self.retention();
        principals.expire_idle(now, retention);
        if principals.entries.len() >= self.max_principals {
            return Err(TunnelLimitReached);
        }
        let entry = Arc::new(PrincipalEntry {
            live: AtomicUsize::new(0),
            last_used: Mutex::new(now),
            spend: self.principal_budget.map(|budget| Arc::new(budget.spend())),
        });
        principals.entries.insert(key.clone(), entry.clone());
        principals.expirations.push(Expiration {
            at: expiration_at(now, retention),
            key,
        });
        Ok(entry)
    }
}

/// The limits of a [`ConnectUdpService`](super::ConnectUdpService), whatever their keyer.
pub(crate) trait AdmitTunnel: Send + Sync + 'static {
    fn admit(&self, request: &Request) -> Result<TunnelLease, Refused>;
}

impl<X, K> AdmitTunnel for ConnectUdpLimits<X, K>
where
    X: InputToRateKey<Request, Key = K>,
    K: RateKey,
{
    fn admit(&self, request: &Request) -> Result<TunnelLease, Refused> {
        Self::admit(self, request)
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
    live: Arc<AtomicUsize>,
    principal: Option<Arc<PrincipalEntry>>,
}

impl TunnelLease {
    /// The budget of the tunnel's principal, when it has one.
    pub(crate) fn principal_spend(&self) -> Option<Arc<PrincipalSpend>> {
        self.principal.as_ref()?.spend.clone()
    }
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        if let Some(principal) = self.principal.take() {
            *principal.last_used.lock() = Instant::now();
            principal.live.fetch_sub(1, Ordering::AcqRel);
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct PrincipalEntry {
    /// Tunnels admitted for the principal that have not ended, including ones still
    /// being set up.
    live: AtomicUsize,
    last_used: Mutex<Instant>,
    spend: Option<Arc<PrincipalSpend>>,
}

struct PrincipalMap<K> {
    entries: HashMap<K, Arc<PrincipalEntry>>,
    expirations: BinaryHeap<Expiration<K>>,
}

impl<K> Default for PrincipalMap<K> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
            expirations: BinaryHeap::new(),
        }
    }
}

impl<K: RateKey> PrincipalMap<K> {
    /// Drop the entries no lease holds that have been idle for `idle_timeout` and whose quota
    /// window has ended.
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
            let idle_until = expiration_at(*entry.last_used.lock(), idle_timeout);
            let window = entry
                .spend
                .as_ref()
                .map_or(QuotaWindowState::Closed, |spend| spend.quota_window(now));
            let at = match window {
                QuotaWindowState::Closed => idle_until,
                QuotaWindowState::OpenUntil(end) => end.max(idle_until),
                // An end no instant can hold: look again later, never drop it early.
                QuotaWindowState::OpenBeyond => {
                    expiration_at(now, idle_timeout.max(Duration::from_nanos(1))).max(idle_until)
                }
            };
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

struct Expiration<K> {
    at: Instant,
    key: K,
}

impl<K> PartialEq for Expiration<K> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}

impl<K> Eq for Expiration<K> {}

impl<K> PartialOrd for Expiration<K> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for Expiration<K> {
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
