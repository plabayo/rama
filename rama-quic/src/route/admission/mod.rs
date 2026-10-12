use std::{error::Error, fmt, net::IpAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use ahash::HashMap;
use parking_lot::Mutex;
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};
use tokio::time::Instant;

/// Trusted ingress tuple. Different egress targets do not make the same
/// incoming datagrams distinguishable, so the target is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssociationKey {
    /// Local destination of the incoming UDP association.
    pub ingress: SocketAddress,
    /// Remote sender whose packets belong to this association.
    pub peer: SocketAddress,
}

/// Shared bounds applied before Initial parsing or key derivation.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionLimits {
    /// Maximum simultaneously retained association permits across all sources.
    pub active: NonZeroUsize,
    /// Maximum simultaneous permits for one canonical source IP.
    pub active_per_source: NonZeroUsize,
    /// Number of source IPs retained for active routes or rate history.
    pub sources: NonZeroUsize,
    /// Active and quarantined tuples combined.
    pub tuples: NonZeroUsize,
    /// Successful starts across all sources in one fixed window.
    pub starts_per_window: NonZeroUsize,
    /// Successful starts from one canonical source IP in its fixed window.
    pub starts_per_source_window: NonZeroUsize,
    /// Fixed-window start-rate accounting. Must be nonzero.
    pub window: Duration,
    /// A closed tuple cannot immediately admit delayed traffic as a new route.
    /// Must be nonzero; applications also keep their trusted target binding stable.
    pub quarantine: Duration,
}

/// Admission fails before allocating capture buffers or invoking protocol code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// A time window is zero or cannot be represented by the clock.
    InvalidLimits,
    /// The policy domain already retains its maximum active associations.
    ActiveLimit,
    /// This source IP already retains its maximum active associations.
    SourceLimit,
    /// Source or tuple history has reached its configured capacity.
    HistoryLimit,
    /// The source or policy domain exhausted its current start window.
    RateLimit,
    /// The exact ingress/peer tuple is active or remains quarantined.
    TupleInUse,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid QUIC route admission limits",
            Self::ActiveLimit => "QUIC route active association limit",
            Self::SourceLimit => "QUIC route source association limit",
            Self::HistoryLimit => "QUIC route admission history limit",
            Self::RateLimit => "QUIC route start rate limit",
            Self::TupleInUse => "QUIC route tuple active or quarantined",
        })
    }
}

impl Error for AdmissionError {}

/// Cloneable admission shared by every listener/route in one policy domain.
/// Ordinary endpoints allocate none of this state unless routing is enabled.
#[derive(Debug, Clone)]
pub struct Admission(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    limits: AdmissionLimits,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    active: usize,
    global: Rate,
    sources: HashMap<IpAddr, Source>,
    tuples: HashMap<AssociationKey, Option<Instant>>,
}

#[derive(Debug)]
struct Source {
    active: usize,
    rate: Rate,
}

#[derive(Debug)]
struct Rate {
    since: Instant,
    used: usize,
}

impl Rate {
    fn refresh(&mut self, now: Instant, window: Duration) {
        if now.saturating_duration_since(self.since) >= window {
            self.since = now;
            self.used = 0;
        }
    }
}

impl Admission {
    pub fn new(limits: AdmissionLimits) -> Result<Self, AdmissionError> {
        let now = Instant::now();
        if limits.window.is_zero()
            || limits.quarantine.is_zero()
            || now.checked_add(limits.window).is_none()
            || now.checked_add(limits.quarantine).is_none()
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(Self(Arc::new(Inner {
            limits,
            state: Mutex::new(State {
                active: 0,
                global: Rate {
                    since: now,
                    used: 0,
                },
                sources: HashMap::default(),
                tuples: HashMap::default(),
            }),
        })))
    }

    /// Reserve a fixed tuple. Failures consume no slot or rate token. IP-mapped
    /// IPv6 and IPv4 forms share their source and tuple limits.
    pub fn try_acquire(&self, key: AssociationKey) -> Result<AssociationPermit, AdmissionError> {
        let key = AssociationKey {
            ingress: key.ingress.into_canonical_ip_addr(),
            peer: key.peer.into_canonical_ip_addr(),
        };
        let now = Instant::now();
        let limits = self.0.limits;
        let mut state = self.0.state.lock();
        state.global.refresh(now, limits.window);
        // The history maps have explicit finite caps. Pruning cannot grow with
        // lifetime traffic, and inactive sources retain their rate window.
        state
            .tuples
            .retain(|_, expires| expires.is_none_or(|expires| now < expires));
        state.sources.retain(|_, source| {
            source.rate.refresh(now, limits.window);
            source.active != 0 || source.rate.used != 0
        });
        if state.tuples.contains_key(&key) {
            return Err(AdmissionError::TupleInUse);
        }
        if state.active >= limits.active.get() {
            return Err(AdmissionError::ActiveLimit);
        }
        let source_ip = key.peer.ip_addr;
        let source = state.sources.get(&source_ip);
        if source.is_some_and(|source| source.active >= limits.active_per_source.get()) {
            return Err(AdmissionError::SourceLimit);
        }
        if state.tuples.len() >= limits.tuples.get()
            || (source.is_none() && state.sources.len() >= limits.sources.get())
        {
            return Err(AdmissionError::HistoryLimit);
        }
        if state.global.used >= limits.starts_per_window.get()
            || source
                .is_some_and(|source| source.rate.used >= limits.starts_per_source_window.get())
        {
            return Err(AdmissionError::RateLimit);
        }

        state.active += 1;
        state.global.used += 1;
        let source = state.sources.entry(source_ip).or_insert(Source {
            active: 0,
            rate: Rate {
                since: now,
                used: 0,
            },
        });
        source.active += 1;
        source.rate.used += 1;
        state.tuples.insert(key, None);
        Ok(AssociationPermit {
            owner: self.0.clone(),
            key,
        })
    }
}

/// Unique ownership of an admitted tuple. Retain it until all receive/send
/// handles for that association are gone. Dropping it releases active credit
/// and starts tuple quarantine; rate history survives cancellation.
#[derive(Debug)]
pub struct AssociationPermit {
    owner: Arc<Inner>,
    key: AssociationKey,
}

impl Drop for AssociationPermit {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock();
        state.active -= 1;
        if let Some(source) = state.sources.get_mut(&self.key.peer.ip_addr) {
            source.active -= 1;
        }
        // Checked at construction; a clock near its representable limit keeps
        // the tuple reserved rather than allowing an early reuse.
        state.tuples.insert(
            self.key,
            Instant::now().checked_add(self.owner.limits.quarantine),
        );
    }
}

#[cfg(test)]
mod tests;
