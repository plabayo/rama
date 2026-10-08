//! Client session resumption, bound to the native context that issued each session.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    hash::Hash,
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use ahash::{HashMap, HashMapExt as _};
use moka::sync::Cache;
use parking_lot::Mutex;
use rama_boring::{
    error::ErrorStack,
    ex_data::Index,
    ssl::{
        Ssl, SslContext, SslContextBuilder, SslContextRef, SslRef, SslSession, SslSessionRef,
        SslVersion,
    },
};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};
use rama_net::address::Host;
use rama_tls::client::TlsPoolId;

use super::{
    BoringTlsConnectorConfig, TlsConnectorContext, TlsConnectorContextBuilder, TlsConnectorData,
};

/// Process-unique identity of one native client context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ContextId(u64);

// Index slots live for the process lifetime; their values belong to one context or connection.
static CONTEXT_ID: LazyLock<Result<Index<SslContext, ContextId>, ErrorStack>> =
    LazyLock::new(SslContext::new_ex_index);
static SESSION_KEY: LazyLock<Result<Index<Ssl, TlsClientSessionKey>, ErrorStack>> =
    LazyLock::new(Ssl::new_ex_index);

fn slot<T: Copy>(index: &LazyLock<Result<T, ErrorStack>>) -> Result<T, BoxError> {
    index
        .as_ref()
        .copied()
        .map_err(|error| error.clone().context("register session ex-data slot"))
}

fn context_id(context: &SslContextRef) -> Option<ContextId> {
    context.ex_data(slot(&CONTEXT_ID).ok()?).copied()
}

/// Give the context `builder` builds a process-unique identity for its sessions.
pub(super) fn identify_context(builder: &mut SslContextBuilder) -> Result<(), BoxError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    builder.set_ex_data(
        slot(&CONTEXT_ID)?,
        ContextId(NEXT.fetch_add(1, Ordering::Relaxed)),
    );
    Ok(())
}

/// Bind `ssl` to `server` before its handshake: the key its sessions are kept and resumed under.
pub(super) fn bind_session_key(
    ssl: &mut SslRef,
    server: &Host,
) -> Result<Option<TlsClientSessionKey>, BoxError> {
    let Some(context) = context_id(ssl.ssl_context()) else {
        return Ok(None);
    };
    let key = TlsClientSessionKey {
        context,
        server: server.clone(),
    };
    ssl.set_ex_data(slot(&SESSION_KEY)?, key.clone());
    Ok(Some(key))
}

/// Where a client session may resume: the context that issued it and the server it authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsClientSessionKey {
    context: ContextId,
    server: Host,
}

impl TlsClientSessionKey {
    /// The server identity the session was established with.
    #[must_use]
    pub fn server(&self) -> &Host {
        &self.server
    }
}

/// A resumable session, bound to the context and server it was established with.
#[derive(Clone)]
pub struct TlsClientSession {
    key: TlsClientSessionKey,
    session: SslSession,
}

impl TlsClientSession {
    /// Tag a session `ssl` established, under the key bound before its handshake.
    pub(super) fn established(ssl: &SslRef, session: SslSession) -> Option<Self> {
        let key = ssl.ex_data(slot(&SESSION_KEY).ok()?)?;
        (context_id(ssl.ssl_context()) == Some(key.context)).then(|| Self {
            key: key.clone(),
            session,
        })
    }

    /// The context and server this session resumes with.
    #[must_use]
    pub fn key(&self) -> &TlsClientSessionKey {
        &self.key
    }

    /// The native session.
    #[must_use]
    pub fn session(&self) -> &SslSessionRef {
        &self.session
    }

    /// Whether to offer this session at most once, as TLS 1.3 asks (RFC 8446 §C.4).
    #[must_use]
    pub fn is_single_use(&self) -> bool {
        self.session.protocol_version() == SslVersion::TLS1_3
    }

    /// Offer this session on `ssl`, which must be bound to the same context and server.
    pub fn resume_on(&self, ssl: &mut SslRef) -> Result<(), BoxError> {
        let bound = ssl.ex_data(slot(&SESSION_KEY)?);
        if bound != Some(&self.key) || context_id(ssl.ssl_context()) != Some(self.key.context) {
            return Err(BoxError::from_static_str(
                "session belongs to another context or server",
            ));
        }
        // SAFETY: the native context of `ssl` issued this session: context ids are unique,
        // and `established` tagged the session with the id of its issuing context.
        unsafe { ssl.set_session(&self.session) }.context("offer session for resumption")
    }
}

impl fmt::Debug for TlsClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClientSession")
            .field("key", &self.key)
            .field("version", &self.session.protocol_version())
            .finish()
    }
}

/// Keeps client sessions for later resumption.
///
/// A session only resumes on a connection with the same [`TlsClientSessionKey`]: the
/// connection checks this itself, so a store cannot leak sessions across connectors,
/// configurations or servers. Implementations should bound their memory.
pub trait TlsClientSessionStore: Send + Sync + 'static {
    /// Keep `session` under its [`TlsClientSession::key`].
    fn put(&self, session: TlsClientSession);

    /// Remove and return the next session to offer for `key`.
    fn take(&self, key: &TlsClientSessionKey) -> Option<TlsClientSession>;
}

/// A shared store, held by connectors and the contexts they configure.
#[derive(Clone)]
pub(super) struct SessionStore(pub(super) Arc<dyn TlsClientSessionStore>);

impl fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStore").finish_non_exhaustive()
    }
}

/// Bounded in-memory sessions: the newest few per key, evicting the least recently
/// stored key once full.
///
/// The default [`TlsClientSessionStore`], also usable for other entries.
pub struct TlsClientSessionCache<K = TlsClientSessionKey, V = TlsClientSession> {
    entries: Mutex<Entries<K, V>>,
    max_keys: NonZeroUsize,
    per_key: NonZeroUsize,
}

struct Entries<K, V> {
    slots: HashMap<K, Slot<V>>,
    by_age: BTreeMap<u64, K>,
    next_stamp: u64,
}

struct Slot<V> {
    values: VecDeque<V>,
    stamp: u64,
}

impl<K: Eq + Hash + Clone, V> TlsClientSessionCache<K, V> {
    /// Keep at most `per_key` values for each of at most `max_keys` keys.
    #[must_use]
    pub fn new(max_keys: NonZeroUsize, per_key: NonZeroUsize) -> Self {
        Self {
            entries: Mutex::new(Entries {
                slots: HashMap::new(),
                by_age: BTreeMap::new(),
                next_stamp: 0,
            }),
            max_keys,
            per_key,
        }
    }

    /// Store `value` as the newest one for `key`.
    pub fn insert(&self, key: K, value: V) {
        let mut entries = self.entries.lock();
        let Entries {
            slots,
            by_age,
            next_stamp,
        } = &mut *entries;
        let stamp = *next_stamp;
        *next_stamp += 1;
        let slot = slots.entry(key.clone()).or_insert_with(|| Slot {
            values: VecDeque::new(),
            stamp,
        });
        by_age.remove(&slot.stamp);
        slot.stamp = stamp;
        by_age.insert(stamp, key);
        slot.values.push_front(value);
        slot.values.truncate(self.per_key.get());
        while slots.len() > self.max_keys.get()
            && let Some((_, oldest)) = by_age.pop_first()
        {
            slots.remove(&oldest);
        }
    }

    /// Remove and return the newest value for `key`.
    pub fn pop(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.lock();
        let slot = entries.slots.get_mut(key)?;
        let value = slot.values.pop_front();
        if slot.values.is_empty() {
            let stamp = slot.stamp;
            entries.slots.remove(key);
            entries.by_age.remove(&stamp);
        }
        value
    }

    /// Which of `keys` holds values and was stored to most recently.
    pub fn most_recent<'k>(&self, keys: impl IntoIterator<Item = &'k K>) -> Option<&'k K>
    where
        K: 'k,
    {
        let entries = self.entries.lock();
        keys.into_iter()
            .filter_map(|key| Some((entries.slots.get(key)?.stamp, key)))
            .max_by_key(|(stamp, _)| *stamp)
            .map(|(_, key)| key)
    }

    /// The number of values held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .slots
            .values()
            .map(|slot| slot.values.len())
            .sum()
    }

    /// Whether no values are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().slots.is_empty()
    }
}

const DEFAULT_MAX_KEYS: NonZeroUsize = NonZeroUsize::new(256).unwrap();
const DEFAULT_PER_KEY: NonZeroUsize = NonZeroUsize::new(2).unwrap();

impl Default for TlsClientSessionCache {
    /// Two sessions for each of 256 server identities and configurations.
    fn default() -> Self {
        Self::new(DEFAULT_MAX_KEYS, DEFAULT_PER_KEY)
    }
}

impl<K, V> fmt::Debug for TlsClientSessionCache<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClientSessionCache")
            .field("max_keys", &self.max_keys)
            .field("per_key", &self.per_key)
            .finish_non_exhaustive()
    }
}

impl TlsClientSessionStore for TlsClientSessionCache {
    fn put(&self, session: TlsClientSession) {
        self.insert(session.key().clone(), session);
    }

    // BoringSSL itself never offers an expired session.
    fn take(&self, key: &TlsClientSessionKey) -> Option<TlsClientSession> {
        self.pop(key)
    }
}

/// A connector's sessions, with one native context per effective configuration to resume them in.
pub(super) struct ConnectorSessions {
    store: Arc<dyn TlsClientSessionStore>,
    contexts: Cache<Option<TlsPoolId>, TlsConnectorContext>,
}

impl ConnectorSessions {
    const MAX_CONTEXTS: u64 = 64;

    pub(super) fn new(store: Arc<dyn TlsClientSessionStore>) -> Self {
        Self {
            store,
            contexts: Cache::new(Self::MAX_CONTEXTS),
        }
    }

    /// Connection state from the context kept for `config`, which only an identical
    /// configuration shares. Configurations without a reusable identity get a fresh
    /// context, so their sessions never resume.
    pub(super) fn connector_data(
        &self,
        config: BoringTlsConnectorConfig<'_>,
    ) -> Result<TlsConnectorData, BoxError> {
        let identity = config.pool_id();
        if identity.as_ref().is_some_and(|id| !id.is_reusable()) {
            return TlsConnectorData::try_from(config);
        }
        if let Some(context) = self.contexts.get(&identity) {
            return context.configure();
        }
        let mut builder = TlsConnectorContextBuilder::try_from(config)?;
        builder.set_session_store(self.store.clone());
        self.contexts
            .entry(identity)
            .or_insert(builder.build())
            .into_value()
            .configure()
    }
}

impl fmt::Debug for ConnectorSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectorSessions")
            .field("contexts", &self.contexts.entry_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
