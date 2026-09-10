//! Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections

use std::{
    collections::VecDeque,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
};

use lru_slab::LruSlab;
use rama_core::bytes::Bytes;
use rama_core::telemetry::tracing::trace;

use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;

use crate::proto::token::TokenStore;

/// `TokenStore` implementation that stores up to `N` tokens per server name for up to a
/// limited number of server names, in-memory
#[derive(Debug)]
pub struct TokenMemoryCache(Mutex<State>);

impl TokenMemoryCache {
    /// Construct empty
    pub(crate) fn new(max_server_names: u32, max_tokens_per_server: usize) -> Self {
        Self(Mutex::new(State::new(
            max_server_names,
            max_tokens_per_server,
        )))
    }
}

impl TokenStore for TokenMemoryCache {
    fn insert(&self, server_name: &str, token: Bytes) {
        trace!(%server_name, "storing token");
        self.0.lock().store(server_name, token)
    }

    fn take(&self, server_name: &str) -> Option<Bytes> {
        let token = self.0.lock().take(server_name);
        trace!(%server_name, found=%token.is_some(), "taking token");
        token
    }
}

/// Defaults to a maximum of 256 servers and 2 tokens per server
impl Default for TokenMemoryCache {
    fn default() -> Self {
        Self::new(256, 2)
    }
}

/// Lockable inner state of `TokenMemoryCache`
#[derive(Debug)]
struct State {
    /// `None` disables the cache: a zero server or token limit stores nothing.
    limits: Option<Limits>,
    // map from server name to index in lru
    lookup: HashMap<Arc<str>, u32>,
    lru: LruSlab<CacheEntry>,
}

/// Non-zero capacity of an enabled cache.
#[derive(Debug, Clone, Copy)]
struct Limits {
    server_names: NonZeroU32,
    tokens_per_server: NonZeroUsize,
}

impl State {
    fn new(max_server_names: u32, max_tokens_per_server: usize) -> Self {
        Self {
            limits: NonZeroU32::new(max_server_names)
                .zip(NonZeroUsize::new(max_tokens_per_server))
                .map(|(server_names, tokens_per_server)| Limits {
                    server_names,
                    tokens_per_server,
                }),
            lookup: HashMap::new(),
            lru: LruSlab::default(),
        }
    }

    fn store(&mut self, server_name: &str, token: Bytes) {
        let Some(limits) = self.limits else {
            return;
        };
        if let Some(&slot) = self.lookup.get(server_name) {
            // known server: the entry becomes most recent and takes the newest token
            self.lru
                .get_mut(slot)
                .tokens
                .push_newest(token, limits.tokens_per_server);
            return;
        }
        // new server: make room first, then insert into both the slab and the lookup together
        if self.lru.len() >= limits.server_names.get()
            && let Some(oldest) = self.lru.lru()
        {
            self.remove_entry(oldest);
        }
        let server_name = Arc::<str>::from(server_name);
        let slot = self.lru.insert(CacheEntry {
            server_name: server_name.clone(),
            tokens: Tokens::single(token),
        });
        self.lookup.insert(server_name, slot);
    }

    fn take(&mut self, server_name: &str) -> Option<Bytes> {
        let slot = *self.lookup.get(server_name)?;
        // `get_mut` marks the entry most recently used
        match self.lru.get_mut(slot).tokens.pop_oldest() {
            Some(token) => Some(token),
            // the last token leaves with its entry
            None => Some(self.remove_entry(slot).tokens.into_last()),
        }
    }

    /// Remove an entry from the slab and the lookup as one operation.
    fn remove_entry(&mut self, slot: u32) -> CacheEntry {
        let entry = self.lru.remove(slot);
        let removed = self.lookup.remove(&entry.server_name);
        debug_assert_eq!(removed, Some(slot));
        entry
    }
}

/// Cache entry within `TokenMemoryCache`'s LRU slab
#[derive(Debug)]
struct CacheEntry {
    server_name: Arc<str>,
    tokens: Tokens,
}

/// The tokens of one server, oldest first; structurally never empty.
#[derive(Debug)]
struct Tokens {
    oldest: Bytes,
    newer: VecDeque<Bytes>,
}

impl Tokens {
    fn single(token: Bytes) -> Self {
        Self {
            oldest: token,
            newer: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        1 + self.newer.len()
    }

    /// Append the newest token, evicting the oldest when `max` tokens are already held.
    fn push_newest(&mut self, token: Bytes, max: NonZeroUsize) {
        if self.len() >= max.get() {
            if let Some(next) = self.newer.pop_front() {
                self.oldest = next
            } else {
                self.oldest = token;
                return;
            }
        }
        self.newer.push_back(token);
    }

    /// Take the oldest token while at least one remains; `None` means the last token can only
    /// leave together with its owner via [`into_last`](Self::into_last).
    fn pop_oldest(&mut self) -> Option<Bytes> {
        let next = self.newer.pop_front()?;
        Some(std::mem::replace(&mut self.oldest, next))
    }

    /// Consume the last token.
    fn into_last(self) -> Bytes {
        debug_assert!(self.newer.is_empty(), "into_last on a multi-token entry");
        self.oldest
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use rand::prelude::*;
    use rand_pcg::Pcg32;

    fn new_rng() -> impl Rng {
        Pcg32::new(0xdeadbeefdeadbeef, 0xdeadbeefdeadbeef)
    }

    /// Reference model: a list ordered least to most recently used, each server with its tokens
    /// oldest first. Store and take both make a server most recent.
    fn run_model(max_servers: usize, max_tokens: usize, names: u32, steps: usize) {
        let mut rng = new_rng();
        for _ in 0..10 {
            let mut model: Vec<(u32, VecDeque<Bytes>)> = Vec::new();
            let cache = TokenMemoryCache::new(max_servers as u32, max_tokens);
            let mut evicted_servers = 0;
            let mut evicted_tokens = 0;

            for i in 0..steps {
                let server_name = rng.random::<u32>() % names;
                if rng.random_bool(0.666) {
                    let token = Bytes::from(vec![(i % 251) as u8, (i / 251) as u8]);
                    if let Some(j) = model.iter().position(|(s, _)| *s == server_name) {
                        let (_, mut queue) = model.remove(j);
                        queue.push_back(token.clone());
                        if queue.len() > max_tokens {
                            queue.pop_front();
                            evicted_tokens += 1;
                        }
                        model.push((server_name, queue));
                    } else {
                        model.push((server_name, VecDeque::from([token.clone()])));
                        if model.len() > max_servers {
                            model.remove(0);
                            evicted_servers += 1;
                        }
                    }
                    cache.insert(&server_name.to_string(), token);
                } else {
                    let expecting = model.iter().position(|(s, _)| *s == server_name).map(|j| {
                        let (_, mut queue) = model.remove(j);
                        let token = queue.pop_front().unwrap();
                        if !queue.is_empty() {
                            model.push((server_name, queue));
                        }
                        token
                    });
                    assert_eq!(
                        cache.take(&server_name.to_string()),
                        expecting,
                        "servers {max_servers} tokens {max_tokens} step {i}"
                    );
                }
                let state = cache.0.lock();
                assert_eq!(state.lru.len() as usize, model.len());
                assert_eq!(state.lookup.len(), model.len());
                assert!(state.lru.len() as usize <= max_servers);
                for (name, queue) in &model {
                    let slot = state.lookup[name.to_string().as_str()];
                    assert_eq!(state.lru.peek(slot).tokens.len(), queue.len());
                }
            }
            if names as usize > max_servers {
                assert!(evicted_servers > 0, "trace must cross the server limit");
            }
            assert!(evicted_tokens > 0, "trace must cross the token limit");
        }
    }

    #[test]
    fn model_wide_cache() {
        run_model(20, 2, 10, 200);
    }

    #[test]
    fn model_small_caches_cross_both_limits() {
        run_model(2, 1, 4, 300);
        run_model(2, 2, 3, 300);
        run_model(3, 2, 5, 300);
        run_model(1, 1, 3, 200);
        run_model(1, 3, 2, 200);
    }

    #[test]
    fn take_refreshes_recency_and_slots_are_reused() {
        let cache = TokenMemoryCache::new(2, 2);
        cache.insert("a", Bytes::from_static(b"a1"));
        cache.insert("a", Bytes::from_static(b"a2"));
        cache.insert("b", Bytes::from_static(b"b1"));
        // taking from `a` makes it most recent, so a third server evicts `b`
        assert_eq!(cache.take("a"), Some(Bytes::from_static(b"a1")));
        cache.insert("c", Bytes::from_static(b"c1"));
        assert_eq!(cache.take("b"), None);
        assert_eq!(cache.take("a"), Some(Bytes::from_static(b"a2")));
        assert_eq!(
            cache.take("a"),
            None,
            "the last token leaves with its entry"
        );
        let slots: Vec<u32> = cache.0.lock().lookup.values().copied().collect();
        assert_eq!(slots.len(), 1);
        // reinserting `a` reuses a freed slot and the cache keeps working at the limit
        cache.insert("a", Bytes::from_static(b"a3"));
        assert!(cache.0.lock().lru.len() == 2);
        assert_eq!(cache.take("c"), Some(Bytes::from_static(b"c1")));
        assert_eq!(cache.take("a"), Some(Bytes::from_static(b"a3")));
        assert!(cache.0.lock().lru.is_empty());
        assert!(cache.0.lock().lookup.is_empty());
    }

    #[test]
    fn single_token_limit_keeps_the_newest() {
        let cache = TokenMemoryCache::new(4, 1);
        cache.insert("a", Bytes::from_static(b"old"));
        cache.insert("a", Bytes::from_static(b"new"));
        assert_eq!(cache.take("a"), Some(Bytes::from_static(b"new")));
        assert_eq!(cache.take("a"), None);
    }

    #[test]
    fn zero_max_server_names() {
        // test that this edge case doesn't panic
        let cache = TokenMemoryCache::new(0, 2);
        for i in 0..10 {
            cache.insert(&i.to_string(), Bytes::from(vec![i]));
            for j in 0..10 {
                assert!(cache.take(&j.to_string()).is_none());
            }
        }
    }

    #[test]
    fn zero_queue_length() {
        // test that this edge case doesn't panic
        let cache = TokenMemoryCache::new(256, 0);
        for i in 0..10 {
            cache.insert(&i.to_string(), Bytes::from(vec![i]));
            for j in 0..10 {
                assert!(cache.take(&j.to_string()).is_none());
            }
        }
    }
}
