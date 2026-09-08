use rama_core::{error::BoxError, telemetry::tracing};
pub(super) use rama_inspect::search::matches_display;
use std::{
    any::TypeId,
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    ops::Bound::{Excluded, Unbounded},
    sync::{Arc, Weak},
};
use tokio::sync::Mutex;

const MAX_CACHED_SEARCHES: usize = 16;

/// Resolve the textual needle once per snapshot. Exchanges use its identity only.
#[derive(Default)]
pub(super) struct SearchCaches {
    pub(super) entries: VecDeque<Arc<SearchQuery>>,
    #[cfg(test)]
    pub(super) lookups: usize,
}
pub(super) struct SearchQuery {
    pub(super) needle: Box<str>,
}
impl SearchCaches {
    pub(super) fn get_or_insert(&mut self, needle: &str) -> Arc<SearchQuery> {
        #[cfg(test)]
        {
            self.lookups += 1;
        }
        let index = self
            .entries
            .iter()
            .position(|query| query.needle.as_ref() == needle);
        let query = index
            .and_then(|index| self.entries.remove(index))
            .unwrap_or_else(|| {
                Arc::new(SearchQuery {
                    needle: needle.into(),
                })
            });
        if self.entries.len() == MAX_CACHED_SEARCHES {
            self.entries.pop_front();
        }
        self.entries.push_back(query.clone());
        query
    }
}

/// Progress belongs to its exchange, including while an export pins that exchange.
/// Evicting an exchange leaves no progress behind in a store-wide results map.
#[derive(Default)]
pub(super) struct ExchangeSearches {
    entries: VecDeque<(Weak<SearchQuery>, Arc<Mutex<SearchProgress>>)>,
}
impl ExchangeSearches {
    pub(super) fn get_or_insert(&mut self, query: &Arc<SearchQuery>) -> Arc<Mutex<SearchProgress>> {
        self.entries.retain(|(query, _)| query.strong_count() != 0);
        let index = self
            .entries
            .iter()
            .position(|(key, _)| key.as_ptr() == Arc::as_ptr(query));
        let entry = index
            .and_then(|index| self.entries.remove(index))
            .unwrap_or_else(|| (Arc::downgrade(query), Arc::default()));
        let progress = entry.1.clone();
        if self.entries.len() == MAX_CACHED_SEARCHES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
        progress
    }
}

#[derive(Default)]
pub(super) struct SearchProgress {
    pub(super) records: SearchCursor,
    pub(super) extensions: BTreeMap<TypeId, SearchCursor>,
    pub(super) matched: bool,
}
#[derive(Default)]
pub(super) struct SearchCursor {
    next: usize,
    // Only errors need retry bookkeeping. Successful immutable records are never
    // reread, even when an earlier record remains unavailable across snapshots.
    failed: BTreeSet<usize>,
}
impl SearchCursor {
    pub(super) async fn matches<F, Fut>(&mut self, count: usize, mut read: F) -> bool
    where
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<bool, BoxError>>,
    {
        let mut after = Unbounded;
        while let Some(index) = self.failed.range((after, Unbounded)).next().copied() {
            after = Excluded(index);
            let result = read(index).await;
            if self.complete(index, result) {
                return true;
            }
        }
        while self.next < count {
            let index = self.next;
            let result = read(index).await;
            // Nothing advances before a read finishes, so cancellation retries it.
            self.next += 1;
            if self.complete(index, result) {
                return true;
            }
        }
        false
    }
    fn complete(&mut self, index: usize, result: Result<bool, BoxError>) -> bool {
        match result {
            Ok(matched) => {
                self.failed.remove(&index);
                matched
            }
            Err(error) => {
                self.failed.insert(index);
                tracing::debug!(record_index = index, %error, "capture search record unavailable; retrying next snapshot");
                false
            }
        }
    }
}
