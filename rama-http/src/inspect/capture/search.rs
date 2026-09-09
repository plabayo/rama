#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    any::TypeId,
    collections::{BTreeMap, VecDeque},
    ops::Bound::{Excluded, Unbounded},
    sync::{Arc, Weak},
    time::Duration,
};

use rama_core::{error::BoxError, telemetry::tracing};
pub(super) use rama_inspect::search::matches_display;
use tokio::{sync::Mutex, time::Instant};

const MAX_CACHED_SEARCHES: usize = 16;

/// Limit outage reporting across queries, exchanges and protocol record kinds.
/// Successful reads do not reset the gate: partial outages must not fan out either.
#[derive(Default)]
pub(super) struct SearchWarnings {
    next: parking_lot::Mutex<Option<Instant>>,
    #[cfg(test)]
    pub(super) emitted: AtomicUsize,
}

impl SearchWarnings {
    fn warn(&self, error: &BoxError) {
        let now = Instant::now();
        {
            let mut next = self.next.lock();
            if next.is_some_and(|deadline| now < deadline) {
                return;
            }
            *next = Some(now + Duration::from_secs(30));
        }

        #[cfg(test)]
        self.emitted.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%error, "capture search results are incomplete; backing off failed reads");
    }
}

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
    failed: BTreeMap<usize, ReadRetry>,
}

struct ReadRetry {
    attempts: u8,
    after: Instant,
}

impl SearchCursor {
    pub(super) async fn matches<F, Fut>(
        &mut self,
        count: usize,
        warnings: &SearchWarnings,
        mut read: F,
    ) -> bool
    where
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<bool, BoxError>>,
    {
        let mut after = Unbounded;
        while let Some((index, retry_at)) = self
            .failed
            .range((after, Unbounded))
            .next()
            .map(|(&index, retry)| (index, retry.after))
        {
            after = Excluded(index);
            if Instant::now() < retry_at {
                continue;
            }
            let result = read(index).await;
            if self.complete(index, result, warnings) {
                return true;
            }
        }
        while self.next < count {
            let index = self.next;
            let result = read(index).await;
            // Nothing advances before a read finishes, so cancellation retries it.
            self.next += 1;
            if self.complete(index, result, warnings) {
                return true;
            }
        }
        false
    }

    fn complete(
        &mut self,
        index: usize,
        result: Result<bool, BoxError>,
        warnings: &SearchWarnings,
    ) -> bool {
        match result {
            Ok(matched) => {
                self.failed.remove(&index);
                matched
            }
            Err(error) => {
                let retry = self.failed.entry(index).or_insert(ReadRetry {
                    attempts: 0,
                    after: Instant::now(),
                });
                retry.attempts = retry.attempts.saturating_add(1);
                let delay = Duration::from_millis(250)
                    .saturating_mul(1 << (retry.attempts - 1).min(7))
                    .min(Duration::from_secs(30));
                retry.after = Instant::now() + delay;
                tracing::debug!(record_index = index, %error, retry_delay = ?delay,
                    "capture search record unavailable");
                if retry.attempts >= 3 {
                    warnings.warn(&error);
                }
                false
            }
        }
    }
}
