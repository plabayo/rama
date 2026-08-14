//! What one evaluation may spend inside the host functions.
//!
//! The execution time limit can only interrupt bytecode, so work that
//! happens in a host function has to bound itself or nothing will.
//!
//! One [`PacBudgetState`] belongs to one runtime: it is created when that
//! runtime's host functions are registered and shared only with them, so
//! two runtimes never see each other's budget however they are scheduled.
//! Whoever drives a call arms it first; an unarmed state still bounds each
//! individual call, it just cannot bound a total across evaluations it
//! knows nothing about.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rama_net::address::Host;
use rama_utils::octets::{kib, mib};
use regex_automata::{
    Input,
    meta::{Cache, Regex},
};

/// Which question a lookup asked, so a cached answer is only reused for one
/// it actually answers.
///
/// The reference keys its own per-execution cache the same way — by the
/// operation, not by address family — because the two ask different things:
/// the classic functions are specified to answer in "the dot-separated
/// format", i.e. ipv4, while the `*Ex` functions were added to carry ipv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LookupKind {
    /// `dnsResolve`, `isResolvable`, `isInNet`
    Classic,
    /// `dnsResolveEx`, `isResolvableEx`, `isInNetEx`
    Extended,
}

impl LookupKind {
    /// Whether an answer to `self` also answers `asked`.
    ///
    /// Only one way round: an extended answer holds everything a classic one
    /// would, and a classic answer queried nothing about ipv6.
    fn answers(self, asked: Self) -> bool {
        self == asked || self == Self::Extended
    }
}

/// What one evaluation may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacBudget {
    /// distinct hosts resolved, across every host function that resolves a
    /// name; repeats within an evaluation are served from its own cache
    pub(crate) lookups: u32,
    /// glob comparison steps, across every `shExpMatch` call
    pub(crate) glob_steps: u64,
    /// `alert` calls written to the log
    pub(crate) alerts: u32,
    /// total wall clock the host functions may block the worker for
    ///
    /// The execution time limit is checked between bytecode slices, so it
    /// cannot interrupt a host function: without this a script could hold
    /// its worker for lookups * dns_timeout however short that limit is.
    pub(crate) blocking: Duration,
}

/// What one *call* may spend on a state nobody armed, so an un-driven
/// runtime is still bounded per call even though its total is not.
const UNARMED_GLOB_STEPS: u64 = 50_000_000;

/// How much pattern source a runtime keeps compiled, alongside the independent
/// count and compiled-memory caps below. Past a cap a pattern is still
/// matched, just not kept.
const MAX_CACHED_PATTERN_BYTES: usize = kib(64);

/// Approximate compiled heap retained by one runtime's pattern cache.
const MAX_CACHED_PATTERN_MEMORY: usize = mib(8);

/// Absolute entry bound for patterns whose engine reports little heap use.
const MAX_CACHED_PATTERNS: usize = 1_024;

/// Arms the budgets of the runtime it came from.
///
/// [`PacRuntimeBuilder`][super::PacRuntimeBuilder] hands one out with the
/// runtime it builds: call [`arm`][Self::arm] before each evaluation, as
/// [`PacResolver`][crate::PacResolver] does, or the host functions bound
/// only each individual call and not the total across one.
#[derive(Debug, Clone)]
pub struct PacBudgetHandle {
    state: std::sync::Arc<PacBudgetState>,
    budget: PacBudget,
}

impl PacBudgetHandle {
    pub(crate) fn new(state: std::sync::Arc<PacBudgetState>, budget: PacBudget) -> Self {
        Self { state, budget }
    }

    /// Give the evaluation about to run a fresh budget, dropping what the
    /// previous one cached.
    ///
    /// Must be called on the thread that will run it — for a
    /// [`JsWorker`][rama_js::JsWorker] that means inside the job.
    pub fn arm(&self) {
        self.state.arm(self.budget);
    }
}

/// One runtime's budget and the caches scoped to its current evaluation.
///
/// The host functions of a runtime hold this, and so does whoever drives
/// that runtime's calls. It is only ever touched from the thread running an
/// evaluation, so the lock is uncontended; it exists because a host function
/// must be `Sync`, not to arbitrate between threads.
#[derive(Debug, Default)]
pub(crate) struct PacBudgetState {
    inner: Mutex<Evaluation>,
}

#[derive(Debug, Default)]
struct Evaluation {
    armed: bool,
    lookups: u32,
    glob_steps: u64,
    alerts: u32,
    blocking_until: Option<Instant>,
    /// what this evaluation already resolved: the reference implementations
    /// cache per execution and count distinct hosts, so a policy testing the
    /// same host against twenty subnets costs one lookup, not twenty
    resolved: Vec<(Host, LookupKind, Vec<IpAddr>)>,
    /// resolved at most once per evaluation: enumerating interfaces is a
    /// syscall a script would otherwise repeat as fast as it can
    local_addresses: Option<Vec<IpAddr>>,
    /// patterns already compiled for this runtime's script: a real policy
    /// tests the same rules on every request, and building the automaton is
    /// the expensive half of a match
    patterns: Vec<CachedPattern>,
    cached_pattern_bytes: usize,
    cached_pattern_memory: usize,
}

#[derive(Debug)]
struct CachedPattern {
    source: String,
    compiled: Regex,
    cache: Cache,
    memory: usize,
}

impl CachedPattern {
    fn new(source: String, compiled: Regex, cache: Cache) -> Self {
        let memory = compiled.memory_usage().saturating_add(cache.memory_usage());
        Self {
            source,
            compiled,
            cache,
            memory,
        }
    }

    fn is_match(&mut self, input: &str) -> bool {
        self.compiled
            .search_with(&mut self.cache, &Input::new(input))
            .is_some()
    }
}

impl PacBudgetState {
    /// Give the evaluation about to run a fresh budget, dropping what the
    /// previous one cached.
    pub(crate) fn arm(&self, budget: PacBudget) {
        let mut state = self.inner.lock();
        state.armed = true;
        state.lookups = budget.lookups;
        state.glob_steps = budget.glob_steps;
        state.alerts = budget.alerts;
        state.blocking_until = Instant::now().checked_add(budget.blocking);
        state.resolved.clear();
        state.local_addresses = None;
        // patterns are kept: they are compiled from the script, which does not
        // change while this runtime lives, and rebuilding the automaton is the
        // expensive half of a match. The first evaluation to use one still
        // pays for building it.
    }

    /// Spend one dns lookup.
    pub(super) fn take_lookup(&self) -> bool {
        let mut state = self.inner.lock();
        if !state.armed {
            return true;
        }
        match state.lookups {
            0 => false,
            left => {
                state.lookups = left - 1;
                true
            }
        }
    }

    /// Spend one `alert` call.
    pub(super) fn take_alert(&self) -> bool {
        let mut state = self.inner.lock();
        if !state.armed {
            return true;
        }
        match state.alerts {
            0 => false,
            left => {
                state.alerts = left - 1;
                true
            }
        }
    }

    /// Glob steps available for the match about to run.
    pub(super) fn glob_steps_left(&self) -> u64 {
        let state = self.inner.lock();
        if state.armed {
            state.glob_steps
        } else {
            UNARMED_GLOB_STEPS
        }
    }

    /// Charge steps a match actually took; only an armed budget accumulates.
    pub(super) fn charge_glob_steps(&self, used: u64) {
        let mut state = self.inner.lock();
        if state.armed {
            state.glob_steps = state.glob_steps.saturating_sub(used);
        }
    }

    /// How long a host function may still block, or `None` when unarmed.
    ///
    /// `Some(ZERO)` means the evaluation has spent it all; `Some(MAX)` is an
    /// armed budget whose deadline cannot be represented and is unbounded.
    pub(super) fn blocking_left(&self) -> Option<Duration> {
        let state = self.inner.lock();
        if !state.armed {
            return None;
        }
        Some(state.blocking_until.map_or(Duration::MAX, |until| {
            until.saturating_duration_since(Instant::now())
        }))
    }

    /// The addresses this evaluation already has for `host`.
    ///
    /// A narrower answer never satisfies a wider ask: an ipv4-only lookup
    /// queried nothing about ipv6, so reusing it for an `*Ex` call would
    /// report a v6-only host as unresolvable.
    pub(super) fn resolved(&self, host: &Host, kind: LookupKind) -> Option<Vec<IpAddr>> {
        let state = self.inner.lock();
        if !state.armed {
            return None;
        }
        state
            .resolved
            .iter()
            .find(|(cached, cached_kind, _)| cached == host && cached_kind.answers(kind))
            .map(|(_, _, addresses)| addresses.clone())
    }

    /// Remember what `host` resolved to for the rest of this evaluation.
    pub(super) fn remember(&self, host: &Host, kind: LookupKind, addresses: &[IpAddr]) {
        let mut state = self.inner.lock();
        if state.armed {
            state
                .resolved
                .push((host.clone(), kind, addresses.to_vec()));
        }
    }

    /// Match with the compiled form of `pattern`, if this runtime has it.
    pub(super) fn match_compiled_pattern(&self, pattern: &str, input: &str) -> Option<bool> {
        let mut state = self.inner.lock();
        if !state.armed {
            return None;
        }
        let index = state
            .patterns
            .iter()
            .position(|cached| cached.source == pattern)?;
        let (matched, old_memory, new_memory) = {
            let cached = &mut state.patterns[index];
            let old_memory = cached.memory;
            let matched = cached.is_match(input);
            cached.memory = cached
                .compiled
                .memory_usage()
                .saturating_add(cached.cache.memory_usage());
            (matched, old_memory, cached.memory)
        };
        state.cached_pattern_memory = state
            .cached_pattern_memory
            .saturating_sub(old_memory)
            .saturating_add(new_memory);
        if state.cached_pattern_memory > MAX_CACHED_PATTERN_MEMORY {
            let evicted = state.patterns.remove(index);
            state.cached_pattern_bytes = state
                .cached_pattern_bytes
                .saturating_sub(evicted.source.len());
            state.cached_pattern_memory =
                state.cached_pattern_memory.saturating_sub(evicted.memory);
        }
        Some(matched)
    }

    /// Keep `compiled` for as long as this runtime serves its script.
    pub(super) fn remember_pattern(&self, pattern: &str, compiled: Regex, cache: Cache) {
        let mut state = self.inner.lock();
        if !state.armed {
            return;
        }
        let cached = CachedPattern::new(pattern.to_owned(), compiled, cache);
        if state.patterns.len() < MAX_CACHED_PATTERNS
            && state.cached_pattern_bytes.saturating_add(pattern.len()) <= MAX_CACHED_PATTERN_BYTES
            && state.cached_pattern_memory.saturating_add(cached.memory)
                <= MAX_CACHED_PATTERN_MEMORY
        {
            state.cached_pattern_bytes += pattern.len();
            state.cached_pattern_memory += cached.memory;
            state.patterns.push(cached);
        }
    }

    /// The evaluation's local addresses, resolving them once.
    ///
    /// Only an armed evaluation caches: without one there is no boundary at
    /// which the answer should be re-read.
    pub(super) fn local_addresses(&self, resolve: impl FnOnce() -> Vec<IpAddr>) -> Vec<IpAddr> {
        {
            let state = self.inner.lock();
            if !state.armed {
                drop(state);
                return resolve();
            }
            if let Some(cached) = state.local_addresses.clone() {
                return cached;
            }
        }

        // resolved outside the lock: enumerating interfaces is a syscall
        let addresses = resolve();
        self.inner.lock().local_addresses = Some(addresses.clone());
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: PacBudget = PacBudget {
        lookups: 2,
        glob_steps: 10,
        alerts: 2,
        blocking: Duration::from_secs(30),
    };

    #[test]
    fn an_unarmed_state_is_still_bounded_per_call() {
        let state = PacBudgetState::default();
        // nothing armed it, so lookups are the caller's business
        for _ in 0..1_000 {
            assert!(state.take_lookup());
        }
        // ... but a single match can never run away, and spending does not
        // deplete a budget nobody set
        assert_eq!(state.glob_steps_left(), UNARMED_GLOB_STEPS);
        state.charge_glob_steps(u64::MAX);
        assert_eq!(state.glob_steps_left(), UNARMED_GLOB_STEPS);
    }

    #[test]
    fn lookups_are_spendable_once_per_arming() {
        let state = PacBudgetState::default();
        state.arm(BUDGET);
        assert!(state.take_lookup());
        assert!(state.take_lookup());
        assert!(!state.take_lookup(), "the budget must run out");

        state.arm(BUDGET);
        assert!(state.take_lookup(), "arming again refills it");
    }

    #[test]
    fn alerts_are_spendable_once_per_arming() {
        let state = PacBudgetState::default();
        state.arm(BUDGET);
        assert!(state.take_alert());
        assert!(state.take_alert());
        assert!(!state.take_alert(), "the budget must run out");

        state.arm(BUDGET);
        assert!(state.take_alert(), "arming again refills it");
    }

    #[test]
    fn glob_steps_accumulate_across_calls() {
        let state = PacBudgetState::default();
        state.arm(BUDGET);
        state.charge_glob_steps(4);
        assert_eq!(state.glob_steps_left(), 6);
        state.charge_glob_steps(4);
        assert_eq!(state.glob_steps_left(), 2);
        // spending more than is left saturates instead of wrapping
        state.charge_glob_steps(100);
        assert_eq!(state.glob_steps_left(), 0);
    }

    #[test]
    fn an_unbounded_blocking_budget_stays_unbounded() {
        let state = PacBudgetState::default();
        state.arm(PacBudget {
            blocking: Duration::MAX,
            ..BUDGET
        });
        assert_eq!(state.blocking_left(), Some(Duration::MAX));
    }

    #[test]
    fn short_patterns_cannot_retain_unbounded_compiled_programs() {
        let state = PacBudgetState::default();
        state.arm(BUDGET);
        for index in 1..=128 {
            let pattern = format!(r"^a{{8000}}(?:x{{{index}}})?$");
            let compiled = Regex::new(&pattern).expect("compile counted repetition");
            let cache = compiled.create_cache();
            state.remember_pattern(&pattern, compiled, cache);
        }

        let state = state.inner.lock();
        assert!(state.patterns.len() < 128);
        assert!(state.cached_pattern_bytes < MAX_CACHED_PATTERN_BYTES);
        assert!(state.cached_pattern_memory <= MAX_CACHED_PATTERN_MEMORY);
    }

    #[test]
    fn ordinary_rule_ladders_fit_the_compiled_memory_budget() {
        let state = PacBudgetState::default();
        state.arm(BUDGET);

        for index in 0..200 {
            let pattern = format!(r"^.*\.r{index}\.corp\.example$");
            let compiled = Regex::new(&pattern).expect("compile ordinary rule");
            let mut cache = compiled.create_cache();
            let input = format!("host.r{index}.corp.example");
            let _ = compiled.search_with(&mut cache, &Input::new(&input));
            state.remember_pattern(&pattern, compiled, cache);
        }

        let state = state.inner.lock();
        assert_eq!(state.patterns.len(), 200);
        assert!(state.cached_pattern_memory <= MAX_CACHED_PATTERN_MEMORY);
    }

    #[test]
    fn one_state_never_spends_another_one_budget() {
        // the whole point of binding this to a runtime rather than a thread
        let first = PacBudgetState::default();
        let second = PacBudgetState::default();
        first.arm(BUDGET);
        second.arm(BUDGET);

        assert!(first.take_lookup());
        assert!(first.take_lookup());
        assert!(!first.take_lookup());

        assert!(second.take_lookup(), "a sibling budget is untouched");
        assert!(second.take_lookup());
        assert!(!second.take_lookup());
    }

    #[test]
    fn local_addresses_resolve_once_per_arming() {
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let resolve = || {
            calls.fetch_add(1, Ordering::Relaxed);
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        };

        let state = PacBudgetState::default();
        state.arm(BUDGET);
        let first = state.local_addresses(resolve);
        let second = state.local_addresses(resolve);
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "resolved more than once");

        state.arm(BUDGET);
        state.local_addresses(resolve);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "arming must invalidate it"
        );
    }
}
