//! What one evaluation may spend inside the host functions.
//!
//! The execution time limit can only interrupt bytecode, so work that
//! happens in a host function has to bound itself or nothing will. These
//! budgets are per evaluation and thread-local: a worker owns one thread,
//! and whoever drives the call arms them first.
//!
//! An unarmed thread still bounds each individual call — no single call may
//! run away — but it cannot bound a total across evaluations it knows
//! nothing about. An embedder driving a runtime itself therefore owns the
//! question of how *often* a script may ask.

use std::cell::{Cell, RefCell};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rama_net::address::Host;
use rama_utils::thirdparty::regex::Regex;

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

/// What one *call* may spend on a thread nobody armed, so an un-driven
/// runtime is still bounded per call even though its total is not.
const UNARMED_GLOB_STEPS: u64 = 50_000_000;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static LOOKUPS: Cell<u32> = const { Cell::new(0) };
    static GLOB_STEPS: Cell<u64> = const { Cell::new(0) };
    static ALERTS: Cell<u32> = const { Cell::new(0) };
    static BLOCKING_UNTIL: Cell<Option<Instant>> = const { Cell::new(None) };
    /// what this evaluation already resolved: the reference implementations
    /// cache per execution and count distinct hosts, so a policy testing the
    /// same host against twenty subnets costs one lookup, not twenty
    static RESOLVED: RefCell<Vec<(Host, Vec<IpAddr>)>> = const { RefCell::new(Vec::new()) };
    /// resolved at most once per evaluation: enumerating interfaces is a
    /// syscall a script would otherwise repeat as fast as it can
    static LOCAL_ADDRESSES: RefCell<Option<Vec<IpAddr>>> = const { RefCell::new(None) };
    /// patterns already compiled for this evaluation: a real policy tests the
    /// same handful of rules per request, and building the automaton is the
    /// expensive half of a match
    static PATTERNS: RefCell<Vec<(String, Regex)>> = const { RefCell::new(Vec::new()) };
}

/// Give the evaluation about to run on this thread a fresh budget.
pub(crate) fn arm(budget: PacBudget) {
    ARMED.set(true);
    LOOKUPS.set(budget.lookups);
    GLOB_STEPS.set(budget.glob_steps);
    ALERTS.set(budget.alerts);
    BLOCKING_UNTIL.set(Instant::now().checked_add(budget.blocking));
    LOCAL_ADDRESSES.replace(None);
    RESOLVED.with_borrow_mut(Vec::clear);
    PATTERNS.with_borrow_mut(Vec::clear);
}

/// Most patterns kept compiled for one evaluation. Past this a pattern is
/// still matched, it just does not displace the ones a real policy reuses.
const MAX_CACHED_PATTERNS: usize = 64;

/// The compiled form of `pattern`, if this evaluation built it already.
pub(super) fn compiled_pattern(pattern: &str) -> Option<Regex> {
    if !ARMED.get() {
        return None;
    }
    PATTERNS.with_borrow(|cache| {
        cache
            .iter()
            .find(|(cached, _)| cached == pattern)
            .map(|(_, compiled)| compiled.clone())
    })
}

/// Keep `compiled` for the rest of this evaluation.
pub(super) fn remember_pattern(pattern: &str, compiled: &Regex) {
    if !ARMED.get() {
        return;
    }
    PATTERNS.with_borrow_mut(|cache| {
        if cache.len() < MAX_CACHED_PATTERNS {
            cache.push((pattern.to_owned(), compiled.clone()));
        }
    });
}

/// Spend one `alert` call.
pub(super) fn take_alert() -> bool {
    if !ARMED.get() {
        return true;
    }
    ALERTS.with(|budget| match budget.get() {
        0 => false,
        left => {
            budget.set(left - 1);
            true
        }
    })
}

/// How long a host function may still block, or `None` when unarmed.
///
/// `Some(ZERO)` means the evaluation has spent it all.
pub(super) fn blocking_left() -> Option<Duration> {
    if !ARMED.get() {
        return None;
    }
    Some(BLOCKING_UNTIL.get().map_or(Duration::ZERO, |until| {
        until.saturating_duration_since(Instant::now())
    }))
}

/// The addresses this evaluation already has for `host`.
pub(super) fn resolved(host: &Host) -> Option<Vec<IpAddr>> {
    if !ARMED.get() {
        return None;
    }
    RESOLVED.with_borrow(|cache| {
        cache
            .iter()
            .find(|(cached, _)| cached == host)
            .map(|(_, addresses)| addresses.clone())
    })
}

/// Remember what `host` resolved to for the rest of this evaluation.
pub(super) fn remember(host: &Host, addresses: &[IpAddr]) {
    if !ARMED.get() {
        return;
    }
    RESOLVED.with_borrow_mut(|cache| cache.push((host.clone(), addresses.to_vec())));
}

/// Spend one dns lookup.
pub(super) fn take_lookup() -> bool {
    if !ARMED.get() {
        return true;
    }
    LOOKUPS.with(|budget| match budget.get() {
        0 => false,
        left => {
            budget.set(left - 1);
            true
        }
    })
}

/// Glob steps available for the match about to run.
pub(super) fn glob_steps_left() -> u64 {
    if ARMED.get() {
        GLOB_STEPS.get()
    } else {
        UNARMED_GLOB_STEPS
    }
}

/// Charge steps a match actually took; only an armed budget accumulates.
pub(super) fn charge_glob_steps(used: u64) {
    if !ARMED.get() {
        return;
    }
    GLOB_STEPS.with(|budget| budget.set(budget.get().saturating_sub(used)));
}

/// The evaluation's local addresses, resolving them once.
///
/// Only an armed evaluation caches: without one there is no boundary at
/// which the answer should be re-read.
pub(super) fn local_addresses(resolve: impl FnOnce() -> Vec<IpAddr>) -> Vec<IpAddr> {
    if !ARMED.get() {
        return resolve();
    }
    if let Some(cached) = LOCAL_ADDRESSES.with_borrow(|cached| cached.clone()) {
        return cached;
    }
    let addresses = resolve();
    LOCAL_ADDRESSES.replace(Some(addresses.clone()));
    addresses
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
    fn an_unarmed_thread_is_still_bounded_per_call() {
        // nothing armed this thread, so lookups are the caller's business
        for _ in 0..1_000 {
            assert!(take_lookup());
        }
        // ... but a single match can never run away, and spending does not
        // deplete a budget nobody set
        assert_eq!(glob_steps_left(), UNARMED_GLOB_STEPS);
        charge_glob_steps(u64::MAX);
        assert_eq!(glob_steps_left(), UNARMED_GLOB_STEPS);
    }

    #[test]
    fn lookups_are_spendable_once_per_arming() {
        arm(BUDGET);
        assert!(take_lookup());
        assert!(take_lookup());
        assert!(!take_lookup(), "the budget must run out");

        arm(BUDGET);
        assert!(take_lookup(), "arming again refills it");
    }

    #[test]
    fn glob_steps_accumulate_across_calls() {
        arm(BUDGET);
        charge_glob_steps(4);
        assert_eq!(glob_steps_left(), 6);
        charge_glob_steps(4);
        assert_eq!(glob_steps_left(), 2);
        // spending more than is left saturates instead of wrapping
        charge_glob_steps(100);
        assert_eq!(glob_steps_left(), 0);
    }

    #[test]
    fn local_addresses_resolve_once_per_arming() {
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALLS: AtomicUsize = AtomicUsize::new(0);
        let resolve = || {
            CALLS.fetch_add(1, Ordering::Relaxed);
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        };

        arm(BUDGET);
        let first = local_addresses(resolve);
        let second = local_addresses(resolve);
        assert_eq!(first, second);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1, "resolved more than once");

        arm(BUDGET);
        local_addresses(resolve);
        assert_eq!(
            CALLS.load(Ordering::Relaxed),
            2,
            "arming must invalidate it"
        );
    }
}
