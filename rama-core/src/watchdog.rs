//! Process-global runtime watchdog.
//!
//! Long-running async services can wedge in subtle ways: a synchronous
//! blocking call inside a hot path, a deadlock between two tasks awaiting each
//! other, or a starved tokio executor under load. When that happens, in-runtime
//! supervision (timers, [`crate::graceful::Shutdown`] cancellation,
//! `tokio::time::sleep`) cannot fire because the very executor that would run
//! it is itself stalled.
//!
//! This module provides a watchdog that runs on a dedicated **OS thread** —
//! never on a tokio executor — and observes one or more heartbeats. When a
//! heartbeat goes stale it invokes a registered abort callback, typically wired
//! to a graceful shutdown signal that cascades to per-flow cancellations.
//!
//! # Single shared thread
//!
//! All registrations share a single [`std::thread`]. The thread starts on the
//! first registration and stays alive for the lifetime of the process (it is
//! cheap when idle). Subsequent registrations attach to the same thread.
//!
//! # Heartbeat semantics
//!
//! The producer is expected to update the heartbeat (`Arc<AtomicU64>`) at the
//! liveness signal of its choice — for an L4 proxy, "completed handler
//! decision" is a good choice because it directly catches the wedge mode the
//! watchdog defends against. The value is `Instant`-derived nanoseconds; the
//! watchdog compares it against [`Instant::now`].
//!
//! Helpers [`record_heartbeat`] and [`heartbeat_now`] capture the current
//! instant in the wire format expected by the watchdog.
//!
//! # When NOT to use this
//!
//! - Don't use it as a substitute for fixing the underlying wedge cause; it's
//!   a recovery mechanism, not a design tool.
//! - Don't enable it under a debugger or interactive testing — set up your
//!   environment so the watchdog is constructed only in production builds.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicU64;
//! use std::time::Duration;
//! use rama_core::watchdog::{WatchdogConfig, register_watchdog, record_heartbeat};
//!
//! let heartbeat = Arc::new(AtomicU64::new(0));
//! let hb_for_cb = heartbeat.clone();
//! let _registration = register_watchdog(
//!     "my-engine".into(),
//!     WatchdogConfig {
//!         stale_threshold: Duration::from_secs(5),
//!         check_interval: Duration::from_millis(500),
//!     },
//!     heartbeat.clone(),
//!     Box::new(move || {
//!         eprintln!("watchdog fired; aborting");
//!     }),
//! );
//!
//! // From the hot path:
//! record_heartbeat(&hb_for_cb);
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::telemetry::tracing;

/// Configuration for a watchdog registration.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogConfig {
    /// How long a heartbeat may go without an update before the watchdog
    /// considers it stale and fires the abort callback.
    pub stale_threshold: Duration,
    /// How often the watchdog wakes up to check heartbeats. Defaults to half
    /// the stale threshold when not explicitly chosen.
    pub check_interval: Duration,
}

impl WatchdogConfig {
    /// Create a config with `stale_threshold` and a derived
    /// `check_interval` of `stale_threshold / 2` (clamped to at least 100ms).
    #[must_use]
    pub fn from_threshold(stale_threshold: Duration) -> Self {
        let check_interval = (stale_threshold / 2).max(Duration::from_millis(100));
        Self {
            stale_threshold,
            check_interval,
        }
    }
}

/// Capture the current instant in the wire format expected by [`Watchdog`]
/// heartbeat atomics.
#[inline]
#[must_use]
pub fn heartbeat_now() -> u64 {
    let dur = Instant::now()
        .saturating_duration_since(*WATCHDOG_REFERENCE_INSTANT.get_or_init(Instant::now));
    u64::try_from(dur.as_nanos()).unwrap_or(u64::MAX)
}

/// Record the current instant as the latest heartbeat.
#[inline]
pub fn record_heartbeat(heartbeat: &AtomicU64) {
    heartbeat.store(heartbeat_now(), Ordering::Release);
}

static WATCHDOG_REFERENCE_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Opaque handle returned by [`register_watchdog`]. Drop to deregister.
///
/// Dropping the handle prevents future stale-checks from firing against this
/// registration but does not interrupt the abort callback if it has already
/// started running.
#[must_use = "dropping the WatchdogRegistration deregisters the watchdog"]
pub struct WatchdogRegistration {
    id: u64,
}

impl std::fmt::Debug for WatchdogRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchdogRegistration")
            .field("id", &self.id)
            .finish()
    }
}

impl Drop for WatchdogRegistration {
    fn drop(&mut self) {
        if let Some(state) = WATCHDOG_STATE.get() {
            let mut regs = state.registrations.lock().unwrap_or_else(|e| e.into_inner());
            regs.retain(|r| r.id != self.id);
        }
    }
}

type AbortFn = Box<dyn Fn() + Send + Sync + 'static>;

struct Registration {
    id: u64,
    name: String,
    config: WatchdogConfig,
    heartbeat: std::sync::Arc<AtomicU64>,
    on_stale: AbortFn,
    fired: AtomicBool,
}

struct WatchdogState {
    registrations: Mutex<Vec<std::sync::Arc<Registration>>>,
}

static WATCHDOG_STATE: OnceLock<&'static WatchdogState> = OnceLock::new();
static NEXT_REGISTRATION_ID: AtomicU64 = AtomicU64::new(1);

/// Register a heartbeat with the process-global watchdog.
///
/// The first call lazily starts the watchdog OS thread. Subsequent calls
/// attach to the same thread. Drop the returned handle to deregister.
pub fn register_watchdog(
    name: String,
    config: WatchdogConfig,
    heartbeat: std::sync::Arc<AtomicU64>,
    on_stale: AbortFn,
) -> WatchdogRegistration {
    // Initialise heartbeat to "now" so the first stale check doesn't fire
    // against an uninitialised counter.
    record_heartbeat(&heartbeat);

    let state = WATCHDOG_STATE.get_or_init(|| {
        let s: &'static WatchdogState = Box::leak(Box::new(WatchdogState {
            registrations: Mutex::new(Vec::new()),
        }));
        // Start the OS thread that observes all heartbeats.
        std::thread::Builder::new()
            .name("rama-watchdog".into())
            .spawn(move || run_watchdog_loop(s))
            .expect("watchdog thread should spawn");
        s
    });

    let id = NEXT_REGISTRATION_ID.fetch_add(1, Ordering::Relaxed);
    let registration = std::sync::Arc::new(Registration {
        id,
        name,
        config,
        heartbeat,
        on_stale,
        fired: AtomicBool::new(false),
    });

    let mut regs = state
        .registrations
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    regs.push(registration);

    WatchdogRegistration { id }
}

fn run_watchdog_loop(state: &'static WatchdogState) {
    loop {
        // Pick the shortest configured check interval; if no registrations
        // are present, sleep for a generous default. We never spin.
        let next_interval = {
            let regs = state
                .registrations
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            regs.iter()
                .map(|r| r.config.check_interval)
                .min()
                .unwrap_or(Duration::from_secs(1))
        };
        std::thread::sleep(next_interval);

        let snapshot = {
            let regs = state
                .registrations
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            regs.clone()
        };

        let now_ns = heartbeat_now();
        for reg in snapshot {
            // Skip registrations that have already fired — fire-once semantics.
            if reg.fired.load(Ordering::Acquire) {
                continue;
            }
            let last_ns = reg.heartbeat.load(Ordering::Acquire);
            let stale_ns =
                u64::try_from(reg.config.stale_threshold.as_nanos()).unwrap_or(u64::MAX);
            // Wrap-safe: `now_ns >= last_ns` always within a single process
            // lifetime; saturating_sub avoids any rare overflow corner case.
            let elapsed_ns = now_ns.saturating_sub(last_ns);
            if elapsed_ns < stale_ns {
                continue;
            }
            // Stale — try to claim the fire (CAS so only one thread fires).
            if reg
                .fired
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            tracing::error!(
                target: "rama::watchdog",
                name = reg.name,
                stale_ms = elapsed_ns / 1_000_000,
                "watchdog detected stale heartbeat; firing abort",
            );
            (reg.on_stale)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn watchdog_fires_on_stale_heartbeat() {
        let heartbeat = Arc::new(AtomicU64::new(0));
        let fire_count = Arc::new(AtomicUsize::new(0));
        let fc = fire_count.clone();

        let _reg = register_watchdog(
            "test-stale".into(),
            WatchdogConfig {
                stale_threshold: Duration::from_millis(200),
                check_interval: Duration::from_millis(50),
            },
            heartbeat.clone(),
            Box::new(move || {
                fc.fetch_add(1, Ordering::Relaxed);
            }),
        );

        // Don't update heartbeat — let it go stale.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            fire_count.load(Ordering::Relaxed) >= 1,
            "watchdog should have fired by now"
        );
    }

    #[test]
    fn watchdog_does_not_fire_under_normal_load() {
        let heartbeat = Arc::new(AtomicU64::new(0));
        let fire_count = Arc::new(AtomicUsize::new(0));
        let fc = fire_count.clone();

        let _reg = register_watchdog(
            "test-fresh".into(),
            WatchdogConfig {
                stale_threshold: Duration::from_millis(300),
                check_interval: Duration::from_millis(50),
            },
            heartbeat.clone(),
            Box::new(move || {
                fc.fetch_add(1, Ordering::Relaxed);
            }),
        );

        // Update heartbeat regularly for 500ms.
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(500) {
            record_heartbeat(&heartbeat);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fire_count.load(Ordering::Relaxed),
            0,
            "watchdog should not have fired under normal load"
        );
    }

    #[test]
    fn watchdog_fires_only_once_per_registration() {
        let heartbeat = Arc::new(AtomicU64::new(0));
        let fire_count = Arc::new(AtomicUsize::new(0));
        let fc = fire_count.clone();

        let _reg = register_watchdog(
            "test-once".into(),
            WatchdogConfig {
                stale_threshold: Duration::from_millis(100),
                check_interval: Duration::from_millis(50),
            },
            heartbeat.clone(),
            Box::new(move || {
                fc.fetch_add(1, Ordering::Relaxed);
            }),
        );

        std::thread::sleep(Duration::from_millis(500));
        // After firing, even if the heartbeat stays stale, the abort should
        // not be re-invoked.
        assert_eq!(
            fire_count.load(Ordering::Relaxed),
            1,
            "watchdog should fire exactly once per registration"
        );
    }

    #[test]
    fn watchdog_runs_outside_async_runtime() {
        // Build a current-thread tokio runtime, register a watchdog from
        // inside it, then deliberately starve the runtime by calling
        // block_on with a future that never yields. The watchdog (running
        // on a separate OS thread) must still fire.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");

        let heartbeat = Arc::new(AtomicU64::new(0));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_cb = fired.clone();

        let _reg = register_watchdog(
            "test-outside-runtime".into(),
            WatchdogConfig {
                stale_threshold: Duration::from_millis(200),
                check_interval: Duration::from_millis(50),
            },
            heartbeat.clone(),
            Box::new(move || {
                fired_cb.store(true, Ordering::Release);
            }),
        );

        // Starve the runtime. The watchdog thread is independent.
        let started = Instant::now();
        rt.block_on(async {
            // Spin until the watchdog fires (observed from outside the runtime).
            while !fired.load(Ordering::Acquire) {
                if started.elapsed() > Duration::from_secs(2) {
                    break;
                }
                // Use a blocking sleep that doesn't yield — simulating
                // executor starvation. The watchdog must still fire.
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        assert!(
            fired.load(Ordering::Acquire),
            "watchdog should fire even when the watched runtime is starved"
        );
    }
}
