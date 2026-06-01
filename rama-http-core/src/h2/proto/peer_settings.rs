//! Shared, cheaply-cloneable per-connection state for the peer's
//! initial h2 `SETTINGS` frame.
//!
//! `Arc<PeerSettingsState>` is held both by the connection's `Send`
//! struct (which populates the snapshot when the first non-ACK SETTINGS
//! arrives, and marks closed on EOF) and by any number of independent
//! observer handles (e.g. an MITM relay's eager-handshake awaiter). The
//! observers carry no reference to the request dispatcher, so retaining
//! a handle does not extend the connection's lifetime.
//!
//! # INVARIANT: single-writer state cell
//!
//! `set_snapshot` and `mark_closed` are both invoked exclusively from
//! the connection-driver task (`Send::apply_remote_settings` via
//! `Settings::poll_send` for capture; `Streams::recv_eof` for close).
//! That task is single-threaded, so the two mutators never overlap.
//! Observers via `snapshot()` / `is_closed()` / `await_settings()`
//! run on arbitrary tasks and use only the `OnceLock` / `AtomicBool`
//! atomic-ordering guarantees for visibility.
//!
//! The interleaving correctness argument depends on this invariant.
//! Adding a second writer (e.g. allowing some external code to call
//! `set_snapshot`) would require re-deriving the no-missed-wake +
//! no-double-wake properties from scratch. In particular, a
//! concurrent `mark_closed` + `set_snapshot` race could produce the
//! logically inconsistent state `snapshot=Some + closed=true`. The
//! current single-writer property (both methods called from the
//! connection task, behind the streams mutex) makes that state
//! unreachable; if you ever lift that constraint, audit
//! `await_settings` carefully.

use rama_http_types::conn::PeerH2Settings;
use rama_http_types::proto::h2::frame;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

/// Shared state cell exposing the peer's initial SETTINGS frame, plus a
/// "connection died before SETTINGS" signal. See module docs.
///
/// The snapshot is held in a `OnceLock<Arc<PeerH2Settings>>`: write-once
/// semantics match exactly what we need, reads are lock-free atomic
/// loads, the standard library handles the once-only sync without us
/// reimplementing it on top of a mutex, and storing the
/// already-extension-wrapped form lets the per-response hot path use
/// [`rama_core::extensions::Extensions::insert_arc`] — a single Arc
/// bump with zero allocations.
#[derive(Debug)]
pub(crate) struct PeerSettingsState {
    /// The first non-ACK SETTINGS frame received from the peer, already
    /// wrapped in the public [`PeerH2Settings`] extension type so the
    /// per-response insertion is a single Arc clone (no allocation, no
    /// double indirection). Set exactly once.
    snapshot: OnceLock<Arc<PeerH2Settings>>,
    /// Set to `true` once the connection has been observed closed via
    /// the EOF path *without* having captured a SETTINGS frame first.
    /// Allows `await_settings` to resolve to `None` instead of hanging.
    closed: AtomicBool,
    /// Wakes any task parked in `await_settings`. Fires once on
    /// first SETTINGS capture, and once on EOF (if no SETTINGS).
    notify: Notify,
}

impl PeerSettingsState {
    #[must_use]
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: OnceLock::new(),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    /// Cheap fast-path: return the captured peer SETTINGS extension if any.
    #[must_use]
    pub(crate) fn snapshot(&self) -> Option<Arc<PeerH2Settings>> {
        self.snapshot.get().cloned()
    }

    /// True iff the connection terminated before any SETTINGS arrived.
    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Called from `Send::apply_remote_settings` on the first non-ACK
    /// SETTINGS receipt. Subsequent calls are ignored (we capture the
    /// *initial* peer SETTINGS only). Idempotency is enforced by
    /// `OnceLock::set` returning `Err` once initialised; only the
    /// first-writer-wins path fires the notify.
    ///
    /// Note on capture timing: this runs at the top of
    /// `apply_remote_settings`, *before* that method does any further
    /// validation that could return `Err` (e.g. initial-window
    /// underflow). For the eager-handshake use case this is fine in
    /// practice — there are no open streams yet at first SETTINGS, so
    /// the spec-invalid frames that *could* slip through here would
    /// also have caused the connection to tear down via
    /// `library_go_away` before any waiter could observe them.
    /// Strictly speaking though, the captured frame is "first non-ACK
    /// SETTINGS received," not "first successfully processed."
    pub(crate) fn set_snapshot(&self, settings: &frame::Settings) {
        if self
            .snapshot
            .set(Arc::new(PeerH2Settings(settings.clone())))
            .is_ok()
        {
            self.notify.notify_waiters();
        }
    }

    /// Called from `Streams::recv_eof`. No-op if a snapshot was already
    /// captured (any waiters already resolved through the success path).
    pub(crate) fn mark_closed(&self) {
        if self.snapshot.get().is_none() && !self.closed.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    /// Resolves to the peer's initial SETTINGS once captured, or `None`
    /// if the connection terminates before SETTINGS arrive. Uses the
    /// standard Notify `register-interest → recheck → await` pattern to
    /// avoid missed wakes.
    pub(crate) async fn await_settings(&self) -> Option<Arc<PeerH2Settings>> {
        // Fast path: already captured (or already closed).
        if let Some(s) = self.snapshot() {
            return Some(s);
        }
        if self.is_closed() {
            return None;
        }

        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Enable interest BEFORE re-checking the state to avoid
            // racing with a notify between the check and the await.
            notified.as_mut().enable();
            if let Some(s) = self.snapshot() {
                return Some(s);
            }
            if self.is_closed() {
                return None;
            }
            notified.await;
        }
    }
}
