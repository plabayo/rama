//! Service-initiated hand-off of a per-flow data path back to Swift.
//!
//! See [`PromoteHandle`] / [`PromoteLayer`].

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rama_core::Layer;
use rama_core::Service;
use rama_core::bytes::Bytes;
use rama_core::extensions::{Extension, ExtensionsRef};
use rama_core::io::BridgeIo;
use rama_core::telemetry::tracing;
use rama_net::extensions::{StreamMultiplexed, StreamTransformed};

use tokio::sync::{Notify, mpsc, oneshot};

/// Handle that lets a per-flow service hand the data path back to Swift.
/// Available via `TcpFlow::extensions()` on every flow accepted via
/// [`crate::tproxy::FlowAction::Intercept`]. Cheap to clone. Idempotent.
///
/// # Safety contract
///
/// The cutover hands the *raw* kernel-flow ↔ NWConnection byte path
/// back to Swift. It MUST only fire while the service is still
/// observing those raw bytes — i.e. **before any framing layer has
/// been terminated**. Concretely:
///
/// * TCP / pre-TLS-peek: safe.
/// * Inside TLS-MITM (post-decryption cleartext): **NEVER**. The
///   kernel flow carries bytes encrypted under your forged session
///   keys; the NWConnection carries bytes encrypted under the real
///   upstream keys. A cutover here forwards mutually-undecryptable
///   bytes in both directions and breaks the connection.
/// * Inside HTTP-MITM (post-HTTP-decoding) / CONNECT tunnel inner
///   stream: **NEVER**. Same reason — the wire framing and the
///   inner stream you're handling no longer match.
///
/// Wrap [`PromoteLayer`] only around services that operate on the
/// raw flow bridge (`BridgeIo<TcpFlow, NwTcpStream>`). Inside any
/// MITM or framing-decoded context, use the plain non-promoting
/// forwarder.
#[derive(Clone)]
pub struct PromoteHandle {
    inner: Arc<PromoteInner>,
}

#[derive(Debug, Clone)]
pub enum PromoteError {
    /// No promote callback is registered on this session.
    ///
    /// Emitted by `fire()` when neither the FFI nor the Rust-typed
    /// slot is populated at dispatch time. The egress NWConnection
    /// itself is never inspected on the Rust side — Swift owns that
    /// state and surfaces failures via [`Self::SwiftCutoverFailed`].
    EgressUnavailable,
    /// Kernel flow has already started closing on Swift's side.
    IngressUnavailable,
    /// Engine-level shutdown raced ahead of this promote request.
    EngineShuttingDown,
    /// The registered promote callback panicked. The protocol can't
    /// recover — `PromoteLayer` falls through to the in-Rust data
    /// path.
    CallbackPanicked,
    /// Swift reported the cutover could not complete.
    SwiftCutoverFailed { reason: String },
}

impl std::fmt::Display for PromoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EgressUnavailable => f.write_str("no promote callback registered"),
            Self::IngressUnavailable => f.write_str("ingress unavailable"),
            Self::EngineShuttingDown => f.write_str("engine shutting down"),
            Self::CallbackPanicked => f.write_str("promote callback panicked"),
            Self::SwiftCutoverFailed { reason } => {
                write!(f, "swift cutover failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PromoteError {}

struct PromoteInner {
    /// CAS to ensure the cutover fires exactly once across concurrent /
    /// repeated [`PromoteHandle::into_passthrough`] calls.
    requested: AtomicBool,
    /// Woken once `result` has been populated.
    completed: Notify,
    /// Cached outcome of the first cutover, returned to every caller.
    result: parking_lot::Mutex<Option<Result<(), PromoteError>>>,
    /// Engine-supplied closure that drives the actual cutover.
    fire: Fire,
}

/// `Fire` is the closure that performs the engine-side cutover when the
/// first `into_passthrough` call runs. It is invoked at most once per
/// `PromoteHandle` (CAS-guarded). The closure must be `Send + Sync` so the
/// handle can move across runtime tasks freely.
type FireFuture = Pin<Box<dyn Future<Output = Result<(), PromoteError>> + Send>>;
type FireFn = dyn Fn() -> FireFuture + Send + Sync;

enum Fire {
    /// Real engine-side cutover. The `Handle` is used to spawn
    /// the fire work as a detached task so cancellation of the
    /// awaiting caller doesn't strand other waiters on the
    /// `Notify`.
    Engine(Arc<FireFn>, tokio::runtime::Handle),
    /// `no_op_for_tests` — populates `result` synchronously
    /// with `Ok(())`. No runtime needed.
    #[cfg(test)]
    NoOp,
}

impl PromoteHandle {
    /// Hand the per-flow data path back to Swift. After this returns, the
    /// service should drain remaining in-flight bytes via its normal
    /// read/write loop until EOF.
    ///
    /// Cancel-safety: the actual fire work is detached onto the
    /// engine's tokio runtime, so dropping the awaiting future
    /// (e.g. on `tokio::time::timeout` expiry or `select!`
    /// race) does not strand other concurrent `into_passthrough`
    /// callers — they will observe whatever result the
    /// (still-running) detached task produces.
    pub async fn into_passthrough(&self) -> Result<(), PromoteError> {
        if !self.inner.requested.swap(true, Ordering::AcqRel) {
            self.spawn_fire();
        }

        // Wait for the firing task (which may be this one or another caller)
        // to populate `result`. `enable()` registers the waiter BEFORE the
        // result check — without that, a `notify_waiters` fired between
        // `notified()` construction and `.await` would be lost, leaving the
        // task parked forever. (Today's tokio also tracks the
        // notify_waiters generation on `notified()` construction, but the
        // documented API surface is `enable()`.)
        loop {
            let notified = self.inner.completed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(r) = self.inner.result.lock().clone() {
                return r;
            }
            notified.await;
        }
    }

    /// Construct a handle that resolves immediately without involving the
    /// engine or Swift. For service-layer unit tests that want to exercise
    /// [`PromoteLayer`] composition without an attached engine.
    #[cfg(test)]
    pub fn no_op_for_tests() -> Self {
        Self {
            inner: Arc::new(PromoteInner {
                requested: AtomicBool::new(false),
                completed: Notify::new(),
                result: parking_lot::Mutex::new(None),
                fire: Fire::NoOp,
            }),
        }
    }

    /// Engine-side constructor.
    ///
    /// `rt` is the engine's tokio runtime handle. The handle
    /// spawns the fire work via `rt.spawn` so the work survives
    /// drop of the awaiting future — cancel-safe by
    /// construction.
    pub(super) fn new_engine<F, Fut>(rt: tokio::runtime::Handle, fire: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), PromoteError>> + Send + 'static,
    {
        let fire: Arc<FireFn> = Arc::new(move || Box::pin(fire()));
        Self {
            inner: Arc::new(PromoteInner {
                requested: AtomicBool::new(false),
                completed: Notify::new(),
                result: parking_lot::Mutex::new(None),
                fire: Fire::Engine(fire, rt),
            }),
        }
    }

    /// Spawn (or synchronously run, for the `NoOp` test path)
    /// the fire work. Called exactly once across all clones
    /// (CAS-guarded in `into_passthrough`). Detaching onto the
    /// runtime is what makes the protocol cancel-safe: even if
    /// the calling future is dropped, the detached task runs
    /// to completion and notifies the `Notify` so any other
    /// concurrent waiter on a cloned handle still observes the
    /// result.
    /// Invariant: `self.inner.fire` (when `Engine`) holds a `Handle`
    /// to a runtime that outlives every clone of this handle. The
    /// engine enforces that — service tasks (the only callers of
    /// `into_passthrough`) are spawned ON that runtime, so they
    /// cannot outlive it. If callers ever leak a `PromoteHandle`
    /// past the engine's runtime, `Handle::spawn` here silently
    /// queues onto a dead scheduler (tokio does NOT panic, contrary
    /// to its docs); the task never runs and `into_passthrough`
    /// hangs forever on `Notify`. No FFI / production caller can
    /// reach that shape today.
    fn spawn_fire(&self) {
        match &self.inner.fire {
            Fire::Engine(f, rt) => {
                let inner = self.inner.clone();
                let f = f.clone();
                let rt_for_fire = rt.clone();
                rt.spawn(async move {
                    // If the fire body unwinds (a user-supplied
                    // `register_rust` closure panics, an FFI trampoline
                    // misbehaves, etc.), the subsequent statements
                    // never run, `inner.result` stays `None`, and every
                    // `into_passthrough().await` parks on `Notify`
                    // forever — the flow wedges past `tcp_idle_timeout`.
                    //
                    // Spawn the fire body as its OWN task so tokio's
                    // `JoinHandle` catches the panic for us, then await
                    // the handle. Two spawns per cutover is fine — the
                    // protocol fires at most once per flow.
                    let fire_task = rt_for_fire.spawn(async move { f().await });
                    let outcome = match fire_task.await {
                        Ok(r) => r,
                        Err(je) if je.is_panic() => {
                            tracing::error!(
                                target: "rama_apple_ne::tproxy::promote",
                                "promote fire body panicked; resolving waiters with CallbackPanicked",
                            );
                            Err(PromoteError::CallbackPanicked)
                        }
                        Err(_) => {
                            // Task cancelled. We don't issue
                            // `JoinHandle::abort` anywhere, so this
                            // can only happen via runtime shutdown.
                            Err(PromoteError::EngineShuttingDown)
                        }
                    };
                    *inner.result.lock() = Some(outcome);
                    inner.completed.notify_waiters();
                });
            }
            #[cfg(test)]
            Fire::NoOp => {
                *self.inner.result.lock() = Some(Ok(()));
                self.inner.completed.notify_waiters();
            }
        }
    }
}

impl std::fmt::Debug for PromoteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromoteHandle").finish_non_exhaustive()
    }
}

impl Extension for PromoteHandle {}

// ── Engine-side registry ─────────────────────────────────────────────────────

/// Shared per-session state backing the engine's real `PromoteHandle`.
///
/// The engine owns this; the FFI exposes registration + ACK entry
/// points that mutate it. The handle's `fire` closure observes it.
///
/// Lifecycle: created in `new_tcp_session`, dropped when the session
/// is dropped or cancelled. On a `cancel`-driven drop, any pending
/// ACK sender is dropped — the awaiting `fire` future then resolves
/// with [`PromoteError::EngineShuttingDown`].
pub(super) struct PromoteRegistry {
    /// FFI-shape callback (Swift consumers). `None` until
    /// `register_promote_request_callback_raw` runs. Stored as
    /// `Copy` because the context pointer is owned by Swift —
    /// see the FFI lifetime contract.
    raw_callback: parking_lot::Mutex<Option<PromoteRequestCallback>>,
    /// Rust-typed callback (used by tests + native Rust API).
    /// Owns its closure so re-registration / drop releases the
    /// memory — no `Box::leak`. Mutually exclusive with
    /// `raw_callback`: registering one clears the other.
    rust_callback: parking_lot::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Set when the first `into_passthrough` fires; consumed by
    /// `confirm_promoted` (or dropped by a session cancel).
    pending_ack: parking_lot::Mutex<Option<oneshot::Sender<Result<(), PromoteError>>>>,
    /// Shared handle to the session's `client_tx`. On a successful
    /// cutover the fire closure takes the sender so the ingress
    /// bridge sees EOF after draining whatever bytes were already
    /// in flight. This keeps zero-byte-loss semantics: bytes already
    /// pushed into `client_tx` by `on_client_bytes` are delivered to
    /// the service before EOF.
    client_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,
    /// Symmetric mirror for `egress_tx`. A service using
    /// bidirectional copy (`tokio::io::copy_bidirectional` and
    /// the like) needs EOF on BOTH `ingress.read` and
    /// `egress.read` for its read loops to terminate. Without
    /// dropping this sender too on Ok ACK, the egress bridge
    /// keeps blocking on `recv()` and the service wedges.
    egress_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,
    /// The session's `callback_active` gate. We acquire this
    /// across the C-trampoline call to mirror the safety
    /// guarantee `guarded_*_sink` provides for the other FFI
    /// callbacks: cancel cannot complete (and Swift cannot
    /// release the callback box) while a callback is in flight.
    /// See the comments on `guarded_demand_sink` /
    /// `guarded_bytes_status_sink` in `mod.rs`.
    callback_active: Arc<parking_lot::Mutex<bool>>,
}

/// Swift-side callback fired by the engine when the service-bound
/// `PromoteHandle::into_passthrough` runs. The Swift side responds
/// by completing the cutover and calling `confirm_promoted` on the
/// session.
#[derive(Copy, Clone)]
pub(super) struct PromoteRequestCallback {
    /// Stored as `usize` to keep the registry `Send + Sync` without
    /// raw-pointer footguns — same pattern as the other FFI
    /// callbacks in this crate.
    pub(super) context: usize,
    pub(super) on_promote_request: unsafe extern "C" fn(context: *mut std::ffi::c_void),
}

impl PromoteRegistry {
    pub(super) fn new(
        client_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,
        egress_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,
        callback_active: Arc<parking_lot::Mutex<bool>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            raw_callback: parking_lot::Mutex::new(None),
            rust_callback: parking_lot::Mutex::new(None),
            pending_ack: parking_lot::Mutex::new(None),
            client_tx,
            egress_tx,
            callback_active,
        })
    }

    /// FFI-shape registration. Replaces both the FFI slot and
    /// the Rust slot (mutually exclusive). Calling after a
    /// promote has already fired is a no-op for the in-flight
    /// cutover — `requested` is CAS-guarded on the handle.
    ///
    /// Callback contract: the registered C trampoline MUST NOT
    /// synchronously call `cancel` on this same session. `fire`
    /// holds `callback_active` across the trampoline call to
    /// keep the Swift box alive; a re-entrant `cancel` would
    /// deadlock waiting for that same lock. Production Swift
    /// satisfies this by hopping to the per-flow dispatch queue
    /// inside the callback body and returning immediately.
    /// `confirm_promoted` is safe to call synchronously — it
    /// only touches `pending_ack`, not `callback_active`.
    pub(super) fn register_raw(&self, cb: PromoteRequestCallback) {
        // Serialises against `fire`'s snapshot+dispatch (which
        // holds the same lock across both). Without this, a swap
        // could land between fire's snapshot and dispatch, and
        // Swift's matching `previous.release()` would free the
        // box mid-dispatch.
        let _active = self.callback_active.lock();
        *self.raw_callback.lock() = Some(cb);
        *self.rust_callback.lock() = None;
    }

    /// Rust-typed registration. Used by tests + native Rust
    /// API. Owns the closure via `Arc` so it doesn't leak.
    pub(super) fn register_rust<F>(&self, f: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let _active = self.callback_active.lock();
        *self.rust_callback.lock() = Some(Arc::new(f));
        *self.raw_callback.lock() = None;
    }

    /// ACK the in-flight cutover. Returns `true` if there was a
    /// pending ACK to resolve; `false` if no promote is in flight
    /// (e.g. Swift confirmed twice, or before any service called
    /// `into_passthrough`).
    pub(super) fn confirm(&self, result: Result<(), PromoteError>) -> bool {
        let Some(tx) = self.pending_ack.lock().take() else {
            return false;
        };
        // The receiver may have been dropped (session cancelled
        // mid-ACK). Either way the result of `send` doesn't matter
        // — what matters is that we cleared `pending_ack`.
        drop(tx.send(result));
        true
    }

    /// Drop the ACK sender so the awaiting `fire` future resolves
    /// with [`PromoteError::EngineShuttingDown`]. Called by the
    /// session on cancel.
    pub(super) fn abort_pending(&self) {
        let _ = self.pending_ack.lock().take();
    }

    /// Test helper: is there an in-flight `fire` awaiting ACK?
    ///
    /// Lets tests synchronise on "fire has reached its await point"
    /// without sleeping for an arbitrary duration.
    #[cfg(test)]
    pub(super) fn has_pending_ack(&self) -> bool {
        self.pending_ack.lock().is_some()
    }

    /// Build the [`PromoteHandle`] this registry backs.
    ///
    /// The handle's `fire` closure captures only `self` (as an
    /// `Arc`) — not the session — so the handle stays valid after
    /// `activate` returns and can be cloned freely into the service
    /// task and beyond.
    ///
    /// `rt` is the engine's tokio runtime handle. The handle
    /// uses it to spawn the actual fire work, so that an
    /// awaiting caller being dropped doesn't strand any
    /// concurrent `PromoteHandle::into_passthrough` waiters.
    pub(super) fn into_handle(self: Arc<Self>, rt: tokio::runtime::Handle) -> PromoteHandle {
        PromoteHandle::new_engine(rt, move || {
            let registry = self.clone();
            async move { registry.fire().await }
        })
    }

    async fn fire(&self) -> Result<(), PromoteError> {
        // Phase 1: install the pending ACK channel.
        let ack_rx = {
            let mut pending = self.pending_ack.lock();
            let (tx, rx) = oneshot::channel();
            *pending = Some(tx);
            rx
        };

        // Phase 2: snapshot + dispatch under `callback_active`.
        //
        // Snapshot AND dispatch share the same lock acquire so a
        // concurrent `register_raw` cannot swap the slot and have
        // Swift release the old `TcpPromoteCallbackBox` between
        // our snapshot and our dispatch. Without that atomicity,
        // we'd dereference a freed FFI context — same UAF window
        // the other guarded sinks avoid.
        {
            let active = self.callback_active.lock();
            if !*active {
                *self.pending_ack.lock() = None;
                return Err(PromoteError::EngineShuttingDown);
            }
            let raw_cb = *self.raw_callback.lock();
            let rust_cb = self.rust_callback.lock().clone();
            if raw_cb.is_none() && rust_cb.is_none() {
                *self.pending_ack.lock() = None;
                return Err(PromoteError::EgressUnavailable);
            }
            // SAFETY (raw path): registration is FFI-owned; caller
            // keeps `context` valid until the session is freed.
            // Holding `callback_active` here AND in `register_raw`
            // serialises swap-and-release against the dispatch.
            if let Some(cb) = raw_cb {
                unsafe { (cb.on_promote_request)(cb.context as *mut std::ffi::c_void) };
            } else if let Some(rust) = rust_cb.as_ref() {
                rust();
            }
        }

        // Phase 3: await the ACK. If the sender is dropped
        // (session cancelled, registry aborted), recv() errors
        // → EngineShuttingDown.
        match ack_rx.await {
            Ok(Ok(())) => {
                // Drop BOTH directional senders. Each bridge's
                // `recv()` drains anything still queued, then
                // returns `None`, which it treats as a natural
                // EOF. Symmetric EOF on the service's `ingress`
                // AND `egress` is what lets services using
                // `tokio::io::copy_bidirectional` (or any
                // bidirectional read loop) terminate cleanly
                // post-cutover — the egress side won't EOF
                // otherwise because Swift stopped delivering
                // bytes when it pivoted to the direct
                // forwarder.
                let _ = self.client_tx.lock().take();
                let _ = self.egress_tx.lock().take();
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PromoteError::EngineShuttingDown),
        }
    }
}

// ── Layer ────────────────────────────────────────────────────────────────────

/// Calls [`PromoteHandle::into_passthrough`] before delegating to the inner
/// service. If no handle is in the bridge's extensions (e.g. unit-test
/// without an engine) or promotion fails, the layer logs and falls through
/// to the inner service unchanged.
///
/// **Placement matters** — only wrap services whose bridge is the raw
/// kernel flow ↔ NWConnection. See [`PromoteHandle`]'s "Safety contract"
/// for the full rule. Using this layer inside a TLS / HTTP / CONNECT
/// MITM context breaks the connection.
///
/// Defense-in-depth: the layer skips the cutover when the bridge's
/// stream extensions carry [`StreamTransformed`] or
/// [`StreamMultiplexed`]. These are best-effort hints, not a hard
/// guarantee — the safety contract above is still primary.
#[derive(Debug, Default, Clone)]
pub struct PromoteLayer {
    _priv: (),
}

impl PromoteLayer {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<S> Layer<S> for PromoteLayer {
    type Service = Promote<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Promote { inner }
    }
}

/// Service produced by [`PromoteLayer`].
#[derive(Debug, Clone)]
pub struct Promote<S> {
    inner: S,
}

impl<S, T, NwIo> Service<BridgeIo<T, NwIo>> for Promote<S>
where
    S: Service<BridgeIo<T, NwIo>>,
    T: ExtensionsRef + Send + 'static,
    NwIo: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, bridge: BridgeIo<T, NwIo>) -> Result<Self::Output, Self::Error> {
        let extensions = bridge.0.extensions();
        if let Some(marker) = extensions.get_ref::<StreamTransformed>() {
            tracing::debug!(
                target: "rama_apple_ne::tproxy::promote",
                by = marker.by,
                "promote skipped: bridge wraps a transformed stream",
            );
        } else if let Some(marker) = extensions.get_ref::<StreamMultiplexed>() {
            tracing::debug!(
                target: "rama_apple_ne::tproxy::promote",
                by = marker.by,
                "promote skipped: bridge wraps a multiplexed stream",
            );
        } else if let Some(handle) = extensions.get_ref::<PromoteHandle>().cloned() {
            if let Err(err) = handle.into_passthrough().await {
                tracing::warn!(
                    target: "rama_apple_ne::tproxy::promote",
                    error = %err,
                    "promote.into_passthrough failed; falling back to in-Rust data path",
                );
            }
        } else {
            tracing::debug!(
                target: "rama_apple_ne::tproxy::promote",
                "promote skipped: no PromoteHandle in extensions \
                 (engine not attached, or extensions were stripped upstream)",
            );
        }
        self.inner.serve(bridge).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_op_handle_resolves_ok() {
        let h = PromoteHandle::no_op_for_tests();
        h.into_passthrough().await.expect("no-op never fails");
    }

    #[tokio::test]
    async fn handle_is_idempotent_across_repeated_calls() {
        let h = PromoteHandle::no_op_for_tests();
        for _ in 0..5 {
            h.into_passthrough().await.expect("ok");
        }
    }

    #[tokio::test]
    async fn handle_is_idempotent_across_concurrent_calls() {
        let h = PromoteHandle::no_op_for_tests();
        let h2 = h.clone();
        let h3 = h.clone();
        let (a, b, c) = tokio::join!(
            tokio::spawn(async move { h.into_passthrough().await }),
            tokio::spawn(async move { h2.into_passthrough().await }),
            tokio::spawn(async move { h3.into_passthrough().await }),
        );
        a.unwrap().expect("ok");
        b.unwrap().expect("ok");
        c.unwrap().expect("ok");
    }

    #[tokio::test]
    async fn engine_fire_is_invoked_at_most_once() {
        use std::sync::atomic::AtomicUsize;
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_inner = counter.clone();
        let rt = tokio::runtime::Handle::current();
        let handle = PromoteHandle::new_engine(rt, move || {
            let c = counter_inner.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        let h2 = handle.clone();
        let h3 = handle.clone();
        tokio::join!(
            async { handle.into_passthrough().await.unwrap() },
            async { h2.into_passthrough().await.unwrap() },
            async { h3.into_passthrough().await.unwrap() },
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1, "fire ran exactly once");
    }

    /// `StreamTransformed` in extensions must skip the cutover.
    /// `into_passthrough` is verified not to fire by counter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn promote_layer_skips_when_stream_transformed_present() {
        marker_skips_promote(rama_net::extensions::StreamTransformed { by: "test" }).await;
    }

    /// Symmetric coverage for `StreamMultiplexed`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn promote_layer_skips_when_stream_multiplexed_present() {
        marker_skips_promote(rama_net::extensions::StreamMultiplexed { by: "test" }).await;
    }

    async fn marker_skips_promote<M: Extension>(marker: M) {
        use rama_core::extensions::Extensions;
        use rama_core::service::service_fn;
        use std::sync::atomic::AtomicUsize;

        struct TestIo {
            extensions: Extensions,
        }
        impl ExtensionsRef for TestIo {
            fn extensions(&self) -> &Extensions {
                &self.extensions
            }
        }

        let fires = Arc::new(AtomicUsize::new(0));
        let fires_inner = fires.clone();
        let handle = PromoteHandle::new_engine(tokio::runtime::Handle::current(), move || {
            let f = fires_inner.clone();
            async move {
                f.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        let extensions = Extensions::new();
        extensions.insert(handle);
        extensions.insert(marker);
        let bridge = BridgeIo(TestIo { extensions }, ());

        let inner =
            service_fn(|_b: BridgeIo<TestIo, ()>| async { Ok::<_, std::convert::Infallible>(()) });
        let wrapped = PromoteLayer::new().into_layer(inner);

        wrapped.serve(bridge).await.unwrap();
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "PromoteLayer must skip the cutover when the marker is present",
        );
    }

    #[tokio::test]
    async fn engine_fire_error_is_propagated_to_all_waiters() {
        let rt = tokio::runtime::Handle::current();
        let handle =
            PromoteHandle::new_engine(rt, || async { Err(PromoteError::EgressUnavailable) });
        let h2 = handle.clone();
        let r1 = handle.into_passthrough().await;
        let r2 = h2.into_passthrough().await;
        assert!(matches!(r1, Err(PromoteError::EgressUnavailable)));
        assert!(matches!(r2, Err(PromoteError::EgressUnavailable)));
    }

    /// Round-3 audit: a panicking fire body MUST NOT leave waiters
    /// parked on `Notify` forever. Without the `JoinHandle::await`
    /// panic-catch in `spawn_fire`, this test would hang past the
    /// timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_fire_panic_resolves_waiters_with_callback_panicked() {
        let rt = tokio::runtime::Handle::current();
        let handle = PromoteHandle::new_engine(rt, || async {
            panic!("synthetic panic from fire body");
        });
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), handle.into_passthrough())
            .await
            .expect("waiter must not hang on panicking fire body");
        assert!(
            matches!(r, Err(PromoteError::CallbackPanicked)),
            "expected CallbackPanicked, got {r:?}",
        );
    }

    /// Audit minor #5: a waiter that arrives AFTER `notify_waiters`
    /// already fired must still observe the result via the
    /// `notified().enable()` + recheck pattern. The serial loop in
    /// `handle_is_idempotent_across_repeated_calls` implicitly
    /// covers this, but make it explicit so a future refactor of
    /// the `Notify` discipline trips here first.
    #[tokio::test]
    async fn engine_late_waiter_after_fire_completed_still_observes_result() {
        let rt = tokio::runtime::Handle::current();
        let handle = PromoteHandle::new_engine(rt, || async { Ok(()) });
        // Drive the fire to completion on this task.
        handle.into_passthrough().await.expect("first call ok");
        // Spawn a fresh waiter on a separate task. The fire is
        // already done; `notify_waiters` has already fired. The
        // new waiter must NOT hang.
        let h2 = handle.clone();
        let late = tokio::spawn(async move { h2.into_passthrough().await });
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), late)
            .await
            .expect("late waiter must not hang")
            .expect("task panicked");
        r.expect("late waiter sees Ok");
    }
}
