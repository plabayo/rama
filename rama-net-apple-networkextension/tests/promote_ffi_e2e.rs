//! End-to-end test for the promote cutover FFI surface.
//!
//! Exercises the **complete** Rust ⇄ "Swift" round-trip in a single
//! process, using the exact C ABI Swift would call:
//!
//!   1. `rama_transparent_proxy_engine_new` — allocate the engine.
//!   2. `rama_transparent_proxy_engine_new_tcp_session` —
//!      construct a TCP session with session callbacks (the
//!      Rust→Swift response writers). The custom handler in
//!      this test returns `Intercept` with a service that
//!      reads ingress bytes, calls
//!      `PromoteHandle::into_passthrough`, and records the
//!      result.
//!   3. `rama_transparent_proxy_tcp_session_register_promote_callbacks`
//!      — register the "Swift" promote callback. When it fires
//!      the test's stand-in handler observes the request and
//!      calls `confirm_promoted`.
//!   4. `rama_transparent_proxy_tcp_session_activate` — supply
//!      the egress write callbacks; the Rust engine spawns the
//!      service task.
//!   5. `rama_transparent_proxy_tcp_session_on_client_bytes` —
//!      deliver bytes that wake the service. The service
//!      decides "I'm done; hand the data path back to Swift"
//!      and calls `into_passthrough`.
//!   6. The engine fires the registered C trampoline which
//!      invokes our test's "Swift callback". The callback
//!      calls `confirm_promoted(.ok)`.
//!   7. Rust drops the ingress sender; the service drains and
//!      exits; the engine fires `on_server_closed` /
//!      `on_close_egress` back to "Swift".
//!
//! Every assertion here exercises plumbing that would otherwise
//! only be tested via mocks. Together with the Swift-side
//! integration tests (which mock the Rust side) and the Rust
//! engine tests (which use the native API), this closes the
//! e2e loop.

#![cfg(target_vendor = "apple")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use rama_net_apple_networkextension::{
    ffi::BytesView,
    tproxy::{
        FlowAction, PromoteHandle, TransparentProxyConfig, TransparentProxyEngineBuilder,
        TransparentProxyFlowMeta, TransparentProxyHandler, TransparentProxyHandlerFactory,
        TransparentProxyNetworkRule, TransparentProxyRuleProtocol, TransparentProxyServiceContext,
    },
    transparent_proxy_ffi,
};

use parking_lot::Mutex;
use rama_core::{
    extensions::ExtensionsRef,
    io::BridgeIo,
    rt::Executor,
    service::{Service, service_fn},
};
use std::{
    convert::Infallible,
    ffi::c_void,
    future::Future,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc as std_mpsc,
    },
};

// ── Shared state between handler / service / test ────────────────────────────

/// The result of `into_passthrough` reported by the service.
/// Visible only after the service has finished its work.
type ServiceResult = Result<(), String>;

/// Globally-installed slot the handler reads at flow-match time
/// and the test populates at start. Concretely: tests set this
/// to a fresh `Arc` before driving each scenario.
static SHARED: OnceLock<Mutex<Option<Arc<Shared>>>> = OnceLock::new();

/// Cross-test serialization. `cargo test` runs tests in
/// parallel by default; the global `SHARED` slot can only host
/// one in-flight scenario at a time.
static TEST_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

fn test_lock() -> parking_lot::MutexGuard<'static, ()> {
    TEST_SERIAL.get_or_init(|| Mutex::new(())).lock()
}

struct Shared {
    /// Records the service's `into_passthrough` result.
    service_result_tx: std_mpsc::Sender<ServiceResult>,
    /// Counts how many times the registered "Swift" callback
    /// fired. Idempotency-of-fire guarantee on the Rust side.
    /// `Arc` so the leaked `SwiftPromoteBox` can hold its own
    /// reference while the test thread also observes it.
    callback_fires: Arc<AtomicUsize>,
}

fn shared_slot() -> &'static Mutex<Option<Arc<Shared>>> {
    SHARED.get_or_init(|| Mutex::new(None))
}

fn install_shared(shared: Arc<Shared>) {
    *shared_slot().lock() = Some(shared);
}

fn current_shared() -> Arc<Shared> {
    shared_slot()
        .lock()
        .clone()
        .expect("test forgot to install shared state")
}

// ── Handler / Service ────────────────────────────────────────────────────────

#[derive(Clone)]
struct PromoteTestHandler;

impl TransparentProxyHandler for PromoteTestHandler {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        TransparentProxyConfig::new().with_rules(vec![
            TransparentProxyNetworkRule::any().with_protocol(TransparentProxyRuleProtocol::Tcp),
        ])
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<
                BridgeIo<
                    rama_net_apple_networkextension::TcpFlow,
                    rama_net_apple_networkextension::NwTcpStream,
                >,
                Output = (),
                Error = Infallible,
            >,
        >,
    > + Send
    + '_ {
        let shared = current_shared();
        let service = service_fn(
            move |bridge: BridgeIo<
                rama_net_apple_networkextension::TcpFlow,
                rama_net_apple_networkextension::NwTcpStream,
            >| {
                let shared = shared.clone();
                async move {
                    let BridgeIo(ingress, _egress) = bridge;
                    let handle = ingress
                        .extensions()
                        .get_ref::<PromoteHandle>()
                        .cloned()
                        .expect("PromoteHandle in extensions");
                    let r = handle.into_passthrough().await;
                    let mapped = match r {
                        Ok(()) => Ok(()),
                        Err(e) => Err(format!("{e}")),
                    };
                    _ = shared.service_result_tx.send(mapped);
                    Ok(())
                }
            },
        );
        std::future::ready(FlowAction::Intercept { service, meta })
    }
}

#[derive(Clone, Copy, Default)]
struct PromoteTestFactory;

impl TransparentProxyHandlerFactory for PromoteTestFactory {
    type Handler = PromoteTestHandler;
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(Ok(PromoteTestHandler))
    }
}

fn init(
    _config: Option<&rama_net_apple_networkextension::ffi::tproxy::TransparentProxyInitConfig>,
) -> bool {
    true
}

transparent_proxy_ffi! {
    init = init,
    engine_builder = TransparentProxyEngineBuilder::new(PromoteTestFactory),
}

// ── "Swift-side" C trampolines + context boxes ──────────────────────────────

/// Carries a session pointer + ACK status into the promote
/// trampoline. Mirrors the Swift-side `TcpPromoteCallbackBox`
/// pattern: a heap-allocated context, raw pointer passed across
/// FFI.
struct SwiftPromoteBox {
    session: *mut RamaTransparentProxyTcpSession,
    /// What to ACK with. `(status, optional reason)`.
    ack: (RamaPromoteConfirmStatus, Option<String>),
    /// Counter incremented every time the trampoline fires.
    fires: Arc<AtomicUsize>,
}

// SAFETY: the session pointer + ack are touched only from the
// engine's tokio thread that invokes the trampoline. The test
// retains the box for the session's lifetime.
unsafe impl Send for SwiftPromoteBox {}
unsafe impl Sync for SwiftPromoteBox {}

unsafe extern "C" fn promote_request_trampoline(ctx: *mut c_void) {
    // SAFETY: ctx is the leaked box we passed in via
    // RamaTransparentProxyTcpPromoteCallbacks.
    let bx = unsafe { &*(ctx as *const SwiftPromoteBox) };
    bx.fires.fetch_add(1, Ordering::SeqCst);
    let session = bx.session;
    let (status, reason) = (bx.ack.0, bx.ack.1.clone());
    // The "Swift" cutover work would happen here. For the test
    // we just ACK directly. Mirrors the simplest valid Swift
    // implementation.
    match reason {
        Some(s) => {
            let bytes = s.into_bytes();
            unsafe {
                rama_transparent_proxy_tcp_session_confirm_promoted(
                    session,
                    status,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                );
            }
        }
        None => unsafe {
            rama_transparent_proxy_tcp_session_confirm_promoted(
                session,
                status,
                std::ptr::null(),
                0,
            );
        },
    }
}

// Stub Rust→"Swift" session callbacks. The test doesn't care
// about response bytes; we just need valid C ABI fn pointers.
unsafe extern "C" fn noop_on_server_bytes(
    _ctx: *mut c_void,
    _bytes: BytesView,
) -> RamaTcpDeliverStatus {
    RamaTcpDeliverStatus::Accepted
}

unsafe extern "C" fn noop_on_client_read_demand(_ctx: *mut c_void) {}
unsafe extern "C" fn noop_on_server_closed(_ctx: *mut c_void) {}

// Egress callbacks (passed to `_session_activate`).
unsafe extern "C" fn noop_on_write_to_egress(
    _ctx: *mut c_void,
    _bytes: BytesView,
) -> RamaTcpDeliverStatus {
    RamaTcpDeliverStatus::Accepted
}

unsafe extern "C" fn noop_on_egress_read_demand(_ctx: *mut c_void) {}
unsafe extern "C" fn noop_on_close_egress(_ctx: *mut c_void) {}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Allocate a flow meta on the stack with a stable remote
/// endpoint host slice. Returned with `_pin` keeping the string
/// alive for the duration of the `new_tcp_session` call.
fn make_tcp_meta_pin() -> (RamaTransparentProxyFlowMeta, &'static [u8]) {
    // `b"example.com\0"` — the FFI uses (ptr, len) without
    // requiring NUL termination, but a stable static is cleaner
    // than juggling lifetimes.
    static HOST: &[u8] = b"example.com";
    let meta = RamaTransparentProxyFlowMeta {
        protocol: 1, // tcp
        remote_endpoint: rama_net_apple_networkextension::ffi::tproxy::TransparentFlowEndpoint {
            host_utf8: HOST.as_ptr() as *const _,
            host_utf8_len: HOST.len(),
            port: 443,
        },
        local_endpoint: rama_net_apple_networkextension::ffi::tproxy::TransparentFlowEndpoint {
            host_utf8: std::ptr::null(),
            host_utf8_len: 0,
            port: 0,
        },
        source_app_signing_identifier_utf8: std::ptr::null(),
        source_app_signing_identifier_utf8_len: 0,
        source_app_bundle_identifier_utf8: std::ptr::null(),
        source_app_bundle_identifier_utf8_len: 0,
        source_app_audit_token_bytes: std::ptr::null(),
        source_app_audit_token_bytes_len: 0,
        source_app_pid: 4242,
        source_app_pid_is_set: true,
    };
    (meta, HOST)
}

struct EngineGuard {
    engine: *mut RamaTransparentProxyEngine,
}

impl Drop for EngineGuard {
    fn drop(&mut self) {
        unsafe { rama_transparent_proxy_engine_stop(self.engine, 0) };
    }
}

fn new_engine() -> EngineGuard {
    let engine = unsafe { rama_transparent_proxy_engine_new() };
    assert!(!engine.is_null(), "engine_new returned null");
    EngineGuard { engine }
}

/// RAII wrapper for the "Swift" promote box. Reclaims the Box on
/// drop so a panicking assertion in `run_round_trip` doesn't leak
/// the heap allocation under Miri / asan / valgrind.
struct PromoteBoxGuard {
    ptr: *mut SwiftPromoteBox,
}

impl PromoteBoxGuard {
    fn new(bx: SwiftPromoteBox) -> Self {
        Self {
            ptr: Box::into_raw(Box::new(bx)),
        }
    }

    fn as_ctx(&self) -> *mut c_void {
        self.ptr as *mut c_void
    }
}

impl Drop for PromoteBoxGuard {
    fn drop(&mut self) {
        // SAFETY: allocated via Box::into_raw in `new`; ownership is
        // exclusive to this guard until drop. No aliased references
        // remain — the session has been freed (or will be by EngineGuard).
        unsafe { drop(Box::from_raw(self.ptr)) };
    }
}

/// RAII clearer for the global `SHARED` slot. Pairs with
/// `install_shared` so a panicking test still empties the slot
/// before the next test installs its own state.
struct SharedSlotGuard;

impl Drop for SharedSlotGuard {
    fn drop(&mut self) {
        *shared_slot().lock() = None;
    }
}

/// Run the standard round-trip: create session, register
/// promote with the given ACK shape, activate, push one byte
/// (so saw_client_bytes flips), eof. Returns the service's
/// observed `into_passthrough` result + the callback fire count.
fn run_round_trip(ack: (RamaPromoteConfirmStatus, Option<String>)) -> (ServiceResult, usize) {
    let _serial = test_lock();
    let (result_tx, result_rx) = std_mpsc::channel::<ServiceResult>();
    let shared = Arc::new(Shared {
        service_result_tx: result_tx,
        callback_fires: Arc::new(AtomicUsize::new(0)),
    });
    install_shared(shared.clone());
    // RAII: even if any of the asserts below panic, clear the
    // global slot so the next test starts with a clean SHARED.
    let _slot_guard = SharedSlotGuard;

    let engine_guard = new_engine();
    let engine = engine_guard.engine;

    let (meta, _host_slice) = make_tcp_meta_pin();
    let session_callbacks = RamaTransparentProxyTcpSessionCallbacks {
        context: std::ptr::null_mut(),
        on_server_bytes: Some(noop_on_server_bytes),
        on_server_closed: Some(noop_on_server_closed),
        on_client_read_demand: Some(noop_on_client_read_demand),
    };
    let session_result =
        unsafe { rama_transparent_proxy_engine_new_tcp_session(engine, &meta, session_callbacks) };
    assert_eq!(
        session_result.action,
        RamaTransparentProxyFlowAction::Intercept,
        "test handler must return Intercept"
    );
    assert!(!session_result.session.is_null());
    let session = session_result.session;

    // Heap-allocate the "Swift" promote callback box behind an
    // RAII guard so a panicking assertion below still frees it.
    let promote_box = PromoteBoxGuard::new(SwiftPromoteBox {
        session,
        ack,
        fires: shared.callback_fires.clone(),
    });
    let promote_callbacks = RamaTransparentProxyTcpPromoteCallbacks {
        context: promote_box.as_ctx(),
        on_promote_request: Some(promote_request_trampoline),
    };
    unsafe {
        rama_transparent_proxy_tcp_session_register_promote_callbacks(session, promote_callbacks);
    }

    // Activate (egress callbacks).
    let egress_callbacks = RamaTransparentProxyTcpEgressCallbacks {
        context: std::ptr::null_mut(),
        on_write_to_egress: Some(noop_on_write_to_egress),
        on_close_egress: Some(noop_on_close_egress),
        on_egress_read_demand: Some(noop_on_egress_read_demand),
    };
    unsafe { rama_transparent_proxy_tcp_session_activate(session, egress_callbacks) };

    // Push a byte so the service observes traffic (and thus
    // `saw_client_bytes` flips true). Without this, the
    // engine's `on_client_eof` would route via `cancel`,
    // aborting the service task.
    let single = [0u8];
    let bytes_view = BytesView {
        ptr: single.as_ptr(),
        len: single.len(),
    };
    let status = unsafe { rama_transparent_proxy_tcp_session_on_client_bytes(session, bytes_view) };
    assert_eq!(status, RamaTcpDeliverStatus::Accepted);

    // Wait for the service's into_passthrough to resolve.
    let result = result_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("service reported result within 5s");
    let fires = shared.callback_fires.load(Ordering::SeqCst);

    // Drop the session BEFORE the promote box: the C trampoline
    // could otherwise be invoked against an already-freed context.
    unsafe { rama_transparent_proxy_tcp_session_free(session) };
    drop(promote_box);
    drop(engine_guard);
    (result, fires)
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// The headline test: service calls `into_passthrough`, the
/// engine fires our registered C trampoline, the trampoline
/// calls `confirm_promoted(.ok)`, the service observes Ok, and
/// the round-trip completes within the deadline.
#[test]
fn promote_round_trip_ok_resolves_service_with_ok() {
    let (result, fires) = run_round_trip((RamaPromoteConfirmStatus::Ok, None));
    assert_eq!(result, Ok(()), "service should observe Ok");
    assert_eq!(fires, 1, "promote callback fired exactly once");
}

/// `.failed` with a reason propagates as `SwiftCutoverFailed`
/// — the service observes the error and falls through.
#[test]
fn promote_round_trip_failed_with_reason_propagates_to_service() {
    let (result, fires) = run_round_trip((
        RamaPromoteConfirmStatus::Failed,
        Some("egress unhealthy".into()),
    ));
    let err = result.expect_err("service should observe Err");
    assert!(
        err.contains("swift cutover failed") && err.contains("egress unhealthy"),
        "error must surface the reason; got: {err}"
    );
    assert_eq!(fires, 1, "promote callback fired exactly once");
}

/// `.failed` with no reason still propagates as
/// `SwiftCutoverFailed { reason: "" }` and the service
/// observes the error path.
#[test]
fn promote_round_trip_failed_without_reason_propagates_to_service() {
    let (result, fires) = run_round_trip((RamaPromoteConfirmStatus::Failed, None));
    let err = result.expect_err("service should observe Err");
    assert!(
        err.contains("swift cutover failed"),
        "error must surface as SwiftCutoverFailed; got: {err}"
    );
    assert_eq!(fires, 1);
}

/// Multi-byte UTF-8 + embedded special characters in the reason
/// survive the round-trip intact.
#[test]
fn promote_round_trip_failed_reason_marshals_utf8_safely() {
    let reason = "cutover \u{1F6A7} niet klaar\n— met nieuwe regel";
    let (result, fires) =
        run_round_trip((RamaPromoteConfirmStatus::Failed, Some(reason.to_owned())));
    let err = result.expect_err("service should observe Err");
    assert!(
        err.contains("niet klaar") && err.contains("nieuwe regel"),
        "UTF-8 reason must survive intact across FFI; got: {err}"
    );
    assert_eq!(fires, 1);
}
