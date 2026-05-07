use std::sync::Arc;
use std::time::Duration;

use rama_core::{
    error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError},
    graceful::Shutdown,
    rt::Executor,
};

use super::{
    DecisionDeadlineAction, DefaultTransparentProxyAsyncRuntimeFactory,
    TransparentProxyAsyncRuntimeFactory, TransparentProxyEngine, TransparentProxyHandlerFactory,
    TransparentProxyServiceContext,
};

pub struct TransparentProxyEngineBuilder<F, R = DefaultTransparentProxyAsyncRuntimeFactory> {
    handler_factory: F,
    tcp_flow_buffer_size: Option<usize>,
    tcp_channel_capacity: Option<usize>,
    udp_channel_capacity: Option<usize>,
    tcp_idle_timeout: Option<Duration>,
    tcp_paused_drain_max_wait: Option<Duration>,
    udp_max_flow_lifetime: Option<Duration>,
    decision_deadline: Option<Duration>,
    decision_deadline_action: Option<DecisionDeadlineAction>,
    app_message_deadline: Option<Duration>,
    opaque_config: Option<Arc<[u8]>>,
    runtime_factory: R,
}

impl<F> TransparentProxyEngineBuilder<F>
where
    F: TransparentProxyHandlerFactory,
{
    #[must_use]
    pub fn new(factory: F) -> Self {
        Self {
            handler_factory: factory,
            tcp_flow_buffer_size: None,
            tcp_channel_capacity: None,
            udp_channel_capacity: None,
            // Backstop defaults; opt out via the macro-generated
            // `without_tcp_idle_timeout()` / `without_udp_max_flow_lifetime()`.
            tcp_idle_timeout: Some(super::DEFAULT_TCP_IDLE_TIMEOUT),
            tcp_paused_drain_max_wait: None,
            udp_max_flow_lifetime: Some(super::DEFAULT_UDP_MAX_FLOW_LIFETIME),
            decision_deadline: None,
            decision_deadline_action: None,
            app_message_deadline: None,
            opaque_config: None,
            runtime_factory: DefaultTransparentProxyAsyncRuntimeFactory::default(),
        }
    }

    pub fn with_runtime_factory<R: TransparentProxyAsyncRuntimeFactory>(
        self,
        runtime_factory: R,
    ) -> TransparentProxyEngineBuilder<F, R> {
        TransparentProxyEngineBuilder {
            handler_factory: self.handler_factory,
            tcp_flow_buffer_size: self.tcp_flow_buffer_size,
            tcp_channel_capacity: self.tcp_channel_capacity,
            udp_channel_capacity: self.udp_channel_capacity,
            tcp_idle_timeout: self.tcp_idle_timeout,
            tcp_paused_drain_max_wait: self.tcp_paused_drain_max_wait,
            udp_max_flow_lifetime: self.udp_max_flow_lifetime,
            decision_deadline: self.decision_deadline,
            decision_deadline_action: self.decision_deadline_action,
            app_message_deadline: self.app_message_deadline,
            opaque_config: self.opaque_config,
            runtime_factory,
        }
    }
}

impl<F, RF> TransparentProxyEngineBuilder<F, RF>
where
    F: TransparentProxyHandlerFactory,
    RF: TransparentProxyAsyncRuntimeFactory,
{
    rama_utils::macros::generate_set_and_with! {
        /// Define what size to use for the TCP flow buffer (`None` will use default)
        pub fn tcp_flow_buffer_size(mut self, size: Option<usize>) -> Self
        {
            self.tcp_flow_buffer_size = size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Capacity (in chunks) of each per-flow TCP ingress / egress mpsc channel
        /// between the Swift FFI boundary and the Rust bridge tasks.
        ///
        /// Bounds the worst-case memory pinned by a slow service before Swift is
        /// told to stop reading from the kernel and wait for the matching
        /// `on_*_read_demand` callback. `None` uses the default.
        pub fn tcp_channel_capacity(mut self, capacity: Option<usize>) -> Self
        {
            self.tcp_channel_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Capacity (in datagrams) of each per-flow UDP ingress / egress mpsc
        /// channel. UDP datagrams are dropped when the channel is full
        /// (matching wire-level UDP semantics). `None` uses the default.
        pub fn udp_channel_capacity(mut self, capacity: Option<usize>) -> Self
        {
            self.udp_channel_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Per-flow idle timeout for TCP bridges.
        ///
        /// When set, the per-flow TCP bridge closes with reason `idle_timeout`
        /// when no byte progress has been observed in either direction within
        /// the configured window. `None` (the default) disables idle detection.
        ///
        /// The bridge naturally terminates on EOF / errors / shutdown regardless
        /// of this setting; the idle timeout exists as a backstop against
        /// "stale flows" that never observe an EOF (e.g. after the host has been
        /// asleep and the kernel-side flow ownership has gone stale).
        ///
        /// Defaults to [`DEFAULT_TCP_IDLE_TIMEOUT`] (15 minutes) — a
        /// generous backstop, not a primary aging mechanism. Opt out
        /// with [`without_tcp_idle_timeout`] only if your deployment
        /// has another mechanism for reaping wedged bridges; with
        /// neither this nor an eventual `engine.stop()` a bridge that
        /// wedges outside its `select!` arms can sit forever, since
        /// `cancel()` deliberately does NOT abort bridge tasks (they
        /// exit naturally via `flow_guard.cancelled()` so the
        /// post-loop close-event emission runs).
        ///
        /// [`DEFAULT_TCP_IDLE_TIMEOUT`]: super::DEFAULT_TCP_IDLE_TIMEOUT
        /// [`without_tcp_idle_timeout`]: Self::without_tcp_idle_timeout
        pub fn tcp_idle_timeout(mut self, timeout: Option<Duration>) -> Self
        {
            self.tcp_idle_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum time a per-flow TCP bridge will park on a `Paused`
        /// ack waiting for the peer's drain signal before closing the
        /// flow with `BridgeCloseReason::PausedTimeout`.
        ///
        /// Backstops a stuck downstream writer (a Swift `flow.write`
        /// completion handler that never invokes `signalServerDrain`,
        /// a logic bug that clears `pausedSignaled` without firing
        /// `onDrained`, etc.) so the bridge can't wedge waiting for
        /// a notification that never arrives.
        ///
        /// `None` (the default) uses the engine's built-in 60-second
        /// constant. Configure shorter values in tests; configure
        /// longer values if your downstream pump is genuinely
        /// expected to stay paused for minutes.
        pub fn tcp_paused_drain_max_wait(mut self, wait: Option<Duration>) -> Self
        {
            self.tcp_paused_drain_max_wait = wait;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum lifetime of a single per-flow UDP service task.
        ///
        /// When set, the engine wraps `service.serve(bridge).await` with a
        /// `tokio::time::timeout` of this duration; on expiry the service
        /// task is dropped and the flow's close path runs.
        ///
        /// Defaults to [`DEFAULT_UDP_MAX_FLOW_LIFETIME`] (15 minutes).
        /// Opt out with [`without_udp_max_flow_lifetime`] if you have
        /// an external mechanism for reaping stuck flows.
        ///
        /// **Semantics: max-lifetime cap, not idle detection.** Picks a
        /// hard upper bound on per-flow service-task longevity so a
        /// flow that never sees an explicit close (Swift-side bug,
        /// app death without flow close, kernel slot leaked, etc.)
        /// eventually frees its per-flow state.
        ///
        /// Production: pick a duration noticeably longer than your
        /// longest legitimate UDP flow (DNS sub-second; QUIC/long-poll
        /// tens of minutes).
        ///
        /// [`DEFAULT_UDP_MAX_FLOW_LIFETIME`]: super::DEFAULT_UDP_MAX_FLOW_LIFETIME
        /// [`without_udp_max_flow_lifetime`]: Self::without_udp_max_flow_lifetime
        pub fn udp_max_flow_lifetime(mut self, lifetime: Option<Duration>) -> Self
        {
            self.udp_max_flow_lifetime = lifetime;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum time the engine will wait for a flow handler to produce a
        /// decision (Intercept / Passthrough / Blocked).
        ///
        /// If `match_tcp_flow` / `match_udp_flow` does not return within
        /// the deadline, the engine takes the configured
        /// [`DecisionDeadlineAction`] for that flow rather than holding kernel
        /// flow ownership indefinitely.
        ///
        /// Defaults to [`DEFAULT_DECISION_DEADLINE`] (3 seconds). The
        /// deadline is always-on; tune it rather than disable it.
        ///
        /// [`DEFAULT_DECISION_DEADLINE`]: super::DEFAULT_DECISION_DEADLINE
        pub fn decision_deadline(mut self, deadline: Duration) -> Self
        {
            self.decision_deadline = Some(deadline);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Action to take when a flow handler exceeds the configured
        /// [`Self::decision_deadline`].
        ///
        /// Default: [`DecisionDeadlineAction::Block`].
        pub fn decision_deadline_action(mut self, action: DecisionDeadlineAction) -> Self
        {
            self.decision_deadline_action = Some(action);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum time a `handle_app_message` invocation may run
        /// before being abandoned and replied with `None`.
        ///
        /// `handle_app_message` is dispatched synchronously on Apple's
        /// `NETransparentProxyProvider` provider queue; a hung handler
        /// would otherwise wedge the entire provider's
        /// `handleAppMessage` flow indefinitely. This deadline is the
        /// backstop against that.
        ///
        /// `None` (the default) reuses [`Self::decision_deadline`] —
        /// which preserves the historical behavior. Set this
        /// explicitly when:
        ///
        /// * `decision_deadline` is tuned tight (sub-second) for
        ///   snappy per-flow decisions, but app messages may
        ///   legitimately need a longer budget (an "install root CA"
        ///   XPC bridge, a bulk-config refresh).
        /// * Or the inverse: app messages are always quick, but
        ///   `decision_deadline` is generous because flow handlers
        ///   need to do real work — you want a tighter cap on
        ///   misbehaving app-message handlers.
        ///
        /// Independent of `decision_deadline`; set both if you need
        /// different budgets.
        pub fn app_message_deadline(mut self, deadline: Duration) -> Self
        {
            self.app_message_deadline = Some(deadline);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        #[must_use]
        #[doc(hidden)]
        /// Unstable API only meant for generated code.
        ///
        /// # Security
        ///
        /// Opaque config is intended for non-sensitive runtime settings only
        /// (timeouts, domain exclusions, feature flags, and similar public info).
        /// Apple logs the payload automatically — it will appear in system diagnostic
        /// output with no ability to suppress this. Never put secrets, private keys,
        /// or credentials here; use the system keychain for sensitive material instead
        /// or transport it over a secure XPC connection yourself.
        pub fn opaque_config(mut self, opaque_config: Option<Arc<[u8]>>) -> Self {
            self.opaque_config = opaque_config;
            self
        }
    }

    pub fn build(self) -> Result<TransparentProxyEngine<F::Handler>, BoxError> {
        let Self {
            handler_factory,
            tcp_flow_buffer_size,
            tcp_channel_capacity,
            udp_channel_capacity,
            tcp_idle_timeout,
            tcp_paused_drain_max_wait,
            udp_max_flow_lifetime,
            decision_deadline,
            decision_deadline_action,
            app_message_deadline,
            opaque_config,
            runtime_factory,
        } = self;

        // Reject explicit `Some(0)` rather than silently falling back to the
        // default. `tokio::sync::mpsc::channel(0)` panics, `tokio::io::duplex(0)`
        // deadlocks the per-flow service on its first `write_all` (the writer
        // immediately backs off waiting for the non-existent reader), and
        // a misconfigured capacity is more useful as a build-time error than
        // as a footgun. `None` continues to mean "use the default".
        if matches!(tcp_flow_buffer_size, Some(0)) {
            return Err(
                OpaqueError::from_static_str("tcp_flow_buffer_size must be > 0").into_box_error(),
            );
        }
        if matches!(tcp_channel_capacity, Some(0)) {
            return Err(
                OpaqueError::from_static_str("tcp_channel_capacity must be > 0").into_box_error(),
            );
        }
        if matches!(udp_channel_capacity, Some(0)) {
            return Err(
                OpaqueError::from_static_str("udp_channel_capacity must be > 0").into_box_error(),
            );
        }

        let rt = runtime_factory
            .create_async_runtime(opaque_config.as_deref())
            .context("TransparentProxyEngineBuilder: create async runtime")?;

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = {
            let _enter = rt.enter();
            Shutdown::new(async move {
                _ = stop_rx.await;
            })
        };
        let guard = shutdown.guard();
        let ctx = TransparentProxyServiceContext {
            executor: Executor::graceful(guard),
            opaque_config,
        };
        // Drive the inner tokio runtime directly (rather than the
        // wrapper's `block_on`) so the handler factory future does not
        // need to satisfy the `'static` bound that dial9's
        // spawn-then-await indirection requires. dial9 wake-tracking on
        // the one-shot handler-construction future is uninteresting
        // anyway.
        let handler = rt
            .tokio_runtime()
            .block_on(handler_factory.create_transparent_proxy_handler(ctx))
            .map_err(Into::into)?;

        Ok(TransparentProxyEngine {
            rt,
            handler,
            tcp_flow_buffer_size: tcp_flow_buffer_size
                .unwrap_or(super::DEFAULT_TCP_FLOW_BUFFER_SIZE),
            tcp_channel_capacity: tcp_channel_capacity
                .unwrap_or(super::DEFAULT_TCP_CHANNEL_CAPACITY),
            udp_channel_capacity: udp_channel_capacity
                .unwrap_or(super::DEFAULT_UDP_CHANNEL_CAPACITY),
            tcp_idle_timeout,
            tcp_paused_drain_max_wait,
            udp_max_flow_lifetime,
            decision_deadline: decision_deadline.unwrap_or(super::DEFAULT_DECISION_DEADLINE),
            decision_deadline_action: decision_deadline_action
                .unwrap_or(DecisionDeadlineAction::Block),
            // `None` here resolves to `decision_deadline` at use-site
            // (see `handle_app_message`); we don't bake the resolution
            // in here so future `set_decision_deadline`-style
            // mutators (none today) would naturally reflect.
            app_message_deadline,
            shutdown: Some(shutdown),
            stop_trigger: Some(stop_tx),
        })
    }
}
