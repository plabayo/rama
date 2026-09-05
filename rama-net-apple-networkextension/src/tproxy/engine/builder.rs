use rama_core::error::BoxErrorExt as _;
use std::sync::Arc;
use std::time::Duration;

use rama_core::{
    error::{BoxError, ErrorContext},
    rt::Executor,
};

use super::{
    DecisionDeadlineAction, DefaultTransparentProxyAsyncRuntimeFactory,
    TransparentProxyAsyncRuntimeFactory, TransparentProxyEngine, TransparentProxyHandler,
    TransparentProxyHandlerFactory, TransparentProxyServiceContext,
};

pub struct TransparentProxyEngineBuilder<F, R = DefaultTransparentProxyAsyncRuntimeFactory> {
    handler_factory: F,
    tcp_flow_buffer_size: Option<usize>,
    tcp_channel_capacity: Option<usize>,
    udp_channel_capacity: Option<usize>,
    udp_ingress_per_flow_max_bytes: Option<usize>,
    udp_ingress_global_max_bytes: Option<usize>,
    udp_ingress_probe_lease: Option<Duration>,
    tcp_idle_timeout: Option<Duration>,
    tcp_paused_drain_max_wait: Option<Duration>,
    udp_max_flow_lifetime: Option<Duration>,
    udp_idle_timeout: Option<Duration>,
    decision_deadline: Option<Duration>,
    decision_deadline_action: Option<DecisionDeadlineAction>,
    decision_concurrency_limit: Option<usize>,
    app_message_deadline: Option<Duration>,
    stop_drain_max_wait: Option<Duration>,
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
            udp_ingress_per_flow_max_bytes: None,
            udp_ingress_global_max_bytes: None,
            udp_ingress_probe_lease: None,
            // Timer defaults. The UDP idle timeout reaps quiet flows, while
            // the absolute UDP max lifetime is intentionally opt-in so active
            // long-lived QUIC / HTTP/3 sessions are not killed by age alone.
            tcp_idle_timeout: Some(super::DEFAULT_TCP_IDLE_TIMEOUT),
            tcp_paused_drain_max_wait: Some(super::DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT),
            udp_max_flow_lifetime: None,
            udp_idle_timeout: Some(super::DEFAULT_UDP_IDLE_TIMEOUT),
            decision_deadline: None,
            decision_deadline_action: None,
            decision_concurrency_limit: None,
            app_message_deadline: None,
            stop_drain_max_wait: Some(super::DEFAULT_STOP_DRAIN_MAX_WAIT),
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
            udp_ingress_per_flow_max_bytes: self.udp_ingress_per_flow_max_bytes,
            udp_ingress_global_max_bytes: self.udp_ingress_global_max_bytes,
            udp_ingress_probe_lease: self.udp_ingress_probe_lease,
            tcp_idle_timeout: self.tcp_idle_timeout,
            tcp_paused_drain_max_wait: self.tcp_paused_drain_max_wait,
            udp_max_flow_lifetime: self.udp_max_flow_lifetime,
            udp_idle_timeout: self.udp_idle_timeout,
            decision_deadline: self.decision_deadline,
            decision_deadline_action: self.decision_deadline_action,
            decision_concurrency_limit: self.decision_concurrency_limit,
            app_message_deadline: self.app_message_deadline,
            stop_drain_max_wait: self.stop_drain_max_wait,
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
        /// Maximum bytes handed to one borrowed Rust→Swift TCP write
        /// callback. The effective limit is the smaller of this value and
        /// [`TransparentProxyConfig::tcp_write_pump_max_pending_bytes`].
        /// `None` uses the 16 KiB default.
        ///
        /// [`TransparentProxyConfig::tcp_write_pump_max_pending_bytes`]: crate::tproxy::TransparentProxyConfig::tcp_write_pump_max_pending_bytes
        pub fn tcp_flow_buffer_size(mut self, size: Option<usize>) -> Self
        {
            self.tcp_flow_buffer_size = size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Capacity (in chunks) of each per-flow TCP ingress / egress mpsc
        /// channel. Bounds memory pinned by a slow service before Swift
        /// pauses kernel reads. `None` uses the default.
        pub fn tcp_channel_capacity(mut self, capacity: Option<usize>) -> Self
        {
            self.tcp_channel_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Capacity (in datagrams) of each per-flow UDP channel. Datagrams
        /// are dropped on overflow (UDP semantics). `None` uses the default.
        pub fn udp_channel_capacity(mut self, capacity: Option<usize>) -> Self
        {
            self.udp_channel_capacity = capacity;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum retained client-ingress payload bytes for one UDP flow.
        /// Reservations survive `Bytes` clones and are released only when the
        /// final payload owner drops. `None` uses 256 KiB. Values below the
        /// maximum UDP payload size (65,535 bytes) are rejected at build time.
        pub fn udp_ingress_per_flow_max_bytes(mut self, max_bytes: Option<usize>) -> Self
        {
            self.udp_ingress_per_flow_max_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Engine-wide maximum retained client-ingress UDP payload bytes.
        /// Shared by every flow created by this immutable engine generation.
        /// `None` uses 16 MiB. The value must be at least the configured
        /// per-flow byte cap.
        pub fn udp_ingress_global_max_bytes(mut self, max_bytes: Option<usize>) -> Self
        {
            self.udp_ingress_global_max_bytes = max_bytes;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Initial lifetime of one charged global-pressure read probe. A probe
        /// which is neither acknowledged nor delivered releases its credit at
        /// this deadline so a broken Apple callback cannot strand capacity.
        /// `None` uses 10 milliseconds. Zero and values above 60 seconds are
        /// rejected at build time.
        pub fn udp_ingress_probe_lease(mut self, lease: Option<Duration>) -> Self
        {
            self.udp_ingress_probe_lease = lease;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Per-flow TCP idle backstop. Defaults to
        /// [`DEFAULT_TCP_IDLE_TIMEOUT`] (15 minutes); opt out with
        /// `without_tcp_idle_timeout` only if you have another
        /// mechanism for reaping wedged bridges. `cancel()` does NOT
        /// abort bridge tasks (they exit cooperatively for clean
        /// close-event emission), so a bridge wedged outside its
        /// `select!` arms relies on this or `engine.stop()` to drain.
        ///
        /// [`DEFAULT_TCP_IDLE_TIMEOUT`]: super::DEFAULT_TCP_IDLE_TIMEOUT
        pub fn tcp_idle_timeout(mut self, timeout: Option<Duration>) -> Self
        {
            self.tcp_idle_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Cap on how long a TCP bridge parks waiting for the peer's
        /// drain signal after a `Paused` ack. Backstops a stuck
        /// downstream writer; flow closes with
        /// [`BridgeCloseReason::PausedTimeout`] on expiry. Defaults to
        /// [`DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT`] (60 seconds).
        ///
        /// [`BridgeCloseReason::PausedTimeout`]: rama_net::proxy::BridgeCloseReason::PausedTimeout
        /// [`DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT`]: super::DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT
        pub fn tcp_paused_drain_max_wait(mut self, wait: Option<Duration>) -> Self
        {
            self.tcp_paused_drain_max_wait = wait;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Optional max-lifetime cap on a per-flow UDP service task (NOT idle
        /// detection). Disabled by default so active long-lived QUIC / HTTP/3
        /// sessions are not terminated solely because of their age. Opt in
        /// with `with_udp_max_flow_lifetime`; the cap is absolute from session
        /// creation and does not reset on traffic. Pick a value longer than
        /// every legitimate UDP flow your application supports. Callers that
        /// want the conventional 15-minute value can pass
        /// [`DEFAULT_UDP_MAX_FLOW_LIFETIME`].
        ///
        /// [`DEFAULT_UDP_MAX_FLOW_LIFETIME`]: super::DEFAULT_UDP_MAX_FLOW_LIFETIME
        pub fn udp_max_flow_lifetime(mut self, lifetime: Option<Duration>) -> Self
        {
            self.udp_max_flow_lifetime = lifetime;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Per-UDP-flow idle timeout — close the flow when no
        /// datagrams have flowed in EITHER direction for this long.
        /// Resets on every observed ingress datagram (`on_client_datagram`)
        /// or service-emitted egress datagram (the `on_server_datagram`
        /// sink). Defaults to [`DEFAULT_UDP_IDLE_TIMEOUT`] (60 s);
        /// opt out with `without_udp_idle_timeout`.
        ///
        /// Distinct from [`Self::udp_max_flow_lifetime`]: that is a
        /// hard wall-clock cap from flow start (whether active or
        /// idle), this is reset-on-activity. Without it, a typical
        /// burst-then-quiet flow (a satisfied DNS query, a NAT
        /// binding probe, an mDNS announcement, …) remains registered until
        /// the service, Swift, engine shutdown, or an explicitly configured
        /// max-lifetime cap closes it — long enough to accumulate thousands
        /// of stale sessions under sustained device traffic.
        ///
        /// [`DEFAULT_UDP_IDLE_TIMEOUT`]: super::DEFAULT_UDP_IDLE_TIMEOUT
        pub fn udp_idle_timeout(mut self, timeout: Option<Duration>) -> Self
        {
            self.udp_idle_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Max time a flow handler may take to return an Intercept /
        /// Passthrough / Blocked decision before the configured
        /// [`DecisionDeadlineAction`] kicks in. Defaults to
        /// [`DEFAULT_DECISION_DEADLINE`] (3 seconds). Always-on; tune
        /// rather than disable.
        ///
        /// [`DEFAULT_DECISION_DEADLINE`]: super::DEFAULT_DECISION_DEADLINE
        pub fn decision_deadline(mut self, deadline: Duration) -> Self
        {
            self.decision_deadline = Some(deadline);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Action when a handler exceeds [`Self::decision_deadline`].
        /// Default [`DecisionDeadlineAction::Block`].
        pub fn decision_deadline_action(mut self, action: DecisionDeadlineAction) -> Self
        {
            self.decision_deadline_action = Some(action);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of TCP and UDP flow-policy decisions polled
        /// concurrently by one engine generation. Saturated flows use the
        /// handler's configured
        /// [`crate::tproxy::TransparentProxyConfig::flow_refusal_action`]
        /// without invoking policy. `None` uses
        /// [`DEFAULT_DECISION_CONCURRENCY_LIMIT`] (64).
        ///
        /// This is independent of admitted-flow limits and exists to bound
        /// pre-decision work when Apple delivers new-flow callbacks in
        /// parallel. It adds no per-packet work.
        ///
        /// [`DEFAULT_DECISION_CONCURRENCY_LIMIT`]: super::DEFAULT_DECISION_CONCURRENCY_LIMIT
        pub fn decision_concurrency_limit(mut self, limit: Option<usize>) -> Self
        {
            self.decision_concurrency_limit = limit;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Max time `handle_app_message` may run before being
        /// abandoned (provider gets a `None` reply). Apple dispatches
        /// `handleAppMessage` synchronously on the provider queue, so
        /// a hung handler would otherwise wedge the queue.
        ///
        /// `None` (the default) inherits [`Self::decision_deadline`].
        /// Set explicitly when app messages need a different budget
        /// from per-flow decisions.
        pub fn app_message_deadline(mut self, deadline: Duration) -> Self
        {
            self.app_message_deadline = Some(deadline);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Backstop on how long `engine.stop()` waits for engine-level
        /// graceful guards to drop before proceeding. Defaults to
        /// [`DEFAULT_STOP_DRAIN_MAX_WAIT`] (5 seconds). A normal stop
        /// resolves after per-flow close epilogues and lifecycle hooks
        /// finish. This bound only bites a flow task or handler hook
        /// ([`TransparentProxyHandler::on_system_sleep`] /
        /// `on_system_wake`) wedged on un-timed I/O. Tune rather than
        /// disable — there is deliberately no opt-out to an unbounded
        /// wait, since that is the hang this guards against.
        ///
        /// [`DEFAULT_STOP_DRAIN_MAX_WAIT`]: super::DEFAULT_STOP_DRAIN_MAX_WAIT
        /// [`TransparentProxyHandler::on_system_sleep`]: super::TransparentProxyHandler::on_system_sleep
        pub fn stop_drain_max_wait(mut self, wait: Duration) -> Self
        {
            self.stop_drain_max_wait = Some(wait);
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
            udp_ingress_per_flow_max_bytes,
            udp_ingress_global_max_bytes,
            udp_ingress_probe_lease,
            tcp_idle_timeout,
            tcp_paused_drain_max_wait,
            udp_max_flow_lifetime,
            udp_idle_timeout,
            decision_deadline,
            decision_deadline_action,
            decision_concurrency_limit,
            app_message_deadline,
            stop_drain_max_wait,
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
            return Err(BoxError::from_static_str(
                "tcp_flow_buffer_size must be > 0",
            ));
        }
        if matches!(tcp_channel_capacity, Some(0)) {
            return Err(BoxError::from_static_str(
                "tcp_channel_capacity must be > 0",
            ));
        }
        if matches!(udp_channel_capacity, Some(0)) {
            return Err(BoxError::from_static_str(
                "udp_channel_capacity must be > 0",
            ));
        }
        if matches!(decision_concurrency_limit, Some(0)) {
            return Err(BoxError::from_static_str(
                "decision_concurrency_limit must be > 0",
            ));
        }
        let udp_ingress_per_flow_max_bytes =
            udp_ingress_per_flow_max_bytes.unwrap_or(super::DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES);
        if udp_ingress_per_flow_max_bytes < super::MAX_UDP_DATAGRAM_PAYLOAD_SIZE {
            return Err(BoxError::from_static_str(
                "udp_ingress_per_flow_max_bytes must be >= 65535",
            ));
        }
        let udp_ingress_global_max_bytes =
            udp_ingress_global_max_bytes.unwrap_or(super::DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES);
        if udp_ingress_global_max_bytes == 0 {
            return Err(BoxError::from_static_str(
                "udp_ingress_global_max_bytes must be > 0",
            ));
        }
        if udp_ingress_global_max_bytes < udp_ingress_per_flow_max_bytes {
            return Err(BoxError::from_static_str(
                "udp_ingress_global_max_bytes must be >= udp_ingress_per_flow_max_bytes",
            ));
        }
        let udp_ingress_probe_lease =
            udp_ingress_probe_lease.unwrap_or(super::DEFAULT_UDP_INGRESS_PROBE_LEASE);
        if udp_ingress_probe_lease.is_zero() {
            return Err(BoxError::from_static_str(
                "udp_ingress_probe_lease must be > 0",
            ));
        }
        if udp_ingress_probe_lease > super::MAX_UDP_INGRESS_PROBE_LEASE {
            return Err(BoxError::from_static_str(
                "udp_ingress_probe_lease must be <= 60 seconds",
            ));
        }

        let rt = runtime_factory
            .create_async_runtime(opaque_config.as_deref())
            .context("TransparentProxyEngineBuilder: create async runtime")?;

        let provider_pid = std::process::id();
        let provider_generation = super::next_provider_generation();

        let pair = super::build_shutdown_pair(&rt);
        let guard = pair.shutdown.guard();
        let ctx = TransparentProxyServiceContext {
            executor: Executor::graceful(guard.clone()),
            opaque_config,
            provider_pid,
            provider_generation,
        };
        // Handler construction may borrow from the factory, so use the
        // runtime's direct, untracked entry point rather than spawning an
        // owned task.
        let handler = rt
            .block_on_borrowed(handler_factory.create_transparent_proxy_handler(ctx))
            .map_err(Into::into)?;
        // Startup configuration is immutable for one engine lifecycle on the
        // Swift side. Cache the same snapshot here so the Rust→Swift write
        // chunk bound cannot drift from the value Swift applies to its pumps.
        let transparent_proxy_config = handler.transparent_proxy_config();
        let udp_ingress_budget = Arc::new(super::UdpIngressBudget::new_with_probe_lease(
            udp_ingress_global_max_bytes,
            udp_ingress_probe_lease,
        ));
        udp_ingress_budget.start_coordinator(&rt, guard);

        Ok(TransparentProxyEngine {
            rt: Some(rt),
            provider_pid,
            provider_generation,
            handler,
            transparent_proxy_config,
            tcp_flow_buffer_size: tcp_flow_buffer_size
                .unwrap_or(super::DEFAULT_TCP_FLOW_BUFFER_SIZE),
            tcp_channel_capacity: tcp_channel_capacity
                .unwrap_or(super::DEFAULT_TCP_CHANNEL_CAPACITY),
            udp_channel_capacity: udp_channel_capacity
                .unwrap_or(super::DEFAULT_UDP_CHANNEL_CAPACITY),
            udp_ingress_per_flow_max_bytes,
            udp_ingress_budget,
            tcp_idle_timeout,
            tcp_paused_drain_max_wait,
            udp_max_flow_lifetime,
            udp_idle_timeout,
            decision_deadline: decision_deadline.unwrap_or(super::DEFAULT_DECISION_DEADLINE),
            decision_deadline_action: decision_deadline_action
                .unwrap_or(DecisionDeadlineAction::Block),
            decision_concurrency: Arc::new(super::DecisionConcurrencyGate::new(
                decision_concurrency_limit.unwrap_or(super::DEFAULT_DECISION_CONCURRENCY_LIMIT),
            )),
            // `None` here resolves to `decision_deadline` at use-site
            // (see `handle_app_message`); we don't bake the resolution
            // in here so future `set_decision_deadline`-style
            // mutators (none today) would naturally reflect.
            app_message_deadline,
            stop_drain_max_wait: stop_drain_max_wait.unwrap_or(super::DEFAULT_STOP_DRAIN_MAX_WAIT),
            shutdown: parking_lot::Mutex::new(Some(pair)),
        })
    }
}

impl<F, R> TransparentProxyEngineBuilder<F, R> {
    /// Backstop-default introspection for tests. The three backstops below
    /// are the last lines of defense against a per-flow bridge that has
    /// wedged outside of its `select!` arms — once any of them expires the
    /// engine fires `on_server_closed` and the Swift side can `cancel()`
    /// the registered NWConnection. Removing any default (back to `None`)
    /// would let such a bridge live indefinitely, holding both the Rust
    /// session and the macOS flow registration; the regression tests in
    /// `lifecycle.rs` use these accessors to pin the defaults so a future
    /// edit cannot silently drop them.
    #[cfg(test)]
    pub(super) fn current_tcp_idle_timeout(&self) -> Option<Duration> {
        self.tcp_idle_timeout
    }

    #[cfg(test)]
    pub(super) fn current_udp_max_flow_lifetime(&self) -> Option<Duration> {
        self.udp_max_flow_lifetime
    }

    #[cfg(test)]
    pub(super) fn current_udp_idle_timeout(&self) -> Option<Duration> {
        self.udp_idle_timeout
    }

    #[cfg(test)]
    pub(super) fn current_tcp_paused_drain_max_wait(&self) -> Option<Duration> {
        self.tcp_paused_drain_max_wait
    }

    #[cfg(test)]
    pub(super) fn current_stop_drain_max_wait(&self) -> Option<Duration> {
        self.stop_drain_max_wait
    }
}
