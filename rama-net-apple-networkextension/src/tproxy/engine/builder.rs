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
            // `without_*()` methods.
            tcp_idle_timeout: Some(super::DEFAULT_TCP_IDLE_TIMEOUT),
            tcp_paused_drain_max_wait: Some(super::DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT),
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
        /// Per-direction TCP duplex buffer size. `None` uses the default.
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
        /// Max-lifetime cap on a per-flow UDP service task (NOT idle
        /// detection). Defaults to [`DEFAULT_UDP_MAX_FLOW_LIFETIME`]
        /// (15 minutes); opt out with `without_udp_max_flow_lifetime`.
        /// Pick longer than your longest legitimate UDP flow (DNS
        /// sub-second; QUIC / long-poll tens of minutes).
        ///
        /// [`DEFAULT_UDP_MAX_FLOW_LIFETIME`]: super::DEFAULT_UDP_MAX_FLOW_LIFETIME
        pub fn udp_max_flow_lifetime(mut self, lifetime: Option<Duration>) -> Self
        {
            self.udp_max_flow_lifetime = lifetime;
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
    pub(super) fn current_tcp_paused_drain_max_wait(&self) -> Option<Duration> {
        self.tcp_paused_drain_max_wait
    }
}
