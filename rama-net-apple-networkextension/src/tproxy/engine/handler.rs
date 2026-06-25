use std::{convert::Infallible, future::Future};

use rama_core::{Service, bytes::Bytes, error::BoxError, io::BridgeIo, rt::Executor};

use crate::{
    NwTcpStream, TcpFlow, UdpFlow,
    tproxy::{TransparentProxyConfig, TransparentProxyFlowMeta, types::NwTcpConnectOptions},
};

use super::TransparentProxyServiceContext;

pub trait TransparentProxyHandlerFactory: Send + Sync + 'static {
    type Handler: TransparentProxyHandler;
    type Error: Into<BoxError>;

    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send;
}

impl<Handler, Error, F, Fut> TransparentProxyHandlerFactory for F
where
    Handler: TransparentProxyHandler,
    Error: Into<BoxError>,
    F: Fn(TransparentProxyServiceContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Handler, Error>> + Send,
{
    type Handler = Handler;
    type Error = Error;

    #[inline(always)]
    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        (self)(ctx)
    }
}

// `Intercept` is much larger than the unit variants (it carries the full
// `TransparentProxyFlowMeta`), but this value is short-lived: it is produced per
// flow by the matcher and consumed immediately. Boxing it would add a per-flow
// heap allocation on the hot path for no real benefit, so allow the size skew.
#[expect(
    clippy::large_enum_variant,
    reason = "short-lived per-flow value; boxing would add a hot-path allocation"
)]
pub enum FlowAction<S> {
    Passthrough,
    Blocked,
    Intercept {
        service: S,
        meta: TransparentProxyFlowMeta,
    },
}

pub trait TransparentProxyHandler: Clone + Send + Sync + 'static {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig;

    /// Handle a provider message from the container app.
    ///
    /// The FFI bridge collapses `None` and `Some(Bytes::new())` to the same
    /// "no reply" outcome on the Swift side (see the `BytesOwned` shim in
    /// `rama_transparent_proxy_engine_handle_app_message`). To send a
    /// distinguishable acknowledgement, return a non-empty payload.
    fn handle_app_message(
        &self,
        _exec: Executor,
        message: Bytes,
    ) -> impl Future<Output = Option<Bytes>> + Send + '_ {
        tracing::debug!(
            message_len = message.len(),
            "transparent proxy app message received without custom handler implementation"
        );
        std::future::ready(None)
    }

    /// Return custom options for the egress `NWConnection` on TCP flows.
    ///
    /// Called by the Swift layer before opening the intercepted flow.
    /// `meta` is the same metadata that will subsequently be passed to
    /// [`match_tcp_flow`](Self::match_tcp_flow).
    ///
    /// Return `None` (the default) to let Swift use sane `NWParameters` defaults.
    fn egress_tcp_connect_options(
        &self,
        _meta: &TransparentProxyFlowMeta,
    ) -> Option<NwTcpConnectOptions> {
        None
    }

    /// Decide what to do with an incoming TCP flow.
    ///
    /// # Async-correctness contract
    ///
    /// This method **must be async-correct**: it must not block the executor
    /// thread. In particular, do not perform synchronous DNS resolution or any
    /// other blocking work inline. Wrap any unavoidable sync work in
    /// [`tokio::task::spawn_blocking`].
    ///
    /// On macOS, blocking the executor here can deadlock against
    /// `mDNSResponder` (the system DNS daemon), because mDNSResponder's UDP
    /// traffic flows through the same provider that's calling this method —
    /// see the `tproxy/apple` documentation on Bonjour DNS.
    ///
    /// The engine enforces a configurable deadline
    /// ([`crate::tproxy::TransparentProxyEngineBuilder::with_decision_deadline`])
    /// on this call. A handler that does not return within the deadline is
    /// treated according to the configured
    /// [`crate::tproxy::DecisionDeadlineAction`] (default: block).
    fn match_tcp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        std::future::ready(FlowAction::<NopSvc>::Passthrough)
    }

    /// Decide what to do with an incoming UDP flow.
    ///
    /// UDP is stateless and asymmetric, so the engine does *not* hand
    /// the service a `BridgeIo`. The service receives a [`UdpFlow`] —
    /// the ingress half only — and is fully responsible for egress:
    /// opening sockets, pooling them across flows, applying any
    /// platform-specific binding (interface, service class, marking,
    /// metadata propagation) before `bind`/`connect`. Every datagram
    /// surfaced through `flow.recv()` carries its peer, so a service
    /// can do `send_to(peer)` on a single pooled socket and dispatch
    /// the right way without holding per-peer state.
    ///
    /// The flow's [`rama_core::extensions::ExtensionsRef`] surface
    /// carries the per-flow [`TransparentProxyFlowMeta`] so the
    /// service can read the originating-app info (audit token, PID,
    /// bundle ID, remote endpoint) it needs to decorate egress
    /// sockets before binding.
    ///
    /// **Backpressure is lossy.** Unlike TCP, the ingress channel
    /// feeding `flow.recv()` is bounded (see
    /// [`crate::tproxy::TransparentProxyEngineBuilder::with_udp_channel_capacity`])
    /// and an `on_client_datagram` arriving while the channel is
    /// full is *dropped*, not blocked. This matches UDP's
    /// connection-less semantics — every layer above (the app, the
    /// kernel, the wire) already tolerates packet loss — and keeps
    /// a slow / stuck service from stalling kernel-side reads. A
    /// service that wants higher reliability should drain promptly
    /// or raise the channel capacity at builder time.
    ///
    /// The same async-correctness contract as
    /// [`Self::match_tcp_flow`] applies — see that method for details.
    fn match_udp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> impl Future<Output = FlowAction<impl Service<UdpFlow, Output = (), Error = Infallible>>>
    + Send
    + '_ {
        std::future::ready(FlowAction::<NopSvc>::Passthrough)
    }

    /// Notification that the system is about to sleep. This is a
    /// brief pause-and-return hook — flows are NOT torn down, so
    /// don't assume a quiesced data path. Opportunity to flush
    /// metrics, snapshot pending work, etc. Default: trace log.
    ///
    /// The returned future runs detached on the engine's graceful
    /// [`Executor`] and holds an engine shutdown guard until it
    /// completes. Bound any network I/O you do here with a timeout:
    /// an un-timed fetch over a link that dies across the suspend
    /// would otherwise hold the guard and delay `engine` teardown
    /// (capped, but not for free). Same applies to
    /// [`Self::on_system_wake`].
    fn on_system_sleep(&self, _exec: Executor) -> impl Future<Output = ()> + Send + '_ {
        tracing::debug!(
            target: "rama_apple_ne::tproxy::lifecycle",
            "system sleep (default handler)"
        );
        std::future::ready(())
    }

    /// Notification that the system has just resumed from sleep.
    /// Flows that did not survive the suspend are reaped by the
    /// per-flow failure path; new flows arrive via `match_tcp_flow`
    /// / `match_udp_flow` as normal. Default: trace log.
    ///
    /// See [`Self::on_system_sleep`] for the guard-holding /
    /// un-timed-I/O contract — it applies here too.
    fn on_system_wake(&self, _exec: Executor) -> impl Future<Output = ()> + Send + '_ {
        tracing::debug!(
            target: "rama_apple_ne::tproxy::lifecycle",
            "system wake (default handler)"
        );
        std::future::ready(())
    }
}

#[derive(Debug, Clone)]
struct NopSvc;

impl<Input> Service<Input> for NopSvc {
    type Output = ();
    type Error = Infallible;

    fn serve(
        &self,
        _: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        std::future::ready(Ok(()))
    }
}
