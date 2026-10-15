//! QUIC interception for UDP flows.
//!
//! One app socket may talk to several servers, so a flow is split into one association per
//! destination it addresses, each peeked on its own before any egress exists. QUIC to a name
//! that is not excluded is terminated with the TCP relay's CA and its HTTP/3 relayed request by
//! request; anything else is forwarded to its destination untouched.

use std::{num::NonZeroUsize, time::Duration};

use rama::{
    Layer as _, Service,
    http::{
        HeaderName, HeaderValue,
        layer::set_header::SetResponseHeaderLayer,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        apple::networkextension::{
            UdpFlow, UdpFlowSender, UdpFlowSocket, tproxy::DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES,
        },
        tls::ApplicationProtocol,
    },
    quic::{
        proto::VarInt,
        proxy::{InputWithQuicClientHello, PeekQuicClientHelloService, QuicMitmRelay, QuicRelay},
        tls::BoringTlsProvider,
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
    tls::{
        alpn::AlpnRouter,
        client::{ServerVerifyMode, TlsClientConfig},
    },
    udp::{
        DatagramDemux, DemuxConfig, DemuxedSocket, PrefixedDatagramSocket,
        proxy::{DatagramForwardService, DatagramToProxyBridge, EcnPolicy},
    },
    utils::octets::kib,
};

use crate::{policy::DomainExclusionList, state::SharedState};

/// The application error code closing both hops when an interception fails.
const FAILURE: u32 = 0x0101;

/// One flow's associations, each a destination the app addressed.
const DEMUX: DemuxConfig = DemuxConfig {
    associations: NonZeroUsize::new(16).unwrap(),
    queue: NonZeroUsize::new(64).unwrap(),
    idle_timeout: Duration::from_secs(30),
    receive_bytes: NonZeroUsize::new(kib(64)).unwrap(),
    // What the engine lets one flow hold: the demux takes every datagram off the flow at once.
    queued_bytes: NonZeroUsize::new(DEFAULT_UDP_INGRESS_PER_FLOW_MAX_BYTES).unwrap(),
};

type Association = PrefixedDatagramSocket<DemuxedSocket<UdpFlowSender>>;

/// Serve one UDP flow until it ends.
pub(super) async fn serve(flow: UdpFlow, state: SharedState, exec: Executor) {
    let settings = state.load();
    let exclusions = DomainExclusionList::new(settings.exclude_domains.iter());
    // As the TCP relay does: the app judges the mirrored certificate, not the relay.
    let egress_tls = TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_keylog(settings.tls_mitm_relay.keylog_intent_ref().clone());
    let h3 = Http3MitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-rama-mitm"),
            HeaderValue::from_static("h3"),
        ),
        ArcLayer::new(),
    ));
    let terminate = DatagramToProxyBridge::extension_connector_target(
        QuicMitmRelay::new(
            settings.tls_mitm_relay.issuer().clone(),
            exec.clone(),
            egress_tls,
            VarInt::from_u32(FAILURE),
        )
        .into_layer(
            AlpnRouter::new(ApplicationProtocol::HTTP_3, h3)
                .with_fallback(QuicRelay::new(VarInt::from_u32(FAILURE))),
        ),
    );
    let forward = DatagramToProxyBridge::extension_connector_target(DatagramForwardService::new(
        NonZeroUsize::new(kib(64)).expect("nonzero"),
        EcnPolicy::Discard,
    ));
    drop(settings);

    let route = {
        let forward = forward.clone();
        service_fn(move |input: InputWithQuicClientHello<Association>| {
            let terminate = terminate.clone();
            let forward = forward.clone();
            let name = input.client_hello.client_hello.ext_server_name().cloned();
            let intercept = name
                .as_ref()
                .is_some_and(|name| !exclusions.is_excluded(name));
            async move {
                if intercept {
                    tracing::debug!(?name, "tproxy quic intercepting");
                    terminate.serve(input).await.map(drop)
                } else {
                    tracing::debug!(?name, "tproxy quic forwarding");
                    forward.serve(input.input).await.map(drop)
                }
            }
        })
    };
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route).with_fallback(
        service_fn(move |input: Association| {
            let forward = forward.clone();
            async move { forward.serve(input).await.map(drop) }
        }),
    );
    let demux = DatagramDemux::new(UdpFlowSocket::new(flow), DEMUX);
    if let Err(error) = demux.serve(exec, inspect).await {
        tracing::debug!(%error, "tproxy quic flow ended");
    }
}

/// Whether a flow to `port` is served by [`serve`] rather than the multi-peer loop.
pub(super) fn serves_port(quic_ports: &[u16], port: Option<u16>) -> bool {
    port.is_some_and(|port| quic_ports.contains(&port))
}
