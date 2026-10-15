//! QUIC interception for UDP flows.
//!
//! One app socket may talk to several servers, so a flow is split into one association per
//! destination it addresses, each peeked on its own before any egress exists. QUIC to a name
//! that is not excluded is terminated with the TCP relay's CA and its HTTP/3 relayed request by
//! request; anything else is forwarded to its destination untouched.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use rama::{
    Layer as _, Service,
    extensions::ExtensionsRef as _,
    http::{
        HeaderName, HeaderValue,
        layer::set_header::SetResponseHeaderLayer,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        address::Host,
        apple::networkextension::{
            UdpFlow, UdpFlowSender, UdpFlowSocket, tproxy::TransparentProxyFlowMeta,
        },
        stream::Socket as _,
        tls::ApplicationProtocol,
    },
    quic::{
        proto::VarInt,
        proxy::{
            InputWithQuicClientHello, PeekQuicClientHelloService, QuicMitmRelay,
            QuicPeekFallbackPolicy, QuicPeekRejection, QuicRelay,
        },
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
        DatagramDemux, DemuxConfig, DemuxedSocket, PrefixedDatagramSocket, SharedQueueBudget,
        proxy::{DatagramForwardService, DatagramToProxyBridge, EcnPolicy},
    },
    utils::octets::kib,
};

use crate::{concurrency::ConcurrencyLimiter, policy::DomainExclusionList, state::SharedState};

/// The application error code closing both hops when an interception fails.
const FAILURE: u32 = 0x0101;

/// What every flow on the QUIC path shares.
#[derive(Clone)]
pub(super) struct QuicPath {
    /// The live settings holding the TLS relay whose issuer QUIC interception shares.
    pub(super) state: SharedState,
    /// The intercept admission QUIC associations share with TCP flows.
    pub(super) limiter: Arc<ConcurrencyLimiter>,
    /// The engine's per-flow ingress bound: the demux takes every datagram off the flow at
    /// once, so its queues hold no more than the engine would.
    pub(super) flow_bytes: NonZeroUsize,
    /// The engine's global ingress bound, shared by every flow's queues.
    pub(super) budget: SharedQueueBudget,
}

/// One flow's associations, each a destination the app addressed.
fn demux_config(flow_bytes: NonZeroUsize) -> DemuxConfig {
    DemuxConfig {
        associations: NonZeroUsize::new(16).expect("nonzero"),
        queue: NonZeroUsize::new(64).expect("nonzero"),
        idle_timeout: Duration::from_secs(30),
        receive_bytes: NonZeroUsize::new(kib(64)).expect("nonzero"),
        queued_bytes: flow_bytes,
    }
}

type Association = PrefixedDatagramSocket<DemuxedSocket<UdpFlowSender>>;

/// Serve one UDP flow until it ends.
pub(super) async fn serve(flow: UdpFlow, path: QuicPath, exec: Executor) {
    let QuicPath {
        state,
        limiter,
        flow_bytes,
        budget,
    } = path;
    let bundle_identifier = flow
        .extensions()
        .get_arc::<TransparentProxyFlowMeta>()
        .and_then(|meta| meta.source_app_bundle_identifier.clone());
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
            // As TCP does: an intercept the limiter refuses passes through untouched.
            let permit = name
                .as_ref()
                .filter(|name| !exclusions.is_excluded(*name))
                .and_then(|name| {
                    let port = input.input.local_addr().map_or(0, |local| local.port);
                    limiter
                        .try_reserve(
                            port,
                            bundle_identifier.as_deref(),
                            Some(&Host::Name(name.clone())),
                        )
                        .inspect_err(|reason| {
                            tracing::debug!(?reason, ?name, "tproxy quic admission refused");
                        })
                        .ok()
                })
                .map(|reservation| reservation.activate());
            async move {
                if let Some(_permit) = permit {
                    tracing::debug!(?name, "tproxy quic intercepting");
                    terminate.serve(input).await.map(drop)
                } else {
                    tracing::debug!(?name, "tproxy quic forwarding");
                    forward.serve(input.input).await.map(drop)
                }
            }
        })
    };
    // Best-effort interception deliberately fails open for every peek rejection. A client
    // can evade inspection with a malformed, oversized, or stalled flight; this demo is
    // not an enforcement boundary. To reject those flights while permitting version
    // negotiation, use { unsupported_version: true, ..QuicPeekFallbackPolicy::NOT_QUIC }.
    // NOT_QUIC alone also rejects unsupported versions.
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route)
        .with_fallback_policy(QuicPeekFallbackPolicy::ALL)
        .with_fallback(service_fn(move |input: Association| {
            let forward = forward.clone();
            async move { forward_uninspected(&forward, input).await.map(drop) }
        }));
    let demux = DatagramDemux::new(UdpFlowSocket::new(flow), demux_config(flow_bytes))
        .with_shared_budget(budget);
    if let Err(error) = demux.serve(exec, inspect).await {
        tracing::debug!(%error, "tproxy quic flow ended");
    }
}

/// Whether a flow to `port` is served by [`serve`] rather than the multi-peer loop.
pub(super) fn serves_port(quic_ports: &[u16], port: Option<u16>) -> bool {
    port.is_some_and(|port| quic_ports.contains(&port))
}

/// Record only the bounded rejection class, never client identity or packet contents.
async fn forward_uninspected<T, S>(forward: &S, input: T) -> Result<S::Output, S::Error>
where
    T: rama::extensions::ExtensionsRef + Send,
    S: Service<T>,
{
    if let Some(rejection) = input.extensions().get_ref::<QuicPeekRejection>() {
        // The class belongs in the public message: Apple logging keeps fields private.
        tracing::info!("tproxy quic fail-open fallback: {rejection}");
    }
    forward.serve(input).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{extensions::Extensions, telemetry::tracing::instrument::WithSubscriber as _};
    use std::{io::Write, sync::RwLock};

    #[derive(Debug)]
    struct PrivateClientMarker;
    impl rama::extensions::Extension for PrivateClientMarker {}

    #[derive(Clone)]
    struct LogBuffer(Arc<RwLock<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.write().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn forwarded_rejections_are_observable_without_client_metadata() {
        let output = Arc::new(RwLock::new(Vec::new()));
        let writer = LogBuffer(output.clone());
        let subscriber = tracing::subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        async {
            for rejection in [
                QuicPeekRejection::NotQuic,
                QuicPeekRejection::UnsupportedVersion,
                QuicPeekRejection::Malformed,
                QuicPeekRejection::Budget,
                QuicPeekRejection::Deadline,
            ] {
                let input = Extensions::new();
                input.insert(rejection);
                input.insert(PrivateClientMarker);
                let forwarded = forward_uninspected(&(), input).await.unwrap();
                assert_eq!(forwarded.get_ref::<QuicPeekRejection>(), Some(&rejection));
                let log = String::from_utf8(output.read().unwrap().clone()).unwrap();
                assert!(log.contains(&format!("tproxy quic fail-open fallback: {rejection}")));
                assert!(!log.contains("PrivateClientMarker"));
            }
        }
        .with_subscriber(subscriber)
        .await;
    }
}
