//! QUIC interception for UDP flows.
//!
//! One app socket may talk to several servers, so a flow is split into one association per
//! destination it addresses, each peeked on its own before any egress exists. QUIC to a name
//! that is not excluded is terminated with the TCP relay's CA and its HTTP/3 relayed request by
//! request; anything else is forwarded to its destination untouched.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rama::{
    Layer as _, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    graceful::WeakScope,
    http::{
        HeaderName, HeaderValue,
        layer::set_header::SetResponseHeaderLayer,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        address::Host,
        apple::networkextension::{
            UdpFlow, UdpFlowSender, UdpFlowSocket,
            process::AuditToken,
            tproxy::{TransparentProxyFlowMeta, TransparentProxyNetworkPath},
        },
        client::{ConnectRequest, ConnectorTarget},
        stream::Socket as _,
        tls::ApplicationProtocol,
    },
    quic::{
        proto::VarInt,
        proxy::{
            InputWithQuicClientHello, PeekQuicClientHelloService, QuicMigrationConfig,
            QuicMigrationDecision, QuicMigrationFailureAction, QuicMigrationInput,
            QuicMigrationLayer, QuicMigrationTrigger, QuicMitmIngressByIdentity, QuicMitmRelay,
            QuicNetworkAvailability, QuicNetworkChanges, QuicPathAction, QuicPeekFallbackPolicy,
            QuicPeekRejection, QuicRelay, QuicTransportReplacement,
        },
        tls::BoringTlsProvider,
    },
    service::service_fn,
    telemetry::tracing,
    tls::alpn::AlpnRouter,
    udp::{
        DatagramDemux, DemuxConfig, DemuxedSocket, PrefixedDatagramSocket, SharedQueueBudget,
        proxy::{DatagramForwardService, DatagramToProxyBridge, EcnPolicy, UdpConnector},
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
    /// Connections belong to the provider, so closing the original flow does not end them.
    pub(super) scope: WeakScope,
    /// Never join paths from different process identities, including PID reuse.
    pub(super) migration: QuicMitmIngressByIdentity<AuditToken>,
    pub(super) network: QuicNetworkChanges,
    pub(super) egress_preparations: Arc<tokio::sync::Semaphore>,
}

/// One flow's associations, each a destination the app addressed.
fn demux_config(flow_bytes: NonZeroUsize) -> DemuxConfig {
    DemuxConfig {
        associations: rama::utils::macros::nonzero!(16),
        queue: rama::utils::macros::nonzero!(64),
        idle_timeout: Duration::from_secs(30),
        receive_bytes: NonZeroUsize::new(kib(64)).expect("nonzero"),
        queued_bytes: flow_bytes,
    }
}

type Association = PrefixedDatagramSocket<DemuxedSocket<UdpFlowSender>>;

/// Serve one UDP flow until it ends.
pub(super) async fn serve(flow: UdpFlow, path: QuicPath, scope: WeakScope) {
    let QuicPath {
        state,
        limiter,
        flow_bytes,
        budget,
        scope: provider_scope,
        migration,
        network,
        egress_preparations,
    } = path;
    let bundle_identifier = flow
        .extensions()
        .get_arc::<TransparentProxyFlowMeta>()
        .and_then(|meta| meta.source_app_bundle_identifier.clone());
    // Without an authenticated process identity, keep this flow isolated. A bounded cache
    // prevents short-lived processes from creating an unbounded collection of endpoints.
    let audit = flow
        .extensions()
        .get_ref::<TransparentProxyFlowMeta>()
        .filter(|meta| {
            meta.local_endpoint.as_ref().is_some_and(|local| {
                local.port != 0 && matches!(&local.host, Host::Address(ip) if !ip.is_unspecified())
            })
        })
        .and_then(|meta| meta.source_app_audit_token);
    let migration_ingress = audit.and_then(|identity| migration.get_or_create(identity));
    let forward = DatagramToProxyBridge::extension_connector_target(DatagramForwardService::new(
        NonZeroUsize::new(kib(64)).expect("nonzero"),
        EcnPolicy::Discard,
    ));

    let route = {
        let scope = if migration_ingress.is_some() {
            provider_scope
        } else {
            scope.clone()
        };
        let migration_ingress = migration_ingress.clone();
        let forward = forward.clone();
        service_fn(move |input: InputWithQuicClientHello<Association>| {
            let network = network.clone();
            let egress_preparations = egress_preparations.clone();
            let migration_ingress = migration_ingress.clone();
            let settings = state.load_full();
            let exclusions = DomainExclusionList::new(settings.exclude_domains.iter());
            let scope = scope.clone();
            let forward = forward.clone();
            let name = input.peeked.client_hello.ext_server_name().cloned();
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
                if let Some(permit) = permit {
                    let supervisor = migration_ingress.clone();
                    let intercept = async move {
                        let _permit = permit;
                        tracing::debug!(?name, "tproxy quic intercepting");
                        let egress_tls = settings
                            .server_auth
                            .quic(settings.tls_mitm_relay.keylog_intent_ref().clone());
                        // HTTP/3 can multiplex ordinary requests and MASQUE tunnels.
                        // Transport settings precede those requests: native datagrams
                        // need room for an inner QUIC Initial on both hops, and the
                        // outer idle timeout must outlive the tunnel's idle policy.
                        let mut transport = rama::http::client::masque_quic_transport();
                        rama::http::core::h3::connection::Config::default()
                            .configure_transport(&mut transport)?;
                        let transport = Arc::new(transport);
                        let h3 = Http3MitmRelay::new(scope.clone())
                            .with_datagram_relay(rama::proxy::masque::connect_udp::mitm::relay(
                                scope.clone(),
                            ))
                            .with_http_middleware((
                                ConsumeErrLayer::trace_as_debug()
                                    .with_response(DefaultErrorResponse),
                                SetResponseHeaderLayer::overriding(
                                    HeaderName::from_static("x-rama-mitm"),
                                    HeaderValue::from_static("h3"),
                                ),
                                rama::proxy::masque::connect_udp::mitm::ConnectUdpMitmLayer::new(),
                                ArcLayer::new(),
                            ));
                        // Use the same connector and original policy extensions as the initial
                        // bridge. A global path hint must never create a direct-routing bypass.
                        let target = input
                            .input
                            .extensions()
                            .get_ref::<ConnectorTarget>()
                            .ok_or_else(|| {
                                BoxError::from_static_str("missing QUIC connector target")
                            })?
                            .0
                            .clone();
                        let request = ConnectRequest::new_with_extensions(
                            target,
                            input.input.extensions().fork(),
                        );
                        let initial_revision = network
                            .snapshot()
                            .egress
                            .context
                            .get_ref::<TransparentProxyNetworkPath>()
                            .map_or(0, |path| path.routing_revision);
                        let prepared_revision = Arc::new(AtomicU64::new(initial_revision));
                        let policy = service_fn(move |event: QuicMigrationInput| {
                            let request = request.clone();
                            let prepared_revision = prepared_revision.clone();
                            async move {
                                // An ingress port change alone says nothing about our upstream.
                                if !matches!(
                                    event.trigger,
                                    QuicMigrationTrigger::Initial
                                        | QuicMigrationTrigger::NetworkChanged
                                ) || event.network.egress.availability
                                    != QuicNetworkAvailability::Available
                                {
                                    return Ok::<_, BoxError>(QuicMigrationDecision::default());
                                }
                                let revision = event
                                    .network
                                    .egress
                                    .context
                                    .get_ref::<TransparentProxyNetworkPath>()
                                    .map_or(0, |path| path.routing_revision);
                                if revision == prepared_revision.load(Ordering::Relaxed) {
                                    return Ok(QuicMigrationDecision::default());
                                }
                                let connected = UdpConnector::new().serve(request).await?;
                                let replacement = QuicTransportReplacement::new(connected.conn)?
                                    .with_on_applied(move || {
                                        prepared_revision.store(revision, Ordering::Relaxed);
                                    });
                                Ok(QuicMigrationDecision {
                                    ingress: QuicPathAction::Keep,
                                    egress: QuicPathAction::Replace(replacement),
                                })
                            }
                        });
                        let migration_policy = QuicMigrationLayer::new(
                            policy,
                            QuicMigrationConfig {
                                scope: scope.clone(),
                                decision_timeout: Duration::from_secs(5),
                                failure_action: QuicMigrationFailureAction::Keep,
                                failure_code: VarInt::from_u32(FAILURE),
                            },
                        )
                        .with_network_changes(network)
                        .with_decision_gate(egress_preparations.clone());
                        let terminate = DatagramToProxyBridge::extension_connector_target(
                            QuicMitmRelay::new(
                                settings.tls_mitm_relay.issuer().clone(),
                                scope.clone(),
                                egress_tls,
                                VarInt::from_u32(FAILURE),
                            )
                            .maybe_with_migration_ingress(migration_ingress)
                            .with_ingress_transport(transport.clone())
                            .with_egress_transport(transport)
                            .into_layer(
                                migration_policy.into_layer(
                                    AlpnRouter::new(ApplicationProtocol::HTTP_3, h3)
                                        .with_fallback(QuicRelay::new(VarInt::from_u32(FAILURE))),
                                ),
                            ),
                        );
                        terminate.serve(input).await.map(drop)
                    };
                    if let Some(supervisor) = supervisor {
                        supervisor.run_connection(intercept).await
                    } else {
                        intercept.await
                    }
                } else {
                    tracing::debug!(?name, "tproxy quic forwarding");
                    forward.serve(input.input).await.map(drop)
                }
            }
        })
    };
    // Best-effort demo: fail open for every peek rejection (see README interception policy).
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route)
        .with_fallback_policy(QuicPeekFallbackPolicy::ALL)
        .with_fallback(service_fn(move |input: Association| {
            let forward = forward.clone();
            async move { forward_uninspected(&forward, input).await.map(drop) }
        }));
    let demux = DatagramDemux::new(UdpFlowSocket::new(flow), demux_config(flow_bytes))
        .with_shared_budget(budget);
    let result = if let Some(ingress) = migration_ingress {
        demux.serve(scope, inspect.with_router(ingress)).await
    } else {
        demux.serve(scope, inspect).await
    };
    if let Err(error) = result {
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
