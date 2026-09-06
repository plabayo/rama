use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::telemetry::tracing;
use rama::tls::KeyLogIntent;
use rama::tls::keylog::{
    KeyLogSink, NoopKeyLogSink, RotatingFileKeyLogSink, RotationPeriod, ToggleableKeyLogSink,
};
use rama::{
    Layer, Service,
    bytes::Bytes,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef,
    http::{
        Request, Response,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            dpi_proxy_credential::DpiProxyCredentialExtractorLayer,
            map_response_body::MapResponseBodyLayer,
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            upgrade::{
                HttpProxyConnectRelayServiceRequestMatcher, mitm::HttpUpgradeMitmRelayLayer,
            },
        },
        matcher::DomainMatcher,
        proxy::mitm::HttpMitmRelay,
        ws::handshake::{
            matcher::HttpWebSocketRelayServiceRequestMatcher, mitm::WebSocketRelayService,
        },
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, MapOutput, MapOutputLayer},
    net::{
        address::Domain,
        apple::networkextension::{
            NwTcpStream, TcpFlow,
            tproxy::{PromoteLayer, TransparentProxyServiceContext},
        },
        http::server::HttpPeekRouter,
        proxy::IoForwardService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    service::MirrorService,
    tls::{boring::proxy::TlsMitmRelay, server::PeekTlsClientHelloService},
};

use crate::{
    concurrency::ConcurrencyReservation,
    demo_trace_traffic::DemoTraceTrafficLayer,
    state::{LiveSettings, SharedState},
    tls::mitm_relay_policy::TlsMitmRelayPolicyLayer,
};

const HIJACK_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");

#[derive(Clone)]
pub(super) struct DemoTcpMitmService {
    state: SharedState,
    peek_duration_s: f64,
}

impl DemoTcpMitmService {
    pub(super) async fn try_new(
        ctx: TransparentProxyServiceContext,
    ) -> Result<(Self, SharedState), BoxError> {
        let demo_config = crate::config::DemoProxyConfig::from_opaque_config(ctx.opaque_config())?;
        let (ca_crt, ca_key) = crate::tls::load_or_create_mitm_ca(
            demo_config.ca_cert_pem.as_deref(),
            demo_config.ca_key_pem.as_deref(),
        )?;
        let ca_crt_pem: Bytes = Bytes::from(ca_crt.to_pem().context("encode root ca cert to pem")?);

        // Build the keylog pipeline unconditionally and bake it into
        // the relay as `KeyLogIntent::Custom`. Runtime on/off is a
        // single AtomicBool flip via XPC — see
        // `LiveSettings::tls_keylog_toggle`. Default is OFF; nothing
        // is persisted across sysext restarts. Rotated files (hourly,
        // 8 h retention) land in `<storage_dir>/keylog/` (Wireshark:
        // Preferences → Protocols → TLS → (Pre)-Master-Secret log
        // filename → pick the most recent file).
        let (tls_keylog_intent, tls_keylog_toggle) = if let Some(dir) = crate::utils::storage_dir()
        {
            let keylog_dir = dir.join("keylog");
            let rotating = RotatingFileKeyLogSink::try_open_with(
                &keylog_dir,
                "sslkeylog",
                RotationPeriod::HOURLY,
                Some(Duration::from_hours(8)),
            )
            .context("open rotating tls keylog sink")?;
            let toggleable = Arc::new(ToggleableKeyLogSink::new(rotating));
            let toggle = toggleable.toggle();
            tracing::info!(
                dir = %keylog_dir.display(),
                "TLS keylog pipeline ready (OFF by default; toggle via XPC)",
            );
            (
                KeyLogIntent::Custom(toggleable as Arc<dyn KeyLogSink>),
                toggle,
            )
        } else {
            tracing::warn!(
                "TLS keylog: no storage_dir → Noop sink; toggle XPC route exists but writes \
                    go nowhere",
            );
            let toggleable = Arc::new(ToggleableKeyLogSink::new(NoopKeyLogSink));
            let toggle = toggleable.toggle();
            (
                KeyLogIntent::Custom(toggleable as Arc<dyn KeyLogSink>),
                toggle,
            )
        };
        let mut tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key);
        tls_mitm_relay.set_keylog_intent(tls_keylog_intent);

        let initial_settings = LiveSettings {
            html_badge_enabled: demo_config.html_badge_enabled,
            html_badge_label: demo_config.html_badge_label.clone(),
            exclude_domains: demo_config.exclude_domains.clone(),
            ca_crt_pem,
            tls_mitm_relay,
            tls_keylog_toggle,
        };
        let state: SharedState = Arc::new(arc_swap::ArcSwap::from_pointee(initial_settings));

        let service = Self {
            state: state.clone(),
            peek_duration_s: demo_config.peek_duration_s,
        };

        Ok((service, state))
    }

    pub(super) fn new_intercept_service(
        &self,
        reservation: ConcurrencyReservation,
    ) -> TcpInterceptService {
        TcpInterceptService {
            mitm: self.clone(),
            reservation,
        }
    }

    fn new_bridge_service<Ingress, Egress>(
        &self,
        exec: Executor,
        within_connect_tunnel: bool,
    ) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone
    where
        Ingress: Io + Unpin + ExtensionsRef,
        Egress: Io + Unpin + ExtensionsRef,
    {
        let settings = self.state.load_full();
        let peek_duration = Duration::from_secs_f64(self.peek_duration_s.max(0.5));

        let http_mitm_svc = HttpMitmRelay::new(exec.clone()).with_http_middleware(
            self.http_relay_middleware(exec.clone(), within_connect_tunnel, settings.clone()),
        );
        // `promote_passthrough` is ONLY safe on a raw kernel-flow ↔
        // NWConnection bridge — see `PromoteHandle`'s safety contract.
        // Inside TLS / HTTP MITM the bridge carries post-decryption
        // cleartext, but the underlying kernel flow + NWConnection
        // still carry mutually-undecryptable TLS bytes, so a cutover
        // there would forward garbage. Wrap the outer fallbacks
        // (non-TLS plain traffic, SNI-excluded TLS passthrough);
        // leave the inner fallback (post-TLS-MITM cleartext) as plain
        // `IoForwardService`.
        let plain_passthrough = MapOutput::new(IoForwardService::new(exec.clone()), drop);
        let promote_passthrough = PromoteLayer::new().into_layer(plain_passthrough.clone());

        let inner_http_router = HttpPeekRouter::new(http_mitm_svc.clone())
            .with_known_non_http_protocol_methods()
            .with_peek_timeout(peek_duration)
            .with_fallback(plain_passthrough);
        let outer_http_router = HttpPeekRouter::new(http_mitm_svc)
            .with_known_non_http_protocol_methods()
            .with_peek_timeout(peek_duration)
            .with_fallback(promote_passthrough.clone());

        let excluded_domains =
            crate::policy::DomainExclusionList::new(settings.exclude_domains.iter());
        let tls_mitm_relay_policy = TlsMitmRelayPolicyLayer::new(exec.clone())
            .with_excluded_domains(excluded_domains)
            .with_fallback(promote_passthrough);

        let app_mitm_layer = PeekTlsClientHelloService::new(
            (tls_mitm_relay_policy, settings.tls_mitm_relay.clone()).into_layer(inner_http_router),
        )
        .with_peek_timeout(peek_duration)
        .with_fallback(outer_http_router);

        if within_connect_tunnel {
            return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
        }

        let socks5_mitm_relay = Socks5MitmRelayService::new(exec, app_mitm_layer.clone());
        let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay)
            .with_peek_timeout(peek_duration)
            .with_fallback(app_mitm_layer);

        Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn http_relay_middleware<S>(
        &self,
        exec: Executor,
        within_connect_tunnel: bool,
        settings: Arc<LiveSettings>,
    ) -> impl Layer<S, Service: Service<Request, Output = Response, Error = BoxError> + Clone>
    + Send
    + Sync
    + 'static
    + Clone
    where
        S: Service<Request, Output = Response, Error = BoxError>,
    {
        let excluded_domains =
            crate::policy::DomainExclusionList::new(settings.exclude_domains.iter());
        let html_badge_layer = crate::http::html::HtmlBadgeLayer::new()
            .with_enabled(settings.html_badge_enabled)
            .with_badge_label(&settings.html_badge_label)
            .with_excluded_domains(excluded_domains);

        let decompressor_matcher = html_badge_layer.decompression_matcher();
        let nested_mitm = self.clone();
        let ca_crt_pem = settings.ca_crt_pem.clone();

        (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            // A MITM relay forwards whatever `Accept-Encoding` the client sends; it must not turn
            // an unsatisfiable negotiation into its own 406, so opt out of that enforcement.
            StreamCompressionLayer::new()
                .with_enforce_not_acceptable(false)
                .with_compress_predicate(MirrorDecompressed::new()),
            html_badge_layer,
            DecompressionLayer::new()
                .with_insert_accept_encoding_header(false)
                // A truncated egress body (e.g. stale path after a network change)
                // must not abort the rewritten client stream; end it cleanly so the
                // client gets a short-but-well-formed page, not an integrity error.
                .with_tolerate_decode_errors(true)
                .with_matcher(decompressor_matcher),
            SetResponseHeaderLayer::if_not_present_typed(
                crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
            ),
            DemoTraceTrafficLayer,
            SetRequestHeaderLayer::if_not_present_typed(
                crate::http::headers::XRamaTransparentProxyObservedHeader::new(),
            ),
            HttpUpgradeMitmRelayLayer::new(
                exec.clone(),
                (
                    HttpWebSocketRelayServiceRequestMatcher::new(WebSocketRelayService::new(
                        DemoTraceTrafficLayer.into_layer(MirrorService::new()),
                    )),
                    HttpProxyConnectRelayServiceRequestMatcher::new(if within_connect_tunnel {
                        // CONNECT tunnel inner stream — post-HTTP-decoding,
                        // NOT a raw kernel-flow bridge. Do not promote here;
                        // see `PromoteHandle`'s safety contract.
                        (ConsumeErrLayer::trace_as_debug(), MapOutputLayer::new(drop))
                            .into_layer(IoForwardService::new(exec))
                            .boxed()
                    } else {
                        nested_mitm.new_bridge_service(exec, true).boxed()
                    }),
                ),
            ),
            DpiProxyCredentialExtractorLayer::new(),
            HijackLayer::new(
                DomainMatcher::exact(HIJACK_DOMAIN),
                Arc::new(crate::http::hijack::new_service(ca_crt_pem)),
            ),
            ArcLayer::new(),
        )
    }
}

#[derive(Clone)]
pub(super) struct TcpInterceptService {
    mitm: DemoTcpMitmService,
    reservation: ConcurrencyReservation,
}

impl Service<BridgeIo<TcpFlow, NwTcpStream>> for TcpInterceptService {
    type Output = ();
    type Error = Infallible;

    async fn serve(
        &self,
        bridge: BridgeIo<TcpFlow, NwTcpStream>,
    ) -> Result<Self::Output, Self::Error> {
        let BridgeIo(ingress, egress) = bridge;

        // The egress NWConnection is already established by Swift — no TcpConnector needed.
        let permit = self.reservation.activate();
        ingress.extensions().insert(permit);

        let flow_exec = ingress.executor().cloned().unwrap_or_default();
        let mitm_svc = self.mitm.new_bridge_service(flow_exec, false);

        mitm_svc.serve(BridgeIo(ingress, egress)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::utils::octets::{kib, mib};
    use rama::{ServiceInput, crypto::cert::boring::generate_certificate_authority_x509};
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader, duplex},
        sync::oneshot,
    };

    #[tokio::test]
    async fn http_response_drains_after_client_write_half_close() {
        // Build the real application router without reading or changing the system keychain.
        let (cert, key) = generate_certificate_authority_x509(&Default::default()).unwrap();
        let settings = LiveSettings {
            html_badge_enabled: false,
            html_badge_label: String::new(),
            exclude_domains: Vec::new(),
            ca_crt_pem: cert.to_pem().unwrap().into(),
            tls_mitm_relay: TlsMitmRelay::new_cached_in_memory(cert, key),
            tls_keylog_toggle: ToggleableKeyLogSink::new(NoopKeyLogSink).toggle(),
        };
        let mitm = DemoTcpMitmService {
            state: Arc::new(arc_swap::ArcSwap::from_pointee(settings)),
            peek_duration_s: 0.5,
        };

        for within_connect_tunnel in [false, true] {
            for body_len in [kib(64), mib(1)] {
                for eager_buffered in [false, true] {
                    tokio::time::timeout(Duration::from_secs(10), async {
                        let body: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();
                        let request_headers = format!(
                            "POST /octet-stream HTTP/1.1\r\nHost: upstream.test\r\n\
                             Content-Type: application/octet-stream\r\n\
                             Content-Length: {body_len}\r\nConnection: close\r\n\r\n"
                        );
                        // Streaming exercises backpressure; eager buffering puts the complete
                        // request and FIN before the router's very first poll.
                        let ingress_capacity = if eager_buffered {
                            request_headers.len() + body.len() + 1
                        } else {
                            4096
                        };
                        let (mut client, ingress) = duplex(ingress_capacity);
                        let (egress, origin) = duplex(4096);
                        let relay =
                            mitm.new_bridge_service(Executor::default(), within_connect_tunnel);
                        let (write_closed, after_write_close) = oneshot::channel();
                        let (responding, response_started) = oneshot::channel();

                        if eager_buffered {
                            client.write_all(request_headers.as_bytes()).await.unwrap();
                            client.write_all(&body).await.unwrap();
                            client.shutdown().await.unwrap();
                        }
                        let client_exchange = async {
                            if !eager_buffered {
                                client.write_all(request_headers.as_bytes()).await.unwrap();
                                client.write_all(&body).await.unwrap();
                                client.shutdown().await.unwrap();
                            }
                            write_closed.send(()).unwrap();
                            if !eager_buffered {
                                response_started.await.unwrap();
                                // Exercise backpressure while response bytes are waiting to drain.
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                            let mut response = Vec::new();
                            client.read_to_end(&mut response).await.unwrap();
                            let boundary = response
                                .windows(4)
                                .position(|w| w == b"\r\n\r\n")
                                .expect("complete response headers");
                            let headers = std::str::from_utf8(&response[..boundary]).unwrap();
                            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
                            assert!(
                                headers
                                    .to_ascii_lowercase()
                                    .contains("x-rama-tproxy-observed:")
                            );
                            assert_eq!(&response[boundary + 4..], body.as_slice());
                        };
                        let origin_exchange = async {
                            // A separately framed upstream, independent of HTTP server EOF defaults.
                            let mut origin = BufReader::new(origin);
                            let mut headers = String::new();
                            loop {
                                let start = headers.len();
                                assert_ne!(origin.read_line(&mut headers).await.unwrap(), 0);
                                if &headers[start..] == "\r\n" {
                                    break;
                                }
                            }
                            assert!(headers.starts_with("POST /octet-stream HTTP/1.1\r\n"));
                            assert!(
                                headers
                                    .to_ascii_lowercase()
                                    .contains(&format!("content-length: {body_len}\r\n"))
                            );
                            let mut received = vec![0; body_len];
                            origin.read_exact(&mut received).await.unwrap();
                            assert_eq!(received, body);
                            after_write_close.await.unwrap();
                            // The response is deliberately unavailable until after the client's FIN.
                            if !eager_buffered {
                                responding.send(()).unwrap();
                            }
                            let headers = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                                 Content-Length: {body_len}\r\nConnection: close\r\n\r\n"
                            );
                            origin.write_all(headers.as_bytes()).await.unwrap();
                            origin.write_all(&received).await.unwrap();
                            origin.shutdown().await.unwrap();
                        };
                        let (result, (), ()) = tokio::join!(
                            relay.serve(BridgeIo(
                                ServiceInput::new(ingress),
                                ServiceInput::new(egress)
                            )),
                            client_exchange,
                            origin_exchange,
                        );
                        result.unwrap();
                    })
                    .await
                    .expect("HTTP half-close exchange and relay must finish");
                }
            }
        }
    }
}
