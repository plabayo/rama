use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
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
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, TimeoutLayer},
    net::{
        address::Domain,
        apple::networkextension::{TcpFlow, tproxy::TransparentProxyServiceContext},
        client::{ConnectorService, EstablishedClientConnection},
        http::server::HttpPeekRouter,
        proxy::{IoForwardService, ProxyTarget},
        socket::{SocketOptions, opts::TcpKeepAlive},
        tls::server::PeekTlsClientHelloService,
    },
    proxy::socks5::{proxy::mitm::Socks5MitmRelayService, server::Socks5PeekRouter},
    rt::Executor,
    service::MirrorService,
    tcp::client::service::TcpConnector,
    telemetry::tracing,
    tls::boring::proxy::{
        TlsMitmRelay,
        cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
    },
};

use crate::{
    concurrency::ConcurrencyReservation, config::DemoProxyConfig,
    demo_trace_traffic::DemoTraceTrafficLayer, tls::mitm_relay_policy::TlsMitmRelayPolicyLayer,
};

const HIJACK_DOMAIN: Domain = Domain::from_static("mitm.ramaproxy.org");

const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(1);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 5;

type DemoTlsMitmRelay = TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>;

#[derive(Clone)]
pub(super) struct DemoTcpMitmService {
    demo_config: DemoProxyConfig,
    tls_mitm_relay_policy: TlsMitmRelayPolicyLayer,
    tls_mitm_relay: DemoTlsMitmRelay,
    ca_crt_pem_bytes: &'static [u8],
    connect_timeout: Duration,
}

impl DemoTcpMitmService {
    pub(super) async fn try_new(ctx: TransparentProxyServiceContext) -> Result<Self, BoxError> {
        let demo_config = DemoProxyConfig::from_opaque_config(ctx.opaque_config())?;
        let ca_crt_pem = resolve_ca_cert_pem(&demo_config)?;
        let ca_crt = rama::tls::boring::core::x509::X509::from_pem(ca_crt_pem.as_bytes())
            .context("parse host-provided MITM CA certificate PEM")?;
        let ca_key_pem = resolve_ca_key_pem(&demo_config)?;
        let ca_key =
            rama::tls::boring::core::pkey::PKey::private_key_from_pem(ca_key_pem.as_bytes())
                .context("parse host-provided MITM CA key PEM")?;
        let ca_crt_pem_bytes: &[u8] = ca_crt
            .to_pem()
            .context("encode root ca cert to pem")?
            .leak();

        let excluded_domains =
            crate::policy::DomainExclusionList::new(demo_config.exclude_domains.iter());
        let tls_mitm_relay_policy =
            TlsMitmRelayPolicyLayer::new().with_excluded_domains(excluded_domains);

        Ok(Self {
            connect_timeout: Duration::from_millis(demo_config.tcp_connect_timeout_ms.max(50)),
            demo_config,
            tls_mitm_relay_policy,
            tls_mitm_relay: TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key),
            ca_crt_pem_bytes,
        })
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
        let peek_duration = Duration::from_secs_f64(self.demo_config.peek_duration_s.max(0.5));

        let http_mitm_svc = HttpMitmRelay::new(exec.clone())
            .with_http_middleware(self.http_relay_middleware(exec, within_connect_tunnel));

        let maybe_http_mitm_svc = HttpPeekRouter::new(http_mitm_svc)
            .with_peek_timeout(peek_duration)
            .with_fallback(IoForwardService::new());

        let app_mitm_layer = PeekTlsClientHelloService::new(
            (
                self.tls_mitm_relay_policy.clone(),
                self.tls_mitm_relay.clone(),
            )
                .into_layer(maybe_http_mitm_svc.clone()),
        )
        .with_peek_timeout(peek_duration)
        .with_fallback(maybe_http_mitm_svc);

        if within_connect_tunnel {
            return Either::A(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer));
        }

        let socks5_mitm_relay = Socks5MitmRelayService::new(app_mitm_layer.clone());
        let mitm_svc = Socks5PeekRouter::new(socks5_mitm_relay)
            .with_peek_timeout(peek_duration)
            .with_fallback(app_mitm_layer);

        Either::B(ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc))
    }

    fn http_relay_middleware<S>(
        &self,
        exec: Executor,
        within_connect_tunnel: bool,
    ) -> impl Layer<S, Service: Service<Request, Output = Response, Error = BoxError> + Clone>
    + Send
    + Sync
    + 'static
    + Clone
    where
        S: Service<Request, Output = Response, Error = BoxError>,
    {
        let excluded_domains =
            crate::policy::DomainExclusionList::new(self.demo_config.exclude_domains.iter());
        let html_badge_layer = crate::http::html::HtmlBadgeLayer::new()
            .with_enabled(self.demo_config.html_badge_enabled)
            .with_badge_label(&self.demo_config.html_badge_label)
            .with_excluded_domains(excluded_domains);

        let decompressor_matcher = html_badge_layer.decompression_matcher();
        let nested_mitm = self.clone();

        (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            StreamCompressionLayer::new().with_compress_predicate(MirrorDecompressed::new()),
            html_badge_layer,
            DecompressionLayer::new()
                .with_insert_accept_encoding_header(false)
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
                        ConsumeErrLayer::trace_as_debug()
                            .into_layer(IoForwardService::new())
                            .boxed()
                    } else {
                        nested_mitm.new_bridge_service(exec, true).boxed()
                    }),
                ),
            ),
            DpiProxyCredentialExtractorLayer::new(),
            HijackLayer::new(
                DomainMatcher::exact(HIJACK_DOMAIN),
                Arc::new(crate::http::hijack::new_service(self.ca_crt_pem_bytes)),
            ),
            ArcLayer::new(),
        )
    }
}

fn resolve_ca_cert_pem(demo_config: &DemoProxyConfig) -> Result<String, BoxError> {
    load_ca_secret(
        demo_config,
        demo_config.ca_cert_secret_name.as_deref(),
        "certificate",
    )
}

fn resolve_ca_key_pem(demo_config: &DemoProxyConfig) -> Result<String, BoxError> {
    load_ca_secret(
        demo_config,
        demo_config.ca_key_secret_name.as_deref(),
        "private key",
    )
}

fn load_ca_secret(
    demo_config: &DemoProxyConfig,
    service_name: Option<&str>,
    secret_kind: &'static str,
) -> Result<String, BoxError> {
    let Some(service_name) = service_name.filter(|value| !value.is_empty()) else {
        return Err(OpaqueError::from_static_str(
            "CA secret missing: protected-storage secret name not provided in transparent proxy opaque config",
        )
        .context_field("secret_kind", secret_kind));
    };
    let Some(account_name) = demo_config
        .ca_secret_account
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return Err(OpaqueError::from_static_str(
            "CA secret missing: protected-storage secret account not provided in transparent proxy opaque config",
        )
        .context_field("secret_kind", secret_kind));
    };

    if let Some(access_group) = demo_config
        .ca_secret_access_group
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        return load_ca_secret_from_app_protected_storage(
            service_name,
            account_name,
            access_group,
            secret_kind,
        );
    }

    load_ca_secret_from_storage_dir(
        service_name,
        account_name,
        secret_kind,
        crate::utils::app_group_dir(),
    )
}

fn load_ca_secret_from_app_protected_storage(
    service_name: &str,
    account_name: &str,
    access_group: &str,
    secret_kind: &'static str,
) -> Result<String, BoxError> {
    tracing::info!(
        service = service_name,
        account = account_name,
        access_group,
        "loading MITM CA secret from app protected storage"
    );

    let secret = rama::net::apple::networkextension::app_protected_storage::load_raw_secret(
        service_name,
        account_name,
        Some(access_group),
    )
    .context("load MITM CA secret from app protected storage")?
    .ok_or_else(|| {
        OpaqueError::from_static_str("CA secret missing: app protected storage item was not found")
            .context_field("secret_kind", secret_kind)
            .context_field("service_name", service_name.to_owned())
    })?;

    String::from_utf8(secret).context("decode MITM CA secret as UTF-8")
}

fn load_ca_secret_from_storage_dir(
    service_name: &str,
    account_name: &str,
    secret_kind: &'static str,
    app_group_dir: Option<&'static std::path::PathBuf>,
) -> Result<String, BoxError> {
    // System Extensions run as root and cannot access user-owned keychains.
    // Prefer the shared app group container directory over the extension-private
    // storage dir so that the host app can write secrets there as a regular user.
    let base_dir = app_group_dir
        .or_else(|| crate::utils::storage_dir())
        .ok_or_else(|| {
            OpaqueError::from_static_str(
                "CA secret missing: neither app group directory nor transparent proxy storage directory is initialized",
            )
            .context_field("secret_kind", secret_kind)
        })?;
    let path = base_dir
        .join("secrets")
        .join(account_name)
        .join(format!("{service_name}.secret"));

    tracing::info!(
        path = %path.display(),
        service = service_name,
        account = account_name,
        "loading MITM CA secret from transparent proxy storage directory"
    );

    std::fs::read_to_string(&path)
        .context("read MITM CA secret from transparent proxy storage directory")
        .context_field("path", path.display().to_string())
}

#[derive(Clone)]
pub(super) struct TcpInterceptService {
    mitm: DemoTcpMitmService,
    reservation: ConcurrencyReservation,
}

impl Service<TcpFlow> for TcpInterceptService {
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, ingress: TcpFlow) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(egress_addr)) = ingress.extensions().get_ref().cloned() else {
            tracing::debug!("missing ProxyTarget in transparent proxy example tcp service");
            return Ok(());
        };

        let permit = self.reservation.activate();

        let flow_exec = ingress.executor().cloned().unwrap_or_default();
        let connector = tcp_connector_service(flow_exec.clone(), self.mitm.connect_timeout);
        let tcp_req = rama::tcp::client::Request::new_with_extensions(
            egress_addr.clone(),
            ingress.extensions().clone(),
        );

        let EstablishedClientConnection { conn: egress, .. } = match connector
            .connect(tcp_req)
            .await
            .context("establish tcp connection")
            .context_field("address", egress_addr.clone())
        {
            Ok(connection) => connection,
            Err(err) => {
                tracing::debug!(error = ?err, address = %egress_addr, "transparent proxy tcp connect failed");
                return Ok(());
            }
        };

        ingress.extensions().insert(permit);

        let mitm_svc = self.mitm.new_bridge_service(flow_exec, false);
        let _ = mitm_svc.serve(BridgeIo(ingress, egress)).await;
        Ok(())
    }
}

fn tcp_connector_service(
    exec: Executor,
    connect_timeout: Duration,
) -> impl ConnectorService<rama::tcp::client::Request, Connection: Io + Unpin + ExtensionsRef> + Clone
{
    TimeoutLayer::new(connect_timeout).into_layer(TcpConnector::new(exec).with_connector(Arc::new(
        SocketOptions {
            keep_alive: Some(true),
            tcp_keep_alive: Some(TcpKeepAlive {
                time: Some(TCP_KEEPALIVE_TIME),
                interval: Some(TCP_KEEPALIVE_INTERVAL),
                retries: Some(TCP_KEEPALIVE_RETRIES),
            }),
            ..SocketOptions::default_tcp()
        },
    )))
}
