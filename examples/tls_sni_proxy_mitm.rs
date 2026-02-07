//! An example SNI proxy with MITM capabilities. See how to run the example below
//! for more information. Also checkout the book for more information
//! about SNI proxies in general: <https://ramaproxy.org/book/proxies/sni.html>
//!
//! Within the code of this example (a fully self-contained example as usual),
//! you'll also find pointers and hints at things you want to especially pay
//! attention to in case you wish to develop a production-ready SNI proxy
//! based on this example. The pointers are just the bare minimum of things
//! you would want to address prior to shipping it. Be aware and be careful.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_sni_proxy_mitm --features=http-full,boring
//! ```
//!
//! # Expected output
//!
//! Usually you combine a SNI proxy together with either:
//!
//! - a firewall or similar network service
//! - or a kernel-like module that allows you to hijack a network interface
//!
//! Such that you can reroute specific or all traffic to your SNI proxy.
//!
//! To keep it simple for this example you can just use the `--connect-to`
//! flag provided by `curl` to force a connection to the SNI proxy
//! running locally regardless of the URI or headers.
//!
//! ## example.com
//!
//! ```sh
//! curl -v -k \
//!     --connect-to '::127.0.0.1:62045' \
//!     https://example.com
//! ```
//!
//! You'll see our own custom example page,
//! as hardcoded in the example file at the bottom,
//! instead of the "usual" example page.
//!
//! ## *.ramaproxy.org
//!
//! ```sh
//! curl -v -k \
//!     --connect-to '::127.0.0.1:62045' \
//!     https://echo.ramaproxy.org
//! ```
//!
//! This traffic will be forwarded to the actual server,
//! and as such you'll get the echo output coming
//! from the public service we offer free of charge. However
//! we still MITM'd the traffic and injected a request + response
//! `x-proxy-via` http header. The request header can be seen in the echo response
//! as proof and the response header you can observe thanks
//! to the usage of `-v` (verbose) curl mode.
//!
//! ## other https traffic
//!
//! ```sh
//! curl -v -k \
//!     --connect-to '::127.0.0.1:62045' \
//!     https://plabayo.tech
//! ```
//!
//! Using the `SniRouter` in this example we choose to only MITM traffic which is
//! of interest to us. It is possible you do not need this in your production proxy,
//! e.g. in case you only redirect traffic of interest as determined by your network
//! component such as an enterprise firewall. In this example we choose
//! this approach however which should in theory be anyway fairly reliable as
//! the SNI tls extensions is set by all clients we are aware of.
//!
//! As a consequence you'll see the regular plabayo homepage index.html response payload,
//! without anything in that payload or its headers modified.
//!
//! ## non-tls traffic
//!
//! ```sh
//! curl -v -k \
//!     --connect-to '::127.0.0.1:62045' \
//!     http://example.com
//! ```
//!
//! In this example we have chosen to reject non-tls traffic, as such you'll
//! notice that if you try to send for exampel plain-text HTTP traffic over it,
//! that the connection will be simply aborted.

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{ExtensionsMut, ExtensionsRef},
    graceful::Shutdown,
    http::{
        Body, HeaderValue, Request, Response,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer,
        },
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::{
        Protocol,
        address::{Domain, HostWithPort, SocketAddress},
        client::{ConnectorTarget, pool::http::HttpPooledConnectorConfig},
        http::RequestContext,
        tls::{
            ApplicationProtocol,
            client::ServerVerifyMode,
            server::{
                ServerAuth, ServerCertIssuerData, ServerConfig, SniPeekStream, SniRequest,
                SniRouter,
            },
        },
    },
    rt::Executor,
    stream::Stream,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{
        self, Level,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::{client::TlsConnectorDataBuilder, server::TlsAcceptorLayer},
};

use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();
    let exec = Executor::graceful(shutdown.guard());

    let tls_service_data = {
        // NOTE for production use:
        //
        // - you most likely want a dynamic server config,
        //   such that you can adapt it per domain group (e.g. specific ALPN needs)
        // - you most likely want an external cert issuer
        //   to issue appropriate certs for each domain,
        //
        // this being an example however we keep things simple.
        // Just know you are only limited by your own imagination.
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
            ..ServerConfig::new(ServerAuth::CertIssuer(ServerCertIssuerData::default()))
        };
        tls_server_config
            .try_into()
            .context("create tls server config")?
    };

    const INTERFACE: SocketAddress = SocketAddress::local_ipv4(62045);

    tracing::info!("bind SNI MITM proxy to {INTERFACE}");
    let tcp_listener = TcpListener::bind(INTERFACE, exec.clone())
        .await
        .context("bind tcp proxy")
        .context_field("interface", INTERFACE)?;

    let https_client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        // NOTE: in a production svc you would probably want a dynamic proxy config,
        // based on a combination of static knowledge and dynamic input. You most likely
        // also wouldn't want to disable server verification... This is however a good
        // enough for a testable example
        .with_tls_support_using_boringssl(Some(Arc::new(
            TlsConnectorDataBuilder::new_http_auto()
                .with_server_verify_mode(ServerVerifyMode::Disable),
        )))
        .with_default_http_connector(exec)
        // NOTE: up to you define if a pool is acceptable, and especially a global one...
        .try_with_connection_pool(HttpPooledConnectorConfig::default())
        .context("build easy web client w/ pool")?
        .build_client();

    let optional_dns_overwrite_layer_used_for_e2e_only =
        std::env::var("EXAMPLE_EGRESS_SERVER_ADDR")
            .ok()
            .map(|raw_addr| {
                let addr: SocketAddress = raw_addr
                    .parse()
                    .context("parse raw addr as SocketAddress")?;
                let connect_target = ConnectorTarget(addr.into());
                Ok::<_, BoxError>(AddInputExtensionLayer::new(connect_target))
            })
            .transpose()
            .context(
                "create optional ConnectorTarget (used for e2e testing only, to force a dest)",
            )?;

    // NOTE: this example shows a very simplistic HTTPS stack,
    // for productions scenarios you probably want to expand this
    // in terms of security, error scenario handling, protocol support, etc...
    let http_svc = Arc::new(
        (
            ConsumeErrLayer::trace(Level::DEBUG),
            MapResponseBodyLayer::new(Body::new),
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::new(),
        )
            .into_layer(HttpsMITMService { https_client }),
    );

    let https_svc = TlsAcceptorLayer::new(tls_service_data)
        .into_layer(HttpServer::auto(Executor::graceful(shutdown.guard())).service(http_svc));

    let tcp_service = optional_dns_overwrite_layer_used_for_e2e_only.into_layer(SniRouter::new(
        SniRouterService {
            https_svc,
            exec: Executor::graceful(shutdown.guard()),
        },
    ));

    shutdown.spawn_task(tcp_listener.serve(tcp_service));

    let duration = shutdown
        .shutdown_with_limit(Duration::from_secs(8))
        .await
        .context("graceful shutdown")?;

    tracing::info!("gracefully shutdown complete, duration: {duration:?}");
    Ok(())
}

const DOMAIN_EXAMPLE: Domain = Domain::example();
const DOMAIN_RAMAPROXY_ORG: Domain = Domain::from_static("ramaproxy.org");

#[derive(Debug, Clone)]
struct IngressSNI(Domain);

#[derive(Debug, Clone)]
struct SniRouterService<T> {
    https_svc: T,
    exec: Executor,
}

impl<T, S> Service<SniRequest<S>> for SniRouterService<T>
where
    S: Stream + Unpin + ExtensionsMut,
    T: Service<SniPeekStream<S>, Output = (), Error: Into<BoxError>>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        SniRequest { sni, mut stream }: SniRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        let Some(sni) = sni else {
            // NOTE: in production systems you may want
            // to handle traffic which has no SNI differently,
            // as it may not even be HTTPS traffic, but here to keep the example
            // simple we choose to assume it is https anyway and forward it
            // already to the https service.
            return self
                .https_svc
                .serve(stream)
                .await
                .context("MITM proxy https data for stream without SNI");
        };

        // NOTE: a production SNI proxy most likely uses
        // a more optimized routing approach, which on top of that
        // is probably dynamic in nature so you can update it on the fly,
        // for this example we just keep it simple with 2 hardcoded domains.
        if sni == DOMAIN_EXAMPLE || DOMAIN_RAMAPROXY_ORG.is_parent_of(&sni) {
            stream.extensions_mut().insert(IngressSNI(sni.clone()));
            self.https_svc
                .serve(stream)
                .await
                .context("MITM proxy https data")
                .context_field("sni", sni)?;
        } else {
            // preserve traffic as is, no MITM even
            Forwarder::new(
                self.exec.clone(),
                HostWithPort {
                    host: sni.clone().into(),
                    port: Protocol::HTTPS_DEFAULT_PORT,
                },
            )
            .serve(stream)
            .await
            .context("forward data")
            .context_field("sni", sni)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct HttpsMITMService<C> {
    https_client: C,
}

// NOTE: checkout examples such as `http_mitm_proxy_boring`
// if you want to get an idea on how you might also supporting protocols
// that are bootstrapped starting from HTTP, such as websockets (WS(S)).

impl<C> Service<Request> for HttpsMITMService<C>
where
    C: Service<Request, Output = Response, Error = BoxError>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request) -> Result<Self::Output, Self::Error> {
        let Some(domain) = req
            .extensions()
            .get::<IngressSNI>()
            .map(|sni| sni.0.clone())
            .or_else(|| {
                RequestContext::try_from(&req)
                    .inspect_err(|err| {
                        tracing::error!("failed to fetch request context for http req: {err}");
                    })
                    .ok()
                    .and_then(|ctx| ctx.authority.host.into_domain())
            })
        else {
            // In a production proxy you might go a bit more advanced here,
            // with more granular control on what exactly you wish to do with this unknown traffic...
            //
            // In fact... why is this going through your proxy at all,
            // as you might want your network interface to only receive
            // traffic to be proxied... if possible of course
            return self
                .https_client
                .serve(req)
                .await
                .context("forward HTTPS request for which no SNI or host was found");
        };

        if domain == DOMAIN_EXAMPLE {
            tracing::debug!("hijack example.com traffic...");
            return Ok(RAMA_EXAMPLE_PAYLOAD.into_response());
        }

        if DOMAIN_RAMAPROXY_ORG.is_parent_of(&domain) {
            const PROXY_HEADER: HeaderValue = HeaderValue::from_static("rama-sni-proxy-example");

            tracing::info!("modify ramaproxy.org req/resp headers");
            req.headers_mut().insert("x-proxy-via", PROXY_HEADER);
            let mut resp = self
                .https_client
                .serve(req)
                .await
                .context("forward HTTPS request for ramaproxy.org domain")
                .context_field("domain", domain)?;
            resp.headers_mut().insert("x-proxy-via", PROXY_HEADER);
            return Ok(resp);
        }

        tracing::info!("serve unknwon https traffic for domain: {domain}");
        self.https_client
            .serve(req)
            .await
            .context("forward HTTPS request for domain")
            .context_field("domain", domain)
    }
}

const RAMA_EXAMPLE_PAYLOAD: &str = r##"<!doctype html>
<title>Rama Example</title>
<style>
body{margin:0;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;}
main{text-align:center;max-width:300px;padding:1rem;}
</style>
<main>
<h1>Example Domain</h1>
<p>Served by the Rama SNI TLS proxy Example.</p>
</main>
"##;
