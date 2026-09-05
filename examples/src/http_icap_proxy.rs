//! Complete HTTP(S) MITM proxy with ICAP response adaptation.
//!
//! By default this process serves both:
//!
//! - an HTTP proxy on `127.0.0.1:62061`;
//! - an ICAP server on `127.0.0.1:62062`.
//!
//! The embedded ICAP service only adapts responses for `example.com`. It
//! adds an `x-rama-icap: adapted` response header while leaving the
//! streaming response body untouched. Other origins receive an ICAP 204.
//! The proxy discovers and caches the selected service's OPTIONS policy.
//!
//! # Run with the embedded ICAP server
//!
//! ```sh
//! cargo run -p rama-examples --bin http_icap_proxy \
//!   --features=http-full,icap,boring
//! curl -v -x http://127.0.0.1:62061 http://example.com/
//! curl -k -v -x http://127.0.0.1:62061 https://example.com/
//! curl -v -x http://127.0.0.1:62061 http://example.net/
//! ```
//!
//! # Run against an external ICAP server
//!
//! Pass one ICAP service URI to skip the embedded server:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_icap_proxy \
//!   --features=http-full,icap,boring -- \
//!   icap://127.0.0.1:1344/echo
//! ```
//!
//! Use an `icaps://` service URI for direct TLS. The external service must
//! support RESPMOD. This makes it easy to replace the embedded Rama
//! implementation with c-icap or another implementation.
//!
//! # Service flow
//!
//! [`HttpServer`] accepts both non-CONNECT forward-proxy requests and CONNECT
//! tunnels. Every HTTP/1.1 non-CONNECT proxy request carries its destination
//! as an absolute-form request-target. The client-to-proxy connection is not
//! bound to that destination, so persistent requests may name different
//! origins. [`EasyHttpWebClient`] derives the origin from each request and
//! acquires a matching upstream connection.
//!
//! CONNECT instead binds a tunnel to one endpoint: the whole connection in
//! HTTP/1.1, or one stream in HTTP/2. Rama's eager connector establishes that
//! endpoint before returning success and preserves its socket through
//! TLS/HTTP peek and [`HttpMitmRelay`]. The relay sends intercepted HTTP over
//! the client built on that socket; it does not connect again per request.
//!
//! The same [`AdaptationLayer`] wraps both branches. For ordinary HTTP it
//! wraps the web client. For intercepted CONNECT traffic it is middleware
//! around the relay's already-established HTTP client. Once the origin
//! responds, the layer discovers the ICAP policy through OPTIONS and sends
//! the response through RESPMOD. Opaque non-HTTP tunnel data is relayed
//! without ICAP adaptation.
//!
//! This example deliberately configures only a response service. Adding a
//! request service to the same layer would also run REQMOD before the origin
//! request is sent.
//!
//! The generated development CA is intentionally ephemeral. A production
//! proxy must use a persistent CA trusted by its clients and an explicit
//! interception policy.

#![expect(
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{sync::Arc, time::Duration};

use clap::Parser;
use rama::{
    Layer as _,
    error::{BoxError, ErrorContext as _},
    http::{
        HeaderValue,
        client::EasyHttpWebClient,
        layer::{
            error_handling::ErrorHandlerLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
    },
    icap::{
        client::{
            Client as IcapClient,
            options::{OptionsCacheLayer, OptionsService},
        },
        http::{
            HttpService, IncomingRequest,
            layer::{AdaptationLayer, ServiceEndpoint},
        },
        io::ConnectionOptions,
        proto::{Method, MethodKind, Preview, ServiceTag},
        server::{OptionsResponse, OutgoingResponse, Server as IcapServer},
    },
    layer::{ArcLayer, ConsumeErrLayer, MapOutputLayer},
    net::{
        AuthorityInputExt as _, address::Host, http::server::HttpPeekRouter,
        proxy::IoForwardService,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        boring::{client::TlsConnector, proxy::TlsMitmRelay},
        server::{CertificateSubject, PeekTlsClientHelloService, SelfSignedCaConfig},
    },
};

const PROXY_ADDRESS: &str = "127.0.0.1:62061";
const ICAP_ADDRESS: &str = "127.0.0.1:62062";
const DEFAULT_ICAP_URI: &str = "icap://127.0.0.1:62062/adapt";
const TARGET_HOST: &str = "example.com";
const SERVICE_TAG: ServiceTag = ServiceTag::from_static("rama-icap-example");

#[derive(Debug, Parser)]
#[command(about = "Run an HTTP proxy through a selective ICAP service")]
struct Args {
    /// External RESPMOD service URI; omit to run the embedded Rama service.
    icap_uri: Option<String>,

    /// HTTP host adapted by the embedded ICAP service.
    #[arg(long, default_value = TARGET_HOST)]
    target_host: String,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let Args {
        icap_uri,
        target_host,
    } = Args::parse();
    let embedded = icap_uri.is_none();
    let icap_uri = icap_uri.unwrap_or_else(|| DEFAULT_ICAP_URI.to_owned());
    let target_host = Arc::new(target_host.parse::<Host>()?);

    let graceful = rama::graceful::Shutdown::default();
    let executor = Executor::graceful(graceful.guard());

    if embedded {
        let listener = TcpListener::bind_address(ICAP_ADDRESS, executor.clone()).await?;
        let service_target = Arc::clone(&target_host);
        let service = HttpService::new(service_fn(move |request| {
            adapt_response(request, Arc::clone(&service_target))
        }));
        let server = IcapServer::new(service, SERVICE_TAG)?;
        graceful.spawn_task(listener.serve(server));
    }

    let connector = TlsConnector::auto(rama::dns::client::DnsConnector::new(
        rama::tcp::client::service::TcpConnector::new(),
    ));
    let icap_client = Arc::new(
        IcapClient::new(connector.clone()).with_options(icap_connection_options(embedded)),
    );
    let options = OptionsCacheLayer::new().layer(OptionsService::new(icap_client.clone()));
    let endpoint = ServiceEndpoint::new(icap_uri)?
        .with_preview(Preview::new(1024))
        .with_allow_204(true)
        .with_allow_206(true);
    let adaptation = AdaptationLayer::new(icap_client)
        .with_options_cache(options)
        .with_response_service(endpoint.clone());

    // A non-CONNECT request selects its origin per request. The web client
    // derives that origin and acquires a matching upstream connection.
    let direct = (
        ErrorHandlerLayer::new(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        adaptation.clone(),
        RemoveResponseHeaderLayer::hop_by_hop(),
    )
        .into_layer(
            EasyHttpWebClient::default_with_executor(executor.clone())
                .with_isolate_forward_proxy_auth_error(true),
        );

    // CONNECT already owns its egress socket. Peek/Relay preserves that
    // socket while applying the same ICAP layer to intercepted HTTP.
    let http_relay = HttpMitmRelay::new(executor.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        adaptation,
        ArcLayer::new(),
    ));
    let maybe_http = HttpPeekRouter::new(http_relay)
        .with_known_non_http_protocol_methods()
        .with_fallback(
            MapOutputLayer::new(drop).into_layer(IoForwardService::new(executor.clone())),
        );
    let tls_relay = TlsMitmRelay::try_new_with_cached_self_signed_issuer(&SelfSignedCaConfig {
        subject: CertificateSubject {
            organisation_name: Some("Rama ICAP Proxy Example".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    })?;
    let tunnel = PeekTlsClientHelloService::new(tls_relay.into_layer(maybe_http.clone()))
        .with_fallback(maybe_http);
    let tunnel = Arc::new(ConsumeErrLayer::trace_as_debug().into_layer(tunnel));
    let connect = EagerHttpProxyConnector::new(connector, tunnel);
    let proxy = (
        ConsumeErrLayer::default(),
        UpgradeLayer::new(executor.clone(), MethodMatcher::CONNECT, connect),
    )
        .into_layer(direct);
    let listener = TcpListener::bind_address(PROXY_ADDRESS, executor.clone()).await?;
    let server = HttpServer::auto(executor).service(proxy);
    graceful.spawn_task(listener.serve(server));

    println!("HTTP proxy listening on http://{PROXY_ADDRESS}");
    if embedded {
        println!("embedded ICAP service listening at {DEFAULT_ICAP_URI}");
        println!("only responses for {target_host} are adapted");
    } else {
        println!("using external ICAP service: {endpoint:?}");
    }
    println!("try: curl -v -x http://{PROXY_ADDRESS} http://{TARGET_HOST}/");

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;
    Ok(())
}

fn icap_connection_options(embedded: bool) -> ConnectionOptions {
    if embedded {
        ConnectionOptions::strict()
    } else {
        ConnectionOptions::new()
    }
}

async fn adapt_response(
    mut request: IncomingRequest,
    target_host: Arc<Host>,
) -> Result<OutgoingResponse, BoxError> {
    let options = OptionsResponse::new(SERVICE_TAG, &[Method::Respmod])
        .with_service("Rama selective response adapter")
        .with_preview(Preview::new(1024))
        .with_allow_204(true)
        .with_allow_206(true)
        .with_transfer_preview_all(true);
    if let Some(response) = options.build_for(request.icap())? {
        return Ok(response);
    }

    if request.icap().method() != MethodKind::Respmod {
        return Ok(request.respond_method_not_allowed(SERVICE_TAG)?);
    }
    if !targets_host(&request, &target_host) {
        let unchanged = request.try_into_unchanged().map_err(|_request| {
            std::io::Error::other("RESPMOD request cannot be returned unchanged")
        })?;
        return Ok(unchanged.respond(SERVICE_TAG)?);
    }

    request
        .encapsulated_mut()
        .and_then(|encapsulated| encapsulated.response_mut())
        .context("RESPMOD request has no HTTP response")?
        .headers_mut()
        .insert("x-rama-icap", HeaderValue::from_static("adapted"));
    Ok(request.adapt_response_head(SERVICE_TAG).await?)
}

fn targets_host(request: &IncomingRequest, target_host: &Host) -> bool {
    let Some(request) = request
        .encapsulated()
        .and_then(|encapsulated| encapsulated.request())
    else {
        return false;
    };
    request
        .authority()
        .is_some_and(|authority| authority.host == *target_host)
}
