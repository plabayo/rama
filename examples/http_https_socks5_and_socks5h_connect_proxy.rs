//! An example to showcase how one can build a proxy that is both a HTTP, HTTPS, SOCKS5 and SOCKS5H Proxy in one.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_https_socks5_and_socks5h_connect_proxy --features=dns,socks5,http-full,boring
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62029`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62029 --proxy-user 'tom:clancy' http://api64.ipify.org/
//! curl -v -x http://127.0.0.1:62029 --proxy-user 'tom:clancy' https://api64.ipify.org/
//! curl --proxy-insecure -v -x https://127.0.0.1:62029 --proxy-user 'tom:clancy' http://api64.ipify.org/
//! curl --proxy-insecure -v -x https://127.0.0.1:62029 --proxy-user 'tom:clancy' https://api64.ipify.org/
//! curl -v -x socks5://127.0.0.1:62029 --proxy-user 'john:secret' http://api64.ipify.org/
//! curl -v -x socks5h://127.0.0.1:62029 --proxy-user 'john:secret' https://api64.ipify.org/
//! curl -v -x socks5://127.0.0.1:62029 --proxy-user 'john:secret' http://api64.ipify.org/
//! curl -v -x socks5h://127.0.0.1:62029 --proxy-user 'john:secret' https://api64.ipify.org/
//! ```
//!
//! You should see in all the above examples the responses from the server.

use rama::{
    Layer, Service,
    extensions::{ExtensionsMut, ExtensionsRef, InputExtensions},
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{
        http::RequestContext,
        proxy::ProxyTarget,
        stream::ClientSocketInfo,
        tls::{
            SecureTransport,
            server::{SelfSignedData, TlsPeekRouter},
        },
        user::credentials::basic,
    },
    proxy::socks5::{Socks5Acceptor, server::Socks5PeekRouter},
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

#[cfg(feature = "boring")]
use rama::{
    net::tls::{
        ApplicationProtocol,
        server::{ServerAuth, ServerConfig},
    },
    tls::boring::server::TlsAcceptorService,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer};

use std::{convert::Infallible, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    #[cfg(feature = "boring")]
    let tls_service_data = {
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                organisation_name: Some("Example Server Acceptor".to_owned()),
                ..Default::default()
            }))
        };
        tls_server_config
            .try_into()
            .expect("create tls server config")
    };

    #[cfg(all(feature = "rustls", not(feature = "boring")))]
    let tls_service_data = {
        TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self signed acceptor data")
        .with_alpn_protocols_http_auto()
        .with_env_key_logger()
        .expect("with env key logger")
        .build()
    };

    let exec = Executor::graceful(graceful.guard());

    let tcp_service = TcpListener::bind("127.0.0.1:62029", exec.clone())
        .await
        .expect("bind http+https+socks5+socks5h proxy to 127.0.0.1:62029");

    let socks5_acceptor =
        Socks5Acceptor::default().with_authorizer(basic!("john", "secret").into_authorizer());

    let http_service = HttpServer::auto(exec.clone()).service(
        (
            TraceLayer::new_for_http(),
            ConsumeErrLayer::default(),
            ProxyAuthLayer::new(basic!("tom", "clancy")),
            UpgradeLayer::new(
                exec.clone(),
                MethodMatcher::CONNECT,
                service_fn(http_connect_accept),
                ConsumeErrLayer::default().into_layer(Forwarder::ctx(exec)),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
            RemoveRequestHeaderLayer::hop_by_hop(),
        )
            .into_layer(service_fn(http_plain_proxy)),
    );

    let tls_acceptor = TlsAcceptorService::new(tls_service_data, http_service.clone(), true);
    let auto_tls_acceptor = TlsPeekRouter::new(tls_acceptor).with_fallback(http_service);

    let auto_socks5_acceptor =
        Socks5PeekRouter::new(socks5_acceptor).with_fallback(auto_tls_acceptor);

    graceful.spawn_task(tcp_service.serve(auto_socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    tracing::info!(
        "proxy secure transport ingress: {:?}",
        req.extensions().get::<SecureTransport>()
    );

    Ok((StatusCode::OK.into_response(), req))
}

async fn http_plain_proxy(req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
    match client.serve(req).await {
        Ok(resp) => {
            if let Some(client_socket_info) = resp
                .extensions()
                .get()
                .and_then(|InputExtensions(ext)| ext.get::<ClientSocketInfo>())
            {
                tracing::info!(
                    http.response.status_code = %resp.status(),
                    network.local.port = client_socket_info.local_addr().map(|addr| addr.port.to_string()).unwrap_or_default(),
                    network.local.address = client_socket_info.local_addr().map(|addr| addr.ip_addr.to_string()).unwrap_or_default(),
                    network.peer.port = %client_socket_info.peer_addr().port,
                    network.peer.address = %client_socket_info.peer_addr().ip_addr,
                    "http plain text proxy received response",
                )
            } else {
                tracing::info!(
                    http.response.status_code = %resp.status(),
                    "http plain text proxy received response, IP info unknown",
                )
            };
            Ok(resp)
        }
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
