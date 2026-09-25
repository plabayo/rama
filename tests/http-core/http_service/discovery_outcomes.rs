//! Multi-request discovery contracts through the complete client stack.

use super::{
    Reply, Server, TEST_TIMEOUT, client, client_with_http3_cache, close_client_endpoint, complete,
    credentials, seed,
};
use parking_lot::Mutex;
use rama::{
    Layer, Service,
    bytes::Bytes,
    dns::client::{DnsConnector, resolver::DnsAddresssResolverOverwrite},
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    futures::{StreamExt as _, stream},
    graceful::Shutdown,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
        header,
        layer::{
            alt_svc::AltSvcCache,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        proto::h2::frame::{AltSvc as AltSvcFrame, StreamId},
        server::HttpServer,
    },
    layer::MapInputLayer,
    net::{
        address::{ProxyAddress, SocketAddress},
        client::{ProxyRoute, ProxyRoutes},
        proxy::IoForwardService,
        tls::ApplicationProtocol,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
};
use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    task::{JoinHandle, spawn},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

fn failing_body() -> Body {
    let data =
        stream::once(async { Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"partial"))) });
    let failure = stream::once(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Err::<Frame<Bytes>, _>(BoxError::from_static_str("server response interrupted"))
    });
    Body::from_frame_stream(data.chain(failure))
}

async fn connect_proxy() -> (
    SocketAddr,
    Arc<Mutex<Vec<String>>>,
    Shutdown,
    CancellationToken,
    JoinHandle<()>,
) {
    let cancel = CancellationToken::new();
    let shutdown = Shutdown::new(cancel.clone().cancelled_owned());
    let executor = Executor::graceful(shutdown.guard());
    let listener = TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone())
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let connect = EagerHttpProxyConnector::new(
        DnsConnector::new(TcpConnector::new()),
        IoForwardService::new(executor.clone()),
    );
    let service = (
        MapInputLayer::new({
            let targets = targets.clone();
            move |request: Request| {
                assert_eq!(request.method(), Method::CONNECT);
                targets.lock().push(request.uri().to_string());
                request
            }
        }),
        UpgradeLayer::new(executor.clone(), MethodMatcher::CONNECT, connect),
    )
        .into_layer(service_fn(async |_request: Request| {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty())
                    .unwrap(),
            )
        }));
    let task = spawn(listener.serve(HttpServer::auto(executor).service(service)));
    (address, targets, shutdown, cancel, task)
}

#[tokio::test]
async fn proxied_response_failure_suppresses_alternative_for_route_plan() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let (proxy_address, _targets, shutdown, cancel, task) = connect_proxy().await;
    let proxy = ProxyRoute::from(
        format!("http://{proxy_address}")
            .parse::<ProxyAddress>()
            .unwrap(),
    );
    let mut failures = Vec::new();
    for plan in [
        vec![proxy.clone()],
        vec![proxy.clone(), ProxyRoute::Direct],
        vec![proxy.clone(), proxy.clone()],
    ] {
        let cache = AltSvcCache::new(64, Duration::from_hours(1), Duration::from_secs(60));
        seed(
            &cache,
            &origin.origin(),
            &format!("h2=\"{}\"; ma=3600", alternative.address),
        );
        let client = client(tls.clone(), cache.clone());
        let alt_before = alternative.request_count();
        let origin_before = origin.request_count();
        for _ in 0..3 {
            alternative.reply(Reply {
                body: Some(failing_body()),
                ..Reply::default()
            });
        }
        let mut alt_dispatches = Vec::new();
        for _ in 0..3 {
            let request = origin.request();
            request.extensions().insert(ProxyRoutes::new(plan.clone()));
            let response = timeout(TEST_TIMEOUT, client.serve(request))
                .await
                .unwrap()
                .unwrap();
            let body = timeout(TEST_TIMEOUT, response.into_body().collect())
                .await
                .unwrap();
            alt_dispatches.push(body.is_err());
        }
        let alt = alternative.request_count() - alt_before;
        assert_eq!(alt_dispatches, [true, false, false]);
        assert_eq!(origin.request_count() - origin_before, 2);
        failures.push((plan.len(), alt));
        // Drain unused failing replies so later plans start clean.
        alternative.replies.lock().clear();
        drop(client);
    }

    for (len, alt) in &failures {
        assert_eq!(
            *alt, 1,
            "plan with {len} routes kept dispatching to the failing alternative: {failures:?}"
        );
    }
    cancel.cancel();
    shutdown.shutdown_with_limit(TEST_TIMEOUT).await.unwrap();
    task.await.unwrap();
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn readvertised_misdirecting_alternative_is_not_reselected() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let advertisement = format!("h2=\"{}\"; ma=3600", alternative.address);
    let cache = AltSvcCache::default();
    seed(&cache, &origin.origin(), &advertisement);
    let client = client(tls, cache.clone());
    for _ in 0..8 {
        origin.reply(Reply::advertise(&advertisement));
        alternative.reply(Reply {
            status: StatusCode::MISDIRECTED_REQUEST,
            ..Reply::default()
        });
    }
    let mut statuses = Vec::new();
    for _ in 0..8 {
        let response = timeout(TEST_TIMEOUT, client.serve(origin.request()))
            .await
            .unwrap()
            .unwrap();
        statuses.push(response.status().as_u16());
        _ = response.into_body().collect().await;
    }
    let misdirected = statuses.iter().filter(|status| **status == 421).count();

    assert_eq!(
        misdirected, 1,
        "misdirecting alternative re-selected: {statuses:?}"
    );
    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn request_dns_override_does_not_poison_shared_alt_backoff() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    // A non-localhost name, so resolution goes through the request's resolver.
    seed(
        &cache,
        &origin.origin(),
        &format!("h2=\"alt.audit.example:{}\"", alternative.address.port()),
    );
    let client = client(tls, cache.clone());
    let with_override = |ip: Ipv4Addr| {
        let request = origin.request();
        request
            .extensions()
            .insert(DnsAddresssResolverOverwrite::new(ip));
        request
    };
    // TEST-NET-1 is unroutable: only this request's resolution cannot connect.
    let restricted = timeout(
        Duration::from_secs(2),
        client.serve(with_override(Ipv4Addr::new(192, 0, 2, 1))),
    )
    .await;
    let snapshot = cache.lookup_fresh(&origin.origin()).unwrap();
    let usable = cache.is_usable(&snapshot, 0);

    drop(restricted);
    assert!(
        usable,
        "one request's DNS override suppressed the shared alternative"
    );
    // Control: a working per-request resolution reaches the alternative.
    assert_eq!(
        complete(&client, with_override(Ipv4Addr::LOCALHOST))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        alternative.request_count(),
        1,
        "healthy request did not use the alternative"
    );

    drop(client);
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn https_upgrade_preserves_version_with_h2_and_h3_advertisements() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_11).await;
    let h2 = Server::start(auth.clone(), Version::HTTP_2).await;
    let quic = Server::start(auth, Version::HTTP_3).await;
    let mut outcomes = Vec::new();
    for alternative in [
        None,
        Some((&h2, ApplicationProtocol::HTTP_2)),
        Some((&quic, ApplicationProtocol::HTTP_3)),
    ] {
        let cache = AltSvcCache::default();
        if let Some((server, protocol)) = &alternative {
            seed(
                &cache,
                &origin.origin(),
                &format!("{protocol}=\"{}\"", server.address),
            );
        }
        let (client, endpoint) = client_with_http3_cache(tls.clone(), cache).await;
        let request = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri(format!(
                "https://localhost:{}/socket",
                origin.address.port()
            ))
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        let result = timeout(TEST_TIMEOUT, client.serve(request)).await.unwrap();
        outcomes.push((alternative.map(|(_, protocol)| protocol), result.is_ok()));
        drop(result);
        drop(client);
        close_client_endpoint(endpoint).await;
    }

    assert!(
        outcomes.iter().all(|(_, ok)| *ok),
        "cached h3 alternative broke an https upgrade: {outcomes:?}"
    );
    assert_eq!(h2.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(quic.accepted.load(Ordering::SeqCst), 0);
    origin.close().await;
    h2.close().await;
    quic.close().await;
}

#[tokio::test]
async fn request_dns_policy_does_not_learn_shared_origin_advertisements() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth, Version::HTTP_2).await;
    let cache = AltSvcCache::default();
    let client = client(tls, cache.clone());
    let mut reply = Reply::advertise("h3=\":8443\"");
    reply.alt_svc_frame = Some(
        AltSvcFrame::new(
            StreamId::zero(),
            Bytes::from(format!("https://localhost:{}", origin.address.port())),
            Bytes::from_static(b"h3=\":9443\""),
        )
        .unwrap(),
    );
    origin.reply(reply);
    let request = origin.request();
    request
        .extensions()
        .insert(DnsAddresssResolverOverwrite::new(Ipv4Addr::LOCALHOST));
    assert_eq!(complete(&client, request).await.0, StatusCode::OK);
    assert!(cache.lookup(&origin.origin()).is_none());
    // A later exchange also lets the connection driver consume the preceding
    // connection-level frame. The original request-only policy remains scoped.
    origin.reply(Reply::advertise("h3=\":10443\""));
    assert_eq!(complete(&client, origin.request()).await.0, StatusCode::OK);
    assert!(cache.lookup(&origin.origin()).is_none());
    assert_eq!(origin.accepted.load(Ordering::SeqCst), 1);
    drop(client);
    origin.close().await;
}
