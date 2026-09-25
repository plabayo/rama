//! RFC 7838 §§2, 3 and 5: redirects change the logical origin, whereas
//! alternative services change only the endpoint used to reach that origin.

use super::{
    Observation, Reply, Server, TEST_TIMEOUT, client_with_http3_cache_and_timeout,
    close_client_endpoint, complete, credentials,
};
use rama::{
    Layer as _,
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, StatusCode, Version,
        conn::{HttpServiceSelection, SelectedHttpService},
        header,
        layer::{alt_svc::AltSvcCache, follow_redirect::FollowRedirectLayer},
    },
    layer::MapInputLayer,
    net::address::HostWithPort,
};
use std::sync::{Arc, atomic::Ordering};
use tokio::time::timeout;

const AUTHORIZATION: &str = "Bearer origin-a-token";
const COOKIE: &str = "session=origin-a-session";

fn location(server: &Server) -> String {
    format!("https://localhost:{}/resource", server.address.port())
}

fn request(server: &Server) -> Request {
    Request::get(location(server))
        .header(header::AUTHORIZATION, AUTHORIZATION)
        .header(header::COOKIE, COOKIE)
        .body(Body::empty())
        .unwrap()
}

fn redirect(location: &str) -> Reply {
    let mut reply = Reply {
        status: StatusCode::FOUND,
        ..Reply::default()
    };
    reply
        .headers
        .insert(header::LOCATION, location.parse().unwrap());
    reply
}

fn assert_destination(
    observed: &Observation,
    origin: &Server,
    alternative: Option<&Server>,
    carries_credentials: bool,
) {
    assert_eq!(
        observed.authority,
        format!("localhost:{}", origin.address.port())
    );
    assert_eq!(observed.sni.as_deref(), Some("localhost"));
    assert_eq!(
        observed.alt_used,
        alternative.map(|server| server.address.to_string())
    );
    assert_eq!(observed.version, alternative.unwrap_or(origin).version);
    for (name, value) in [
        (header::AUTHORIZATION, AUTHORIZATION),
        (header::COOKIE, COOKIE),
    ] {
        assert_eq!(
            observed.headers.get(name).map(|value| value.as_bytes()),
            carries_credentials.then_some(value.as_bytes()),
        );
    }
}

#[tokio::test]
async fn redirects_reselect_alternatives_and_scope_credentials_to_each_origin() {
    let (auth, tls) = credentials();
    let origin_a = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative_a = Server::start(auth.clone(), Version::HTTP_3).await;
    let origin_b = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative_b = Server::start(auth, Version::HTTP_3).await;
    let cache = AltSvcCache::default();
    let (client, endpoint) =
        client_with_http3_cache_and_timeout(tls, cache.clone(), Some(TEST_TIMEOUT)).await;
    let client = FollowRedirectLayer::new().layer(
        MapInputLayer::new(|request: Request| {
            // Redirect hops re-enter selection. A prior hop's winning selection
            // belongs to that dispatch, not to the reusable redirect template.
            assert!(!request.extensions().contains::<HttpServiceSelection>());
            assert!(!request.extensions().contains::<SelectedHttpService>());
            request
        })
        .layer(Arc::new(client)),
    );

    // Learn A while following its cross-origin redirect, then independently
    // learn B. The first B request must use B's origin and carry no A credentials.
    let mut first_reply = redirect(&location(&origin_b));
    first_reply.headers.insert(
        header::ALT_SVC,
        format!("h3=\"{}\"", alternative_a.address).parse().unwrap(),
    );
    origin_a.reply(first_reply);
    origin_b.reply(Reply::advertise(&format!(
        "h3=\"{}\"",
        alternative_b.address
    )));
    assert_eq!(
        timeout(TEST_TIMEOUT, complete(&client, request(&origin_a)))
            .await
            .unwrap(),
        (StatusCode::OK, Version::HTTP_2),
    );
    assert_eq!(origin_a.request_count(), 1);
    assert_eq!(origin_b.request_count(), 1);
    assert_eq!(alternative_a.request_count(), 0);
    assert_eq!(alternative_b.request_count(), 0);
    assert_destination(&origin_a.observations.lock()[0], &origin_a, None, true);
    assert_destination(&origin_b.observations.lock()[0], &origin_b, None, false);
    for (origin, alternative) in [(&origin_a, &alternative_a), (&origin_b, &alternative_b)] {
        let candidates = cache.lookup(&origin.origin()).unwrap();
        assert_eq!(candidates.origin(), &origin.origin());
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates.get(0).unwrap().target,
            HostWithPort::from(alternative.address)
        );
    }

    // The next chain uses both cached H3 services. A's relative redirect retains
    // its logical origin and credentials; its cross-origin redirect must then
    // choose B's own service and remove those credentials.
    alternative_a.reply(redirect("/same-origin"));
    alternative_a.reply(redirect(&location(&origin_b)));
    assert_eq!(
        timeout(TEST_TIMEOUT, complete(&client, request(&origin_a)))
            .await
            .unwrap(),
        (StatusCode::OK, Version::HTTP_3),
    );
    assert_eq!(origin_a.request_count(), 1);
    assert_eq!(origin_b.request_count(), 1);
    assert_eq!(alternative_a.request_count(), 2);
    assert_eq!(alternative_b.request_count(), 1);
    for observed in alternative_a.observations.lock().iter() {
        assert_destination(observed, &origin_a, Some(&alternative_a), true);
    }
    assert_destination(
        &alternative_b.observations.lock()[0],
        &origin_b,
        Some(&alternative_b),
        false,
    );
    assert_eq!(alternative_a.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(alternative_b.accepted.load(Ordering::SeqCst), 1);

    drop(client);
    close_client_endpoint(endpoint).await;
    origin_a.close().await;
    alternative_a.close().await;
    origin_b.close().await;
    alternative_b.close().await;
}
