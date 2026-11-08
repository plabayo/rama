use std::{sync::Arc, time::Duration};

use super::utils;

use rama::{
    Layer,
    extensions::ExtensionsRef,
    graceful::WeakScope,
    http::{
        BodyExtractExt, HeaderName, Request, fingerprint::Ja4H, header::USER_AGENT,
        server::HttpServer, service::web::response::Json,
    },
    net::{address::ProxyAddress, client::ProxyRoute},
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        fingerprint::Ja4,
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
    ua::profile::{
        analysis::fingerprint::RecordedFingerprintCache, selection::database::UserAgentDatabase,
    },
};

use serde_json::{Value, json};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_mitm_proxy_emulate() {
    utils::init_tracing();

    // The origin checks what it observed against the profile recorded for the
    // User-Agent it received, as the echo service does.
    let database = Arc::new(UserAgentDatabase::try_embedded().expect("embedded profiles"));
    let recorded = Arc::new(RecordedFingerprintCache::new(&database));
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self-signed")
        .with_alpn_http_auto();
    let origin = TlsAcceptorLayer::new(tls)
        .with_store_client_hello(true)
        .into_layer(HttpServer::auto(WeakScope::detached()).service(service_fn(
            move |req: Request| {
                let (database, recorded) = (database.clone(), recorded.clone());
                async move {
                    let user_agent = req
                        .headers()
                        .get(USER_AGENT)
                        .and_then(|value| value.to_str().ok())
                        .map(ToOwned::to_owned);
                    let profile = user_agent
                        .as_deref()
                        .and_then(|ua| recorded.get(&database, ua));
                    let ja4 = Ja4::compute(req.extensions()).ok();
                    let ja4h = Ja4H::compute(&req).ok();
                    let header_names: Vec<_> =
                        req.headers().keys().map(HeaderName::as_str).collect();
                    let profile_ja4: Option<Vec<_>> = profile.map(|profile| {
                        profile
                            .tls
                            .iter()
                            .filter_map(|tls| tls.ja4.as_ref().map(ToString::to_string))
                            .collect()
                    });
                    let profile_ja4h: Option<Vec<_>> = profile
                        .map(|profile| profile.http.iter().map(ToString::to_string).collect());
                    let ja4_matches = profile.zip(ja4.as_ref()).is_some_and(|(profile, ja4)| {
                        profile.tls.iter().any(|tls| tls.ja4.as_ref() == Some(ja4))
                    });
                    let ja4h_matches = profile
                        .zip(ja4h.as_ref())
                        .is_some_and(|(profile, ja4h)| profile.matching_http(ja4h).is_some());
                    Ok(Json(json!({
                        "header_names": header_names,
                        "user_agent": user_agent,
                        "ja4": ja4.as_ref().map(ToString::to_string),
                        "ja4h": ja4h.as_ref().map(ToString::to_string),
                        "profile_ja4": profile_ja4,
                        "profile_ja4h": profile_ja4h,
                        "ja4_matches_profile": ja4_matches,
                        "ja4h_matches_profile": ja4h_matches,
                    })))
                }
            },
        )));
    tokio::spawn(async {
        TcpListener::bind_address("127.0.0.1:13048", WeakScope::detached())
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: emulation origin: {e}"))
            .serve(origin)
            .await;
    });

    let mut runner =
        utils::ExampleRunner::interactive(utils::example!("http_mitm_proxy_emulate_boring"));
    // Loading the embedded profile database is CPU-heavy in unoptimized CI builds.
    runner
        .wait_for_tcp_within(([127, 0, 0, 1], 12066), Duration::from_mins(1))
        .await;

    let observe = async |username: &str| -> Value {
        let proxy =
            ProxyAddress::try_from(format!("http://{username}:secret@127.0.0.1:12066")).unwrap();
        // A hostname keeps SNI in the ClientHello, as the profiles were captured.
        let response = runner
            .get("https://localhost:13048/")
            .header(USER_AGENT, "rama-example-test")
            .extension(ProxyRoute::Proxy(proxy))
            .send()
            .await
            .unwrap();
        let selected = response
            .headers()
            .get("x-emulated-user-agent")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
            .expect("the proxy reports the profile it selected");
        let observed = response.try_into_json::<Value>().await.unwrap();
        // The origin saw the selected profile, with that profile's TLS and HTTP fingerprints.
        assert_eq!(
            observed["user_agent"].as_str(),
            Some(selected.as_str()),
            "{observed}"
        );
        assert_eq!(observed["ja4_matches_profile"], true, "{observed}");
        assert_eq!(observed["ja4h_matches_profile"], true, "{observed}");
        observed
    };

    let firefox = observe("john-ua_firefox").await;
    let chrome = observe("john-ua_chrome-ua_macos").await;
    observe("john").await;

    let user_agent = |observed: &Value| observed["user_agent"].as_str().unwrap().to_owned();
    assert!(user_agent(&firefox).contains("Firefox/"), "{firefox}");
    let chrome_agent = user_agent(&chrome);
    assert!(
        chrome_agent.contains("Chrome/") && chrome_agent.contains("Macintosh"),
        "{chrome}"
    );
}
