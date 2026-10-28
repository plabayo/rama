//! Receive budgets must survive omitted peer SETTINGS on both relay hops.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use std::{convert::Infallible, sync::Arc, time::Duration};

use rama_core::{
    Service, extensions::ExtensionsRef as _, io::BridgeIo, rt::Executor, service::service_fn,
};
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version,
    conn::{H2ClientContextParams, H2ServerContextParams, H2SettingsLimits, TargetHttpVersion},
    header,
};
use rama_http_backend::{proxy::mitm::HttpMitmRelay, server::HttpServer};
use rama_http_core::{
    client::conn::http2::Builder as ClientBuilder, h2::server::inspect_client_initial_settings,
};
use rama_http_types::proto::h2::frame::{Setting, SettingId, Settings};
use rama_net::test_utils::client::MockSocket;
use rama_utils::octets::{kib, kib_u32, mib_u32};
use tokio::{sync::oneshot, time::timeout};

fn settings(cap: Option<u32>) -> Arc<Settings> {
    Arc::new(
        Settings::from_ordered_entries(
            cap.into_iter()
                .map(|value| Setting {
                    id: SettingId::MaxHeaderListSize,
                    value,
                })
                .collect(),
        )
        .unwrap(),
    )
}

#[derive(Clone, Copy, Debug, Default)]
enum Mode {
    #[default]
    Eager,
    Lazy,
    LateSettings,
}

struct Case {
    mode: Mode,
    limit: u32,
    egress_limit: Option<u32>,
    origin_cap: Option<u32>,
    client_cap: Option<u32>,
    ingress: H2ServerContextParams,
    egress: H2ClientContextParams,
    cookie_fields: usize,
    response_bytes: usize,
}

impl Default for Case {
    fn default() -> Self {
        Self {
            mode: Mode::Eager,
            limit: H2SettingsLimits::default().header_list_size,
            egress_limit: None,
            origin_cap: None,
            client_cap: None,
            ingress: H2ServerContextParams::default(),
            egress: H2ClientContextParams::default(),
            // ~21 KiB, plus 32 bytes per field in H2's decoded-list accounting.
            cookie_fields: 30,
            response_bytes: kib(20),
        }
    }
}

struct Outcome {
    response: Response<rama_http_core::body::Incoming>,
    ingress_cap: Option<u32>,
    egress_cap: Option<u32>,
}

async fn relay_headers(case: Case) -> Outcome {
    timeout(Duration::from_secs(20), async move {
        let (client, ingress) = tokio::io::duplex(kib(64));
        let (egress, origin) = tokio::io::duplex(kib(64));
        let ingress = MockSocket::new(ingress);
        let egress = MockSocket::new(egress);
        let mut limits = H2SettingsLimits::default();
        limits.header_list_size = case.limit;
        if case.limit != H2SettingsLimits::default().header_list_size {
            ingress.extensions().insert(limits);
        }
        limits.header_list_size = case.egress_limit.unwrap_or(case.limit);
        if limits.header_list_size != H2SettingsLimits::default().header_list_size {
            egress.extensions().insert(limits);
        }
        ingress.extensions().insert(case.ingress);
        egress.extensions().insert(case.egress);
        if !matches!(case.mode, Mode::Lazy) {
            // Same selection as a TLS connection that negotiated h2 via ALPN.
            egress
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
        }

        let (egress_settings_tx, egress_settings_rx) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (origin, observed) = inspect_client_initial_settings(MockSocket::new(origin))
                .await
                .unwrap();
            egress_settings_tx
                .send(observed.unwrap().settings.config.max_header_list_size)
                .unwrap();
            if matches!(case.mode, Mode::LateSettings) {
                tokio::time::sleep(Duration::from_secs(6)).await;
            }
            origin.extensions().insert(H2ServerContextParams {
                initial_settings: Some(settings(case.origin_cap)),
                max_header_list_size: Some(mib_u32(1)),
                ..Default::default()
            });
            HttpServer::new_h2(Executor::default())
                .serve(
                    origin,
                    service_fn(move |request: Request| async move {
                        let cookie_bytes: usize = request
                            .headers()
                            .get_all(header::COOKIE)
                            .iter()
                            .map(HeaderValue::len)
                            .sum();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("x-cookie-bytes", cookie_bytes)
                                .header("x-large", "r".repeat(case.response_bytes))
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }),
                )
                .await
        });
        let relay = tokio::spawn(async move {
            HttpMitmRelay::new(Executor::default())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut sender, connection) = ClientBuilder::new(Executor::default())
            .with_initial_settings(settings(case.client_cap))
            .with_max_header_list_size(mib_u32(1))
            .with_observe_peer_settings(true)
            .handshake(MockSocket::new(client))
            .await
            .unwrap();
        let peer = connection.peer_settings_handle();
        let driver = tokio::spawn(connection);
        let ingress_cap = peer
            .await_settings()
            .await
            .unwrap()
            .0
            .config
            .max_header_list_size;

        let mut request = Request::builder()
            .uri("https://origin.example/cookies")
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap();
        for _ in 0..case.cookie_fields {
            request.headers_mut().append(
                header::COOKIE,
                HeaderValue::from_str(&format!("session={}", "c".repeat(700))).unwrap(),
            );
        }
        let response = sender.send_request(request).await.unwrap();
        // A rejected lazy ingress request never opens the egress connection.
        let egress_cap = if matches!(case.mode, Mode::Lazy)
            && response.status() == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        {
            None
        } else {
            egress_settings_rx.await.unwrap()
        };
        driver.abort();
        relay.abort();
        origin_task.abort();
        Outcome {
            response,
            ingress_cap,
            egress_cap,
        }
    })
    .await
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn omitted_header_caps_relay_large_cookies_and_response_headers() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        let result = relay_headers(Case {
            mode,
            ..Default::default()
        })
        .await;
        assert_eq!(result.response.status(), StatusCode::OK, "{mode:?}");
        assert_eq!(result.response.headers()["x-large"].len(), kib(20));
        assert!(
            result.response.headers()["x-cookie-bytes"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > kib(20)
        );
        // Mirroring preserves omissions. Without a mirror, the baseline is advertised.
        assert_eq!(
            result.ingress_cap,
            match mode {
                Mode::Eager => None,
                Mode::Lazy | Mode::LateSettings => Some(kib_u32(256)),
            }
        );
        assert_eq!(
            result.egress_cap,
            match mode {
                Mode::Lazy => Some(kib_u32(256)),
                Mode::Eager | Mode::LateSettings => None,
            }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn omitted_header_caps_enforce_each_hops_configured_budget() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        for limit in [kib_u32(16), kib_u32(32), kib_u32(256)] {
            let accepted = relay_headers(Case {
                mode,
                limit,
                cookie_fields: 1,
                response_bytes: kib(1),
                ..Default::default()
            })
            .await;
            assert_eq!(accepted.response.status(), StatusCode::OK);
            let rejected_request = relay_headers(Case {
                mode,
                limit,
                cookie_fields: limit as usize / 700 + 1,
                response_bytes: 0,
                ..Default::default()
            })
            .await;
            assert_eq!(
                rejected_request.response.status(),
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "{mode:?}, limit {limit}"
            );
            let rejected_response = relay_headers(Case {
                mode,
                limit,
                cookie_fields: 0,
                response_bytes: limit as usize + 1,
                ..Default::default()
            })
            .await;
            assert_eq!(
                rejected_response.response.status(),
                StatusCode::BAD_GATEWAY,
                "{mode:?}, limit {limit}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn omitted_header_caps_use_independent_ingress_and_egress_limits() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        // A small request budget must not constrain a large response.
        let response = relay_headers(Case {
            mode,
            limit: kib_u32(16),
            egress_limit: Some(kib_u32(32)),
            cookie_fields: 1,
            ..Default::default()
        })
        .await;
        assert_eq!(response.response.status(), StatusCode::OK, "{mode:?}");
        assert_eq!(response.response.headers()["x-large"].len(), kib(20));

        // The same budgets must still reject an oversized request.
        let request = relay_headers(Case {
            mode,
            limit: kib_u32(16),
            egress_limit: Some(kib_u32(32)),
            ..Default::default()
        })
        .await;
        assert_eq!(
            request.response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        // Reverse the budgets: large requests pass, but large responses fail.
        for response_bytes in [kib(1), kib(20)] {
            let result = relay_headers(Case {
                mode,
                limit: kib_u32(32),
                egress_limit: Some(kib_u32(16)),
                response_bytes,
                ..Default::default()
            })
            .await;
            assert_eq!(
                result.response.status(),
                if response_bytes == kib(1) {
                    StatusCode::OK
                } else {
                    StatusCode::BAD_GATEWAY
                },
                "{mode:?}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn omitted_header_caps_can_be_expanded_above_the_default() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        let result = relay_headers(Case {
            mode,
            limit: kib_u32(512),
            cookie_fields: 450,
            response_bytes: kib(300),
            ..Default::default()
        })
        .await;
        assert_eq!(result.response.status(), StatusCode::OK, "{mode:?}");
        assert_eq!(result.response.headers()["x-large"].len(), kib(300));
        assert!(
            result.response.headers()["x-cookie-bytes"]
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > kib(256)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn advertised_header_caps_are_mirrored_fitted_and_enforced() {
    let result = relay_headers(Case {
        origin_cap: Some(kib_u32(16)),
        ..Default::default()
    })
    .await;
    assert_eq!(result.ingress_cap, Some(kib_u32(16)));
    assert_eq!(
        result.response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );

    let result = relay_headers(Case {
        client_cap: Some(kib_u32(16)),
        ..Default::default()
    })
    .await;
    assert_eq!(result.egress_cap, Some(kib_u32(16)));
    assert_eq!(result.response.status(), StatusCode::BAD_GATEWAY);

    let result = relay_headers(Case {
        origin_cap: Some(mib_u32(1)),
        client_cap: Some(mib_u32(1)),
        limit: kib_u32(32),
        ..Default::default()
    })
    .await;
    assert_eq!(result.ingress_cap, Some(kib_u32(32)));
    assert_eq!(result.egress_cap, Some(kib_u32(32)));
    assert_eq!(result.response.status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn explicit_context_header_caps_take_precedence_over_fallbacks() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        for literal in [false, true] {
            let mut ingress = H2ServerContextParams::default();
            let mut egress = H2ClientContextParams::default();
            if literal {
                ingress.initial_settings = Some(settings(Some(kib_u32(16))));
                egress.initial_settings = Some(settings(Some(kib_u32(16))));
            } else {
                ingress.max_header_list_size = Some(kib_u32(16));
                egress.max_header_list_size = Some(kib_u32(16));
            }
            let result = relay_headers(Case {
                mode,
                ingress,
                ..Default::default()
            })
            .await;
            assert_eq!(
                result.response.status(),
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            );
            let result = relay_headers(Case {
                mode,
                egress,
                ..Default::default()
            })
            .await;
            assert_eq!(result.response.status(), StatusCode::BAD_GATEWAY);
        }
        let result = relay_headers(Case {
            mode,
            limit: kib_u32(16),
            ingress: H2ServerContextParams {
                initial_settings: Some(settings(None)),
                max_header_list_size: Some(kib_u32(32)),
                ..Default::default()
            },
            egress: H2ClientContextParams {
                initial_settings: Some(settings(None)),
                max_header_list_size: Some(kib_u32(32)),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        assert_eq!(result.ingress_cap, None);
        assert_eq!(result.egress_cap, None);
        assert_eq!(result.response.status(), StatusCode::OK);
    }
}

#[tokio::test(start_paused = true)]
async fn explicit_initial_frames_keep_precedence_over_scalars_and_peer_frames() {
    for mode in [Mode::Eager, Mode::Lazy, Mode::LateSettings] {
        let result = relay_headers(Case {
            mode,
            origin_cap: Some(kib_u32(32)),
            client_cap: Some(kib_u32(32)),
            ingress: H2ServerContextParams {
                initial_settings: Some(settings(Some(kib_u32(64)))),
                max_header_list_size: Some(kib_u32(16)),
                ..Default::default()
            },
            egress: H2ClientContextParams {
                initial_settings: Some(settings(Some(kib_u32(64)))),
                max_header_list_size: Some(kib_u32(16)),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        assert_eq!(result.ingress_cap, Some(kib_u32(64)));
        assert_eq!(result.egress_cap, Some(kib_u32(64)));
        assert_eq!(result.response.status(), StatusCode::OK, "{mode:?}");
    }
}
