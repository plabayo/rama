use rama_core::{extensions::ExtensionsRef as _, graceful::WeakScope, rt::spawn};
use rama_http_types::{
    Body, HeaderName, HeaderValue, Request, Response, header, proto::RequestHeaders,
};

use super::Pair;
use crate::h3::{client, connection::Config, server};

#[tokio::test(start_paused = true)]
async fn public_send_selects_only_forwardable_hosts_in_wire_form() {
    for (host, nominated, expected) in [
        (" \tother.test\t ", false, "other.test"),
        (" 2001:db8::1 ", false, "[2001:db8::1]"),
        ("other.test", true, "gateway.test"),
    ] {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, client_driver) = client::handshake::<Body, _>(
            pair.client.clone(),
            Config::default(),
            WeakScope::detached(),
        )
        .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let mut request = Request::builder()
            .uri("https://gateway.test/")
            .body(Body::empty())
            .unwrap();
        for (name, value) in [("X-First", "first"), ("hOsT", host), ("X-Last", "last")] {
            request.headers_mut().append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        if nominated {
            request
                .headers_mut()
                .append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
            request
                .headers_mut()
                .append(header::CONNECTION, HeaderValue::from_static("Host"));
        }
        let (result, ()) = tokio::join!(client.send_request(request), async {
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            assert_eq!(request.uri().authority().unwrap().to_string(), expected);
            let names: Vec<_> = request
                .headers()
                .ordered_iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(
                names,
                if nominated {
                    vec!["x-first", "x-last"]
                } else {
                    vec!["x-first", "host", "x-last"]
                }
            );
            response
                .send_response(Response::new(Body::empty()))
                .await
                .unwrap();
        });
        let response = result.unwrap();
        let recorded = response.extensions().get_ref::<RequestHeaders>().unwrap();
        let names: Vec<_> = recorded
            .ordered_iter()
            .map(|(name, _)| name.as_original_str())
            .collect();
        assert_eq!(
            names,
            if nominated {
                vec!["X-First", "X-Last"]
            } else {
                vec!["X-First", "hOsT", "X-Last"]
            }
        );
        if !nominated {
            assert_eq!(recorded[header::HOST], expected);
        }
        pair.client.close(0u32, b"complete");
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    }
}
