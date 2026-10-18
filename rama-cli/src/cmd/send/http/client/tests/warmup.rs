//! Preliminary exchanges use the real shared middleware without main credentials.

use super::{new_hermetic, output_dir, send_cfg, spawn_origin};
use crate::cmd::send::http::WarmupRequest;
use parking_lot::Mutex;
use rama::{
    Service,
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, StatusCode,
        header::{AUTHORIZATION, LOCATION},
    },
    service::service_fn,
};
use std::{convert::Infallible, sync::Arc};

#[tokio::test]
async fn preliminary_authentication_is_isolated_without_changing_redirect_policy() {
    // HTTP/1 is deliberate: authentication middleware is shared with H3, so
    // this checks actual network requests without coupling the test to QUIC archives.
    for trusted in [false, true] {
        let start_auth = Arc::new(Mutex::new(Vec::new()));
        let target_auth = Arc::new(Mutex::new(Vec::new()));
        let target = spawn_origin(service_fn({
            let target_auth = target_auth.clone();
            move |request: Request| {
                target_auth
                    .lock()
                    .push(request.headers().contains_key(AUTHORIZATION));
                async { Ok::<_, Infallible>(Response::new(Body::empty())) }
            }
        }))
        .await;
        let start = spawn_origin(service_fn({
            let start_auth = start_auth.clone();
            move |request: Request| {
                start_auth
                    .lock()
                    .push(request.headers().contains_key(AUTHORIZATION));
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header(LOCATION, format!("http://{target}/final"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                }
            }
        }))
        .await;

        let (_directory, output) = output_dir();
        let uri = format!("http://{start}/start");
        let mut config = send_cfg(&[
            "--http1.1",
            "--location",
            "--user",
            "test:synthetic",
            "--output",
            &output,
            &uri,
        ]);
        config.location_trusted = trusted;
        let client = new_hermetic(&config).await.unwrap();

        for preliminary in [true, true, false] {
            let request = Request::builder()
                .uri(uri.as_str())
                .body(Body::empty())
                .unwrap();
            if preliminary {
                request.extensions().insert(WarmupRequest);
            }
            assert_eq!(
                client.serve(request).await.unwrap().status(),
                StatusCode::OK
            );
        }

        assert_eq!(*start_auth.lock(), [false, false, true]);
        assert_eq!(*target_auth.lock(), [false, false, trusted]);
    }
}
