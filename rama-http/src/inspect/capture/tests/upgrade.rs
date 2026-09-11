use super::*;
use crate::{
    inspect::control::HttpUpgradeContext, layer::upgrade::mitm::HttpUpgradeMitmRelayExtensions,
};

#[tokio::test]
async fn upgrade_metadata_shares_capture_guard_until_relay_releases_it() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let store = test_store();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama_core::service::service_fn(move |request: Request| async move {
                request.into_body().collect().await.unwrap();
                Response::builder()
                    .version(version)
                    .status(if version == Version::HTTP_2 {
                        StatusCode::CREATED
                    } else {
                        StatusCode::SWITCHING_PROTOCOLS
                    })
                    .body(Body::empty())
            }),
        );
        let request = upgrade_request(version);
        let response = service.serve(request).await.unwrap();
        let selected = response
            .extensions()
            .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
            .expect("inspector selected relay metadata")
            .clone();
        assert!(selected.0.parent().is_none());
        assert_eq!(
            selected
                .0
                .get_ref::<HttpUpgradeContext>()
                .unwrap()
                .request
                .url
                .path_or_root()
                .as_ref(),
            "/socket"
        );
        let exchange_id = selected.0.get_ref::<HttpExchangeId>().unwrap().0;
        assert_eq!(
            exchange_id,
            response.extensions().get_ref::<HttpExchangeId>().unwrap().0
        );
        let guard = selected.0.get_arc::<HttpUpgradeCaptureGuard>().unwrap();
        assert!(Arc::ptr_eq(
            &guard,
            &response
                .extensions()
                .get_arc::<HttpUpgradeCaptureGuard>()
                .unwrap()
        ));
        let guard_weak = Arc::downgrade(&guard);
        drop(guard);
        response.into_body().collect().await.unwrap();
        assert!(
            guard_weak.upgrade().is_some(),
            "relay retains the shared capture guard"
        );
        assert!(
            store
                .inspector_details(exchange_id)
                .await
                .unwrap()
                .summary
                .active
        );
        drop(selected);
        assert!(
            guard_weak.upgrade().is_none(),
            "no message/transport ownership cycle"
        );
        assert!(
            !store
                .inspector_details(exchange_id)
                .await
                .unwrap()
                .summary
                .active
        );
    }
}

#[tokio::test]
async fn rejected_upgrade_does_not_stage_a_capture_lifetime_guard() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let store = test_store();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama_core::service::service_fn(move |request: Request| async move {
                request.into_body().collect().await.unwrap();
                Response::builder()
                    .version(version)
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
            }),
        );
        let response = service.serve(upgrade_request(version)).await.unwrap();
        let selected = response
            .extensions()
            .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
            .unwrap();
        assert!(selected.0.get_ref::<HttpUpgradeContext>().is_some());
        assert!(selected.0.get_ref::<HttpUpgradeCaptureGuard>().is_none());
        assert!(selected.0.get_ref::<HttpExchangeId>().is_none());
        let exchange_id = response.extensions().get_ref::<HttpExchangeId>().unwrap().0;
        response.into_body().collect().await.unwrap();
        assert!(
            !store
                .inspector_details(exchange_id)
                .await
                .unwrap()
                .summary
                .active
        );
    }
}

fn upgrade_request(version: Version) -> Request {
    let mut request = Request::builder()
        .uri("http://example.test/socket")
        .version(version)
        .method(if version == Version::HTTP_2 {
            Method::CONNECT
        } else {
            Method::GET
        })
        .body(Body::empty())
        .unwrap();
    if version == Version::HTTP_2 {
        request
            .extensions()
            .insert(crate::proto::h2::ext::Protocol::from_static("websocket"));
    } else {
        request
            .headers_mut()
            .insert("upgrade", "websocket".parse().unwrap());
    }
    request
}
