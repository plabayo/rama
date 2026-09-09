use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use rama_core::{Layer, Service, service::service_fn};
use rama_inspect::storage::{MemoryStore, Storage};
use rama_utils::octets::{kib, mib_u64};
use tokio::io::{AsyncReadExt, AsyncWrite};

use super::*;
use crate::{
    Body, HeaderMap, Request, Response,
    body::util::BodyExt,
    headers::{ContentType, HeaderMapExt},
    inspect::{
        capture::{CaptureConfig, CaptureHttpLayer, CaptureStore},
        control::Message,
    },
};

struct BoundedWrites(Vec<u8>);

impl AsyncWrite for BoundedWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        assert!(data.len() <= kib(16), "body-sized write: {}", data.len());
        self.0.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn captured(request: Vec<u8>, response: Vec<u8>, form: bool) -> CaptureStore {
    let store = CaptureStore::with_storage(
        Storage::new(MemoryStore::new(Default::default())),
        CaptureConfig {
            body_limit: mib_u64(8),
            ..Default::default()
        },
        Default::default(),
    );
    let layer = CaptureHttpLayer::new(Some(store.clone()));
    let service = layer.layer(service_fn(move |request: Request| {
        let response = response.clone();
        async move {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::from(response.clone())))
        }
    }));
    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("http://example.test/upload?a=b")
                .header(
                    crate::header::CONTENT_TYPE,
                    if form {
                        "application/x-www-form-urlencoded"
                    } else {
                        "application/octet-stream"
                    },
                )
                .body(Body::from(request))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    store
}

#[tokio::test]
async fn large_bodies_and_form_fields_stream_after_clear() {
    let name = "n".repeat(kib(129));
    let value = "λ\"\n".repeat(kib(64));
    let encoded = format!(
        "{name}={}&a=hello+world&a=again&empty&bad=%GG%&utf8=%E2%82%AC",
        value.replace('\n', "%0A")
    );
    let binary: Vec<_> = (0..kib(513)).map(|index| index as u8).collect();
    let store = captured(encoded.as_bytes().to_vec(), binary.clone(), true).await;
    let capture = store.exchange_capture(1).unwrap();
    store.clear().await;
    let mut writer = BoundedWrites(Vec::new());
    write_captured_har_entry(&mut writer, &capture, &())
        .await
        .unwrap();
    let entry: spec::Entry = serde_json::from_slice(&writer.0).unwrap();
    let post = entry.request.post_data.unwrap();
    assert_eq!(post.text.as_deref(), Some(encoded.as_str()));
    let params = post.params.unwrap();
    assert_eq!(params[0].name, name.as_str());
    assert_eq!(params[0].value.as_deref(), Some(value.as_str()));
    assert_eq!(params[1].value.as_deref(), Some("hello world"));
    assert_eq!(params[2].value.as_deref(), Some("again"));
    assert_eq!(params[3].value.as_deref(), Some(""));
    assert_eq!(params[4].value.as_deref(), Some("%GG%"));
    assert_eq!(params[5].value.as_deref(), Some("€"));
    assert_eq!(entry.response.content.encoding.as_deref(), Some("base64"));
    assert_eq!(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            entry.response.content.text.unwrap()
        )
        .unwrap(),
        binary
    );
}

#[tokio::test]
async fn cancelled_export_preserves_the_capture_and_replay_stream() {
    let payload = vec![b'x'; kib(257)];
    let store = captured(payload.clone(), payload.clone(), false).await;
    let capture = store.exchange_capture(1).unwrap();
    let (mut writer, _reader) = tokio::io::duplex(32);
    tokio::time::timeout(
        Duration::from_millis(20),
        write_captured_har_entry(&mut writer, &capture, &()),
    )
    .await
    .unwrap_err();
    let replay = store.replay_request(1).await.unwrap();
    store.clear().await;
    let mut replay_bytes = Vec::new();
    replay
        .body
        .reader()
        .read_to_end(&mut replay_bytes)
        .await
        .unwrap();
    assert_eq!(replay_bytes, payload);
    let mut writer = BoundedWrites(Vec::new());
    write_captured_har_entry(&mut writer, &capture, &())
        .await
        .unwrap();
    let entry: spec::Entry = serde_json::from_slice(&writer.0).unwrap();
    assert_eq!(entry.response.content.text.unwrap().as_bytes(), payload);
}

#[tokio::test]
async fn form_export_uses_forwarded_content_type_including_removal() {
    for content_type in [Some(ContentType::form_url_encoded()), None] {
        let store = captured(b"a=hello+world".to_vec(), Vec::new(), true).await;
        let mut headers = HeaderMap::new();
        if let Some(content_type) = &content_type {
            headers.typed_insert(content_type.clone());
        }
        store
            .record_decision(1, &Message::default(), "forward", Some(&headers))
            .await;
        let mut writer = BoundedWrites(Vec::new());
        write_captured_har_entry(&mut writer, &store.exchange_capture(1).unwrap(), &())
            .await
            .unwrap();
        let entry: spec::Entry = serde_json::from_slice(&writer.0).unwrap();
        let post = entry.request.post_data.unwrap();
        assert_eq!(post.mime_type, content_type.map(ContentType::into_mime));
        assert_eq!(post.text.as_deref(), Some("a=hello+world"));
        if post.mime_type.is_some() {
            let params = post.params.unwrap();
            assert_eq!(params[0].name, "a");
            assert_eq!(params[0].value.as_deref(), Some("hello world"));
        } else {
            assert!(post.params.is_none());
        }
    }
}

mod metadata;
