use std::{
    pin::Pin,
    task::{Context, Poll},
};

use rama_utils::octets::{kib, mib_u64};
use tokio::io::AsyncWrite;

use super::*;
use crate::{Request, Response};

struct RepeatedBody {
    byte: u8,
    length: u64,
}

impl HarBody for RepeatedBody {
    fn reader(&self) -> impl AsyncRead + Unpin + Send {
        tokio::io::repeat(self.byte).take(self.length)
    }
}

#[derive(Default)]
struct CountWrites(u64);

impl AsyncWrite for CountWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        assert!(bytes.len() <= kib(16), "body-sized write: {}", bytes.len());
        self.0 += bytes.len() as u64;
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn entry() -> spec::Entry {
    let request = Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap();
    let response = Response::new(());
    spec::Entry {
        page_ref: None,
        started_date_time: "2026-01-01T00:00:00Z".parse().unwrap(),
        time: 0,
        request: spec::Request::from_http_request_parts(&request.into_parts().0, &[], false)
            .unwrap(),
        response: spec::Response::from_http_response_parts(&response.into_parts().0, &[], false)
            .unwrap(),
        cache: spec::Cache::default(),
        timings: spec::Timings::default(),
        server_ip_address: None,
        connection: None,
        comment: None,
        resource_type: None,
        web_socket_messages: None,
    }
}

#[tokio::test]
async fn streamed_entry_matches_serde_without_an_inspector() {
    let entry = entry();
    let body = b"".as_slice();
    let stats = scan(body.reader()).await.unwrap();
    let mut output = Vec::new();
    write_entry(&mut output, &entry, &body, &stats, &body, &stats, &())
        .await
        .unwrap();
    let decoded: spec::Entry = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        serde_json::to_vec(&decoded).unwrap(),
        serde_json::to_vec(&entry).unwrap()
    );
}

async fn streamed_post_data(post: spec::PostData, body: &[u8]) -> spec::PostData {
    let mut entry = entry();
    entry.request.post_data = Some(post);
    let stats = scan(body.reader()).await.unwrap();
    let empty = b"".as_slice();
    let empty_stats = scan(empty.reader()).await.unwrap();
    let mut output = Vec::new();
    write_entry(
        &mut output,
        &entry,
        &body,
        &stats,
        &empty,
        &empty_stats,
        &(),
    )
    .await
    .unwrap();
    serde_json::from_slice::<spec::Entry>(&output)
        .unwrap()
        .request
        .post_data
        .unwrap()
}

#[tokio::test]
async fn provided_post_parameters_preserve_their_typed_metadata() {
    for mime in [
        "multipart/form-data; boundary=upload",
        "application/x-www-form-urlencoded",
    ] {
        for body in [b"".as_slice(), b"raw=body"] {
            let post = spec::PostData {
                mime_type: Some(mime.parse().unwrap()),
                params: Some(vec![spec::PostParam {
                    name: "upload".into(),
                    value: Some("original".into()),
                    file_name: Some("report.txt".into()),
                    content_type: Some("text/plain".into()),
                    comment: Some("captured parameter".into()),
                }]),
                text: None,
                comment: None,
            };
            let params = streamed_post_data(post, body).await.params.unwrap();
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "upload");
            assert_eq!(params[0].value.as_deref(), Some("original"));
            assert_eq!(params[0].file_name.as_deref(), Some("report.txt"));
            assert_eq!(params[0].content_type.as_deref(), Some("text/plain"));
            assert_eq!(params[0].comment.as_deref(), Some("captured parameter"));
        }
    }
}

#[tokio::test]
async fn only_urlencoded_bodies_derive_missing_post_parameters() {
    for mime in [
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=upload",
        "text/x-www-form-urlencoded",
    ] {
        for params in [None, Some(Vec::new())] {
            let had_params = params.is_some();
            let post = spec::PostData {
                mime_type: Some(mime.parse().unwrap()),
                params,
                text: None,
                comment: None,
            };
            let post = streamed_post_data(post, b"name=hello+world&name=again").await;
            assert_eq!(post.text.as_deref(), Some("name=hello+world&name=again"));
            if mime == "application/x-www-form-urlencoded" {
                let params = post.params.unwrap();
                assert_eq!(params.len(), 2);
                assert_eq!(params[0].name, "name");
                assert_eq!(params[0].value.as_deref(), Some("hello world"));
                assert_eq!(params[1].name, "name");
                assert_eq!(params[1].value.as_deref(), Some("again"));
            } else {
                assert_eq!(post.params.is_some(), had_params);
                assert!(post.params.is_none_or(|params| params.is_empty()));
            }
        }
    }
}

#[tokio::test]
async fn generated_large_body_streams_without_an_owned_payload() {
    let mut entry = entry();
    let body = RepeatedBody {
        byte: b'x',
        length: mib_u64(16),
    };
    let stats = scan(body.reader()).await.unwrap();
    assert_eq!(stats.size(), body.length);
    entry.request.post_data = Some(spec::PostData {
        mime_type: None,
        params: None,
        text: None,
        comment: None,
    });
    let mut output = CountWrites::default();
    write_entry(&mut output, &entry, &body, &stats, &body, &stats, &())
        .await
        .unwrap();
    assert!(output.0 > body.length * 2);
    assert!(output.0 < body.length * 2 + kib(4) as u64);
}

#[tokio::test]
async fn json_strings_preserve_split_unicode_and_binary() {
    let text = format!(
        "{}🙂é\\\"\n\t\u{0000}{}",
        "x".repeat(kib(8) - 1),
        "€".repeat(kib(9))
    );
    let mut output = Vec::new();
    write_json_string(&mut output, text.as_bytes(), true)
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<String>(&output).unwrap(), text);
    for size in [0, 1, 2, 3, kib(8) - 1, kib(8), kib(8) + 1, kib(16) + 1] {
        let data = vec![0xff; size];
        output.clear();
        write_json_string(&mut output, data.as_slice(), false)
            .await
            .unwrap();
        let encoded: String = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap(),
            data
        );
    }
}
