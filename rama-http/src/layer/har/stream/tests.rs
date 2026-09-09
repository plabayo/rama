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
