//! End-to-end test for the combined HTTP proxy and ICAP server example.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::utils;

const PROXY_URI: &str = "http://127.0.0.1:62059";

#[tokio::test]
#[ignore]
async fn test_http_icap_proxy() {
    utils::init_tracing();

    let (origin_port, expected) = spawn_origin().await;
    let _runner = utils::ExampleRunner::interactive_with_args(
        "http_icap_proxy",
        Some("icap"),
        ["--target-host", "127.0.0.1"],
    );

    let adapted = tokio::time::timeout(
        Duration::from_secs(10),
        proxy_get("127.0.0.1", origin_port, "/adapted"),
    )
    .await
    .expect("adapted proxy request timed out")
    .unwrap();
    assert!(
        adapted
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("x-rama-icap: adapted"))
    );
    assert_eq!(adapted.body, expected.as_bytes());

    let trailer_only = tokio::time::timeout(
        Duration::from_secs(10),
        proxy_get("127.0.0.1", origin_port, "/trailers"),
    )
    .await
    .expect("trailer-only proxy request timed out")
    .unwrap();
    assert!(
        trailer_only
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("x-rama-icap: adapted"))
    );
    assert!(
        trailer_only
            .body
            .windows(b"x-end: kept".len())
            .any(|window| window.eq_ignore_ascii_case(b"x-end: kept")),
        "response head: {}\nresponse body: {}",
        trailer_only.head,
        String::from_utf8_lossy(&trailer_only.body),
    );
}

struct RawResponse {
    head: String,
    body: Vec<u8>,
}

async fn proxy_get(host: &str, port: u16, path: &str) -> std::io::Result<RawResponse> {
    let proxy = PROXY_URI.trim_start_matches("http://");
    let mut attempts = 0;
    let mut stream = loop {
        match tokio::net::TcpStream::connect(proxy).await {
            Ok(stream) => break stream,
            Err(_error) if attempts < 40 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error),
        }
    };
    let request = format!(
        "GET http://{host}:{port}{path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         TE: trailers\r\n\
         Connection: TE, close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("proxy response has no header terminator"))?;
    let body = response.split_off(head_end + 4);
    response.truncate(head_end);
    let head = String::from_utf8(response)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(RawResponse { head, body })
}

async fn spawn_origin() -> (u16, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let payload = "rama".repeat(1025);
    let response_payload = payload.clone().into_bytes();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let payload = response_payload.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() <= 16 * 1024);
                }
                if request
                    .windows(b" /trailers ".len())
                    .any(|window| window == b" /trailers ")
                {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
                              Transfer-Encoding: chunked\r\n\
                              Trailer: x-end\r\n\
                              Connection: close\r\n\r\n\
                              0\r\n\
                              x-end: kept\r\n\r\n",
                        )
                        .await
                        .unwrap();
                } else {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        payload.len(),
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                }
            });
        }
    });
    (port, payload)
}
