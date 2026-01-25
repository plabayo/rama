//! This example demonstrates how to use rama's HTTP plus HAR support
//! to be able to replay previously recorded log files.
//!
//! This can be useful in function of semi automated e2e tests,
//! benchmarks, and all kind of other development reasons.
//!
//! ```sh
//! cargo run --example http_har_replay --features=http-full
//! cargo run --example http_har_replay --features=http-full -- /path/to/file.har
//! ```
//!
//! # Expected output
//!
//! You should see the requests and responses printed.

use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    graceful::Shutdown,
    http::{
        Request, Response, Uri,
        client::EasyHttpWebClient,
        layer::{
            compression::{CompressionLayer, predicate::Always},
            decompression::DecompressionLayer,
            har::spec::LogFile,
            required_header::AddRequiredResponseHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
            traffic_writer::{BidirectionalWriter, RequestWriterLayer, ResponseWriterLayer},
        },
        server::HttpServer,
    },
    layer::{Abortable, abort::AbortController},
    net::address::SocketAddress,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};
use rama_http::body::util::BodyExt;

use std::{convert::Infallible, fs, sync::Arc, time::Duration};
use tokio::sync::oneshot;

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62048);
const HAR_REQ_ID_HEADER: &str = "x-har-req-id";

#[tokio::main]
async fn main() {
    setup_tracing();

    let (shutdown_txt, shutdown_rx) = oneshot::channel();

    let graceful = Shutdown::new(shutdown_rx);

    let har_json = std::env::args()
        .nth(1)
        .map(|p| fs::read_to_string(p).expect("read har file"))
        .unwrap_or_else(|| HAR_LOG_FILE_PAYLOAD_EXAMPLE.to_owned());

    let log_file: LogFile = serde_json::from_str(&har_json).expect("parse har json");

    let min_start_time = log_file
        .log
        .entries
        .iter()
        .map(|entry| entry.started_date_time)
        .min()
        .expect("har log file with at least 1 entry");

    let log_file = Arc::new(log_file);

    tokio::spawn(run_server(ADDRESS, log_file.clone()));

    let exec = Executor::graceful(graceful.guard());
    let traffic_writer = BidirectionalWriter::stdout_unbounded(
        &exec,
        Some(rama_http::layer::traffic_writer::WriterMode::All),
        Some(rama_http::layer::traffic_writer::WriterMode::All),
    );

    let client = (
        TraceLayer::new_for_http(),
        RequestWriterLayer::new(traffic_writer.clone()),
        ResponseWriterLayer::new(traffic_writer),
        DecompressionLayer::new(),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ),
    )
        .into_layer(EasyHttpWebClient::default_with_executor(exec));

    let req_start_instant = tokio::time::Instant::now();
    for (idx, entry) in log_file.log.entries.iter().enumerate() {
        let mut req: Request = entry
            .request
            .clone()
            .try_into()
            .expect("convert har request to rama request");

        rewrite_request_uri_to_local_server(&mut req, ADDRESS);

        req.headers_mut().insert(
            rama::http::HeaderName::from_static(HAR_REQ_ID_HEADER),
            rama::http::HeaderValue::from_str(&idx.to_string()).unwrap(),
        );

        let elapsed_millis = req_start_instant.elapsed().as_millis() as i64;
        let offset_millis = (entry.started_date_time - min_start_time).num_milliseconds();
        if offset_millis > elapsed_millis {
            let emulation_delay_millis = (offset_millis - elapsed_millis) as u64;
            tracing::warn!("replay emulation: delay for {emulation_delay_millis}ms");
            tokio::time::sleep(Duration::from_millis(emulation_delay_millis)).await;
        }

        let resp = client.serve(req).await.expect("send request");
        resp.into_body().collect().await.expect("body to be loaded");
    }

    drop(client);
    shutdown_txt.send(()).unwrap();

    graceful
        .shutdown_with_limit(Duration::from_secs(1))
        .await
        .unwrap();
}

fn rewrite_request_uri_to_local_server(req: &mut Request, addr: SocketAddress) {
    let original = req.uri().clone();

    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let new_uri = Uri::builder()
        .scheme("http")
        .authority(addr.to_string())
        .path_and_query(path_and_query)
        .build()
        .expect("build uri");

    *req.uri_mut() = new_uri;
}

fn setup_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .init();
}

async fn run_server(addr: SocketAddress, log_file: Arc<LogFile>) {
    tracing::info!(
        network.local.address = %addr.ip_addr,
        network.local.port = %addr.port,
        "running server",
    );

    let exec = Executor::default();
    let http_svc = HttpServer::auto(exec.clone()).service(
        (
            AddRequiredResponseHeadersLayer::new(),
            CompressionLayer::new()
                .with_compress_predicate(Always::new())
                .with_respect_content_encoding_if_possible(),
        )
            .into_layer(service_fn(move |req: Request| {
                let log_file = Arc::clone(&log_file);
                async move {
                    let id = req
                        .headers()
                        .get(HAR_REQ_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or_default();

                    let entry = &log_file.log.entries[id % log_file.log.entries.len()];

                    let res = if let Some(har_res) = entry.response.clone() {
                        let res: Response = har_res
                            .try_into()
                            .expect("convert har response to rama response");
                        res
                    } else {
                        req.extensions()
                            .get::<AbortController>()
                            .unwrap()
                            .abort()
                            .await;
                        unreachable!();
                    };

                    Ok::<_, Infallible>(res)
                }
            })),
    );

    TcpListener::bind(ADDRESS, exec)
        .await
        .unwrap()
        .serve(Abortable::new(http_svc))
        .await;
}

const HAR_LOG_FILE_PAYLOAD_EXAMPLE: &str = r##"{"log":{"version":"1.2","creator":{"name":"Firefox","version":"147.0"},"browser":{"name":"Firefox","version":"147.0"},"pages":[{"id":"page_1","pageTimings":{"onContentLoad":46,"onLoad":51},"startedDateTime":"2026-01-25T17:24:58.370+01:00","title":"https://http-test.ramaproxy.org/sse"}],"entries":[{"startedDateTime":"2026-01-25T17:24:58.370+01:00","request":{"bodySize":0,"method":"GET","url":"https://example.com/","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"example.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Upgrade-Insecure-Requests","value":"1"},{"name":"Sec-Fetch-Dest","value":"document"},{"name":"Sec-Fetch-Mode","value":"navigate"},{"name":"Sec-Fetch-Site","value":"none"},{"name":"Sec-Fetch-User","value":"?1"},{"name":"Priority","value":"u=0, i"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"},{"name":"TE","value":"trailers"}],"cookies":[],"queryString":[],"headersSize":492},"response":{"status":200,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"date","value":"Sun, 25 Jan 2026 16:24:58 GMT"},{"name":"content-type","value":"text/html"},{"name":"content-encoding","value":"gzip"},{"name":"last-modified","value":"Fri, 23 Jan 2026 20:54:05 GMT"},{"name":"allow","value":"GET, HEAD"},{"name":"age","value":"2388"},{"name":"cf-cache-status","value":"HIT"},{"name":"vary","value":"Accept-Encoding"},{"name":"server","value":"cloudflare"},{"name":"cf-ray","value":"9c391fb509003d1a-BRU"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/html","size":513,"text":"<!doctype html><html lang=\"en\"><head><title>Example Domain</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href=\"https://iana.org/domains/example\">Learn more</a></div></body></html>\n"},"redirectURL":"","headersSize":291,"bodySize":657},"cache":{},"timings":{"blocked":-1,"dns":0,"connect":0,"ssl":0,"send":0,"wait":34,"receive":0},"time":34,"_securityState":"secure","serverIPAddress":"2606:4700::6812:1a78","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:24:58.420+01:00","request":{"bodySize":0,"method":"GET","url":"https://example.com/favicon.ico","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"example.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Referer","value":"https://example.com/"},{"name":"Sec-Fetch-Dest","value":"image"},{"name":"Sec-Fetch-Mode","value":"no-cors"},{"name":"Sec-Fetch-Site","value":"same-origin"},{"name":"Priority","value":"u=6"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"}],"cookies":[],"queryString":[],"headersSize":490},"response":{"status":404,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"date","value":"Sun, 25 Jan 2026 16:24:58 GMT"},{"name":"content-type","value":"text/html"},{"name":"content-encoding","value":"gzip"},{"name":"cf-cache-status","value":"HIT"},{"name":"age","value":"100"},{"name":"vary","value":"Accept-Encoding"},{"name":"server","value":"cloudflare"},{"name":"cf-ray","value":"9c391fb549ab3d1a-BRU"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/html","size":513,"text":"<!doctype html><html lang=\"en\"><head><title>Example Domain</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href=\"https://iana.org/domains/example\">Learn more</a></div></body></html>\n"},"redirectURL":"","headersSize":226,"bodySize":592},"cache":{},"timings":{"blocked":0,"dns":0,"connect":0,"ssl":0,"send":0,"wait":28,"receive":0},"time":28,"_securityState":"secure","serverIPAddress":"2606:4700::6812:1a78","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:25:00.619+01:00","request":{"bodySize":0,"method":"GET","url":"https://http-test.ramaproxy.org/response-stream-compression","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"http-test.ramaproxy.org"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Upgrade-Insecure-Requests","value":"1"},{"name":"Sec-Fetch-Dest","value":"document"},{"name":"Sec-Fetch-Mode","value":"navigate"},{"name":"Sec-Fetch-Site","value":"none"},{"name":"Sec-Fetch-User","value":"?1"},{"name":"Priority","value":"u=0, i"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"}],"cookies":[],"queryString":[],"headersSize":531},"response":{"status":200,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"content-type","value":"text/html; charset=utf-8"},{"name":"vary","value":"accept-encoding"},{"name":"content-encoding","value":"zstd"},{"name":"x-sponsored-by","value":"fly.io"},{"name":"server","value":"rama/0.3.0-rc1"},{"name":"date","value":"Sun, 25 Jan 2026 16:25:00 GMT"},{"name":"x-clacks-overhead","value":"GNU Bram Moolenaar"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/html; charset=utf-8","size":353,"text":"<!DOCTYPE html>\n<html lang=en>\n<head>\n<meta charset='utf-8'>\n<title>Chunked transfer encoding test</title>\n</head>\n<body><h1>Chunked transfer encoding test</h1><h5>This is a chunked response after 100 ms.</h5><h5>This is a chunked response after 1 second.\nThe server should not close the stream before all chunks are sent to a client.</h5></body></html>"},"redirectURL":"","headersSize":246,"bodySize":511},"cache":{},"timings":{"blocked":121,"dns":48,"connect":29,"ssl":46,"send":0,"wait":66,"receive":0},"time":310,"_securityState":"secure","serverIPAddress":"2a09:8280:1::ba:3ab1:0","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:25:00.870+01:00","request":{"bodySize":0,"method":"GET","url":"https://http-test.ramaproxy.org/favicon.ico","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"http-test.ramaproxy.org"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Referer","value":"https://http-test.ramaproxy.org/response-stream-compression"},{"name":"Sec-Fetch-Dest","value":"image"},{"name":"Sec-Fetch-Mode","value":"no-cors"},{"name":"Sec-Fetch-Site","value":"same-origin"},{"name":"Priority","value":"u=6"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"}],"cookies":[],"queryString":[],"headersSize":541},"response":{"status":404,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"x-sponsored-by","value":"fly.io"},{"name":"server","value":"rama/0.3.0-rc1"},{"name":"date","value":"Sun, 25 Jan 2026 16:25:00 GMT"},{"name":"x-clacks-overhead","value":"GNU Bram Moolenaar"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/plain","size":0,"text":""},"redirectURL":"","headersSize":159,"bodySize":159},"cache":{},"timings":{"blocked":0,"dns":0,"connect":0,"ssl":0,"send":0,"wait":30,"receive":0},"time":30,"_securityState":"secure","serverIPAddress":"2a09:8280:1::ba:3ab1:0","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:25:04.446+01:00","request":{"bodySize":0,"method":"GET","url":"https://http-test.ramaproxy.org/sse","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"http-test.ramaproxy.org"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Upgrade-Insecure-Requests","value":"1"},{"name":"Sec-Fetch-Dest","value":"document"},{"name":"Sec-Fetch-Mode","value":"navigate"},{"name":"Sec-Fetch-Site","value":"none"},{"name":"Sec-Fetch-User","value":"?1"},{"name":"Priority","value":"u=0, i"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"},{"name":"TE","value":"trailers"}],"cookies":[],"queryString":[],"headersSize":507},"response":{"status":200,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"content-type","value":"text/html; charset=utf-8"},{"name":"x-sponsored-by","value":"fly.io"},{"name":"server","value":"rama/0.3.0-rc1"},{"name":"date","value":"Sun, 25 Jan 2026 16:25:04 GMT"},{"name":"x-clacks-overhead","value":"GNU Grant Imahara"},{"name":"content-length","value":"1937"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/html; charset=utf-8","size":1937,"text":"<!doctype html>\n<html lang=\"en\">\n    <head>\n    <meta charset=\"utf-8\" />\n    <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n    <title>Rama HTTP SSE Test</title>\n    <style>\n        body { font-family: system-ui, sans-serif; margin: 0; padding: 0; }\n        main { min-height: 100vh; display: grid; justify-items: center; }\n        ul { list-style: none; padding: 0; margin: 0; width: min(560px, 92vw); }\n        li { padding: 10px 12px; border: 1px solid #ddd; border-radius: 10px; margin: 10px 0; }\n        .hint { opacity: 0.7; font-size: 14px; margin-top: 10px; text-align: center; }\n        label { display: inline-flex; gap: 8px; cursor: pointer; }\n        input:checked + label { text-decoration: line-through; opacity: 0.6; }\n    </style>\n    </head>\n    <body>\n    <main>\n        <div>\n        <h1>TODO:</h1>\n        <ul id=\"todos\"></ul>\n        <div class=\"hint\" id=\"status\">Connecting…</div>\n        </div>\n    </main>\n\n    <script>\n        let nextId = 0;\n        const list = document.getElementById(\"todos\");\n        const statusEl = document.getElementById(\"status\");\n\n        const es = new EventSource(\"/sse\");\n\n        function addTodo(text) {\n          const li = document.createElement(\"li\");\n\n          const id = \"todo-\" + nextId++;\n\n          const checkbox = document.createElement(\"input\");\n          checkbox.type = \"checkbox\";\n          checkbox.id = id;\n\n          const label = document.createElement(\"label\");\n          label.htmlFor = id;\n          label.textContent = text;\n\n          li.appendChild(checkbox);\n          li.appendChild(label);\n          list.appendChild(li);\n        }\n\n        es.onopen = () => { statusEl.textContent = \"Connected\"; };\n        es.onerror = () => { es.close(); statusEl.textContent = \"Disconnected\"; };\n\n        es.onmessage = (ev) => {\n            if (!ev.data) return;\n            addTodo(ev.data);\n        };\n    </script>\n    </body>\n</html>\n"},"redirectURL":"","headersSize":220,"bodySize":2157},"cache":{},"timings":{"blocked":-1,"dns":0,"connect":0,"ssl":0,"send":0,"wait":36,"receive":0},"time":36,"_securityState":"secure","serverIPAddress":"2a09:8280:1::ba:3ab1:0","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:25:04.502+01:00","request":{"bodySize":0,"method":"GET","url":"https://http-test.ramaproxy.org/sse","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"http-test.ramaproxy.org"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"text/event-stream"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Referer","value":"https://http-test.ramaproxy.org/sse"},{"name":"Sec-Fetch-Dest","value":"empty"},{"name":"Sec-Fetch-Mode","value":"cors"},{"name":"Sec-Fetch-Site","value":"same-origin"},{"name":"Priority","value":"u=4"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"},{"name":"TE","value":"trailers"}],"cookies":[],"queryString":[],"headersSize":454},"response":{"status":200,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"cache-control","value":"no-cache"},{"name":"content-type","value":"text/event-stream"},{"name":"x-clacks-overhead","value":"GNU Grant Imahara"},{"name":"x-sponsored-by","value":"fly.io"},{"name":"server","value":"rama/0.3.0-rc1"},{"name":"date","value":"Sun, 25 Jan 2026 16:25:04 GMT"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/event-stream","size":146,"text":"data: Wake up slowly, enjoy morning light\n\ndata: Make loose plans, feel excited\n\ndata: Do one thing, celebrate it\n\ndata: Go to bed, feeling okay\n\n"},"redirectURL":"","headersSize":216,"bodySize":362},"cache":{},"timings":{"blocked":-1,"dns":0,"connect":0,"ssl":0,"send":0,"wait":28,"receive":0},"time":28,"_securityState":"secure","serverIPAddress":"2a09:8280:1::ba:3ab1:0","connection":"443","pageref":"page_1"},{"startedDateTime":"2026-01-25T17:25:04.606+01:00","request":{"bodySize":0,"method":"GET","url":"https://http-test.ramaproxy.org/favicon.ico","httpVersion":"HTTP/2","headers":[{"name":"Host","value":"http-test.ramaproxy.org"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"},{"name":"Accept","value":"image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"},{"name":"Accept-Language","value":"en-US,en;q=0.9"},{"name":"Accept-Encoding","value":"gzip, deflate, br, zstd"},{"name":"Connection","value":"keep-alive"},{"name":"Referer","value":"https://http-test.ramaproxy.org/sse"},{"name":"Sec-Fetch-Dest","value":"image"},{"name":"Sec-Fetch-Mode","value":"no-cors"},{"name":"Sec-Fetch-Site","value":"same-origin"},{"name":"Priority","value":"u=6"},{"name":"Pragma","value":"no-cache"},{"name":"Cache-Control","value":"no-cache"},{"name":"TE","value":"trailers"}],"cookies":[],"queryString":[],"headersSize":517},"response":{"status":404,"statusText":"","httpVersion":"HTTP/2","headers":[{"name":"x-sponsored-by","value":"fly.io"},{"name":"server","value":"rama/0.3.0-rc1"},{"name":"date","value":"Sun, 25 Jan 2026 16:25:04 GMT"},{"name":"x-clacks-overhead","value":"GNU Grant Imahara"},{"name":"X-Firefox-Spdy","value":"h2"}],"cookies":[],"content":{"mimeType":"text/plain","size":0,"text":""},"redirectURL":"","headersSize":158,"bodySize":158},"cache":{},"timings":{"blocked":0,"dns":0,"connect":0,"ssl":0,"send":0,"wait":28,"receive":0},"time":28,"_securityState":"secure","serverIPAddress":"2a09:8280:1::ba:3ab1:0","connection":"443","pageref":"page_1"}]}}"##;
