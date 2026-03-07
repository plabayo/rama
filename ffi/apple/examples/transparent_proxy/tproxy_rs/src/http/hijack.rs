use std::convert::Infallible;

use rama::{
    Service,
    bytes::Bytes,
    http::{
        Body, HeaderValue, Request, Response,
        header::CONTENT_TYPE,
        service::web::{Router, response::Html},
    },
    utils::str::NonEmptyStr,
};

pub fn new_service(
    root_ca_pem: NonEmptyStr,
) -> impl Service<Request, Output = Response, Error = Infallible> {
    Router::new()
        .with_get("/", Html(STATIC_INDEX_PAGE))
        .with_get("/data/root.ca.pem", move || {
            let mut resp =
                Response::new(Body::from(Bytes::copy_from_slice(root_ca_pem.as_bytes())));
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            );
            std::future::ready(resp)
        })
}

const STATIC_INDEX_PAGE: &str = r#"<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Rama Transparent Proxy Demo</title>
    <style>
        body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 2rem; line-height: 1.45; }
        main { max-width: 860px; margin: 0 auto; }
        h1 { margin-bottom: 0.25rem; }
        .meta { color: #555; margin-top: 0; }
        a.button { display: inline-block; margin-top: 1rem; padding: 0.65rem 1rem; background: #111; color: #fff; text-decoration: none; border-radius: 8px; }
        code { background: #f4f4f4; padding: 0.1rem 0.25rem; border-radius: 4px; }
    </style>
</head>
<body>
    <main>
        <h1>Rama Transparent Proxy Demo</h1>
        <p class="meta">Domain hijacked by the transparent proxy runtime.</p>
        <p>Your proxy is active. This endpoint is served locally by the Rust MITM stack.</p>
        <p>Install the proxy root certificate to trust MITM traffic:</p>
        <p><a class="button" href="/data/root.ca.pem">Download Root CA PEM</a></p>
    </main>
</body>
</html>
"#;
