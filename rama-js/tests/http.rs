#![cfg(feature = "http")]

use rama_http_types::{HeaderValue, Method, Request, Response, StatusCode, Version};
use rama_js::http::{
    JsHttpError, JsHttpLayer, JsHttpScriptProvider, request_host, request_host_class,
    response_host, response_host_class,
};
use rama_js::{JsErrorKind, JsRuntime, JsScript, JsValue};

#[test]
fn request_host_exposes_and_mutates_metadata_without_touching_body() {
    let body = Box::new(42_u32);
    let body_address = (&*body) as *const u32;
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/original?x=1")
        .version(Version::HTTP_10)
        .header("accept", "text/plain")
        .body(body)
        .unwrap();
    request
        .headers_mut()
        .append("accept", HeaderValue::from_static("application/json"));
    request
        .headers_mut()
        .insert("x-remove", HeaderValue::from_static("yes"));

    let (parts, body) = request.into_parts();
    let class = request_host_class();
    let (object, handle) = class.bind(parts);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("request", object).unwrap();
    assert_eq!(
        runtime
            .eval(
                r#"
                const initial = request.method === "GET"
                    && request.uri === "https://example.com/original?x=1"
                    && request.version === "HTTP/1.0"
                    && request.header("accept") === "text/plain"
                    && request.headers("accept").length === 2
                    && request.containsHeader("x-remove")
                    && request.headerNames().includes("accept");
                request.method = "POST";
                request.uri = "https://example.com/modified";
                request.version = "HTTP/2";
                request.setHeader("accept", "text/html");
                request.appendHeader("accept", "application/xhtml+xml");
                request.setHeader("x-js-request", "yes");
                request.removeHeader("x-remove");
                initial;
                "#,
            )
            .unwrap(),
        JsValue::Bool(true),
    );

    let request = Request::from_parts(handle.take().unwrap(), body);
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().as_str(), "https://example.com/modified");
    assert_eq!(request.version(), Version::HTTP_2);
    assert_eq!(
        request
            .headers()
            .get_all("accept")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["text/html", "application/xhtml+xml"],
    );
    assert_eq!(request.headers()["x-js-request"], "yes");
    assert!(!request.headers().contains_key("x-remove"));
    assert_eq!((&**request.body()) as *const u32, body_address);
    assert_eq!(**request.body(), 42);
}

#[test]
fn response_host_exposes_and_mutates_metadata_without_touching_body() {
    let body = vec![1_u8, 2, 3];
    let body_address = body.as_ptr();
    let response = Response::builder()
        .status(StatusCode::CREATED)
        .version(Version::HTTP_2)
        .header("content-type", "application/octet-stream")
        .body(body)
        .unwrap();

    let (parts, body) = response.into_parts();
    let class = response_host_class();
    let (object, handle) = class.bind(parts);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("response", object).unwrap();
    assert_eq!(
        runtime
            .eval(
                r#"
                const initial = response.status === 201
                    && response.version === "HTTP/2.0"
                    && response.header("content-type") === "application/octet-stream";
                response.status = 202;
                response.version = "HTTP/3.0";
                response.setHeader("x-js-response", "yes");
                initial;
                "#,
            )
            .unwrap(),
        JsValue::Bool(true),
    );

    let response = Response::from_parts(handle.take().unwrap(), body);
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(response.headers()["x-js-response"], "yes");
    assert_eq!(response.body().as_ptr(), body_address);
    assert_eq!(response.body(), &[1, 2, 3]);
}

#[test]
fn http_hosts_reject_invalid_or_non_text_metadata_without_corruption() {
    let mut request = Request::builder().body(()).unwrap();
    request.headers_mut().insert(
        "x-binary",
        HeaderValue::from_bytes(&[0x80]).expect("obs-text is valid in an HTTP field value"),
    );
    let (parts, body) = request.into_parts();
    let (object, handle) = request_host(parts);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("request", object).unwrap();

    assert_eq!(
        runtime
            .eval(
                r#"
                let failures = 0;
                for (const operation of [
                    () => request.header("x-binary"),
                    () => request.setHeader("bad header", "value"),
                    () => request.setHeader("x-value", "é"),
                    () => { request.method = "bad method"; },
                    () => { request.uri = "http://[invalid"; },
                    () => { request.version = "HTTP/9"; },
                ]) {
                    try { operation(); } catch (error) {
                        if (error instanceof TypeError) failures++;
                    }
                }
                failures;
                "#,
            )
            .unwrap(),
        JsValue::Number(6.0),
    );

    let request = Request::from_parts(handle.take().unwrap(), body);
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().as_str(), "/");
    assert_eq!(request.version(), Version::HTTP_11);
    assert_eq!(request.headers()["x-binary"].as_bytes(), &[0x80]);
    assert!(!request.headers().contains_key("x-value"));
}

#[test]
fn http_hosts_deny_payload_header_mutation() {
    let mut request = Request::builder().body(()).unwrap();
    request
        .headers_mut()
        .insert("content-length", HeaderValue::from_static("3"));
    let (parts, body) = request.into_parts();
    let (object, handle) = request_host(parts);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("request", object).unwrap();

    assert_eq!(
        runtime
            .eval(
                r#"
                let failures = 0;
                for (const operation of [
                    () => request.setHeader("content-length", "0"),
                    () => request.setHeader("Transfer-Encoding", "chunked"),
                    () => request.appendHeader("content-encoding", "gzip"),
                    () => request.removeHeader("content-length"),
                    () => request.setHeader("content-range", "bytes 0-1/3"),
                    () => request.setHeader("trailer", "expires"),
                    () => request.setHeader("te", "trailers"),
                ]) {
                    try { operation(); } catch (error) {
                        if (error instanceof TypeError) failures++;
                    }
                }
                failures + (request.header("content-length") === "3" ? 1 : 0);
                "#,
            )
            .unwrap(),
        JsValue::Number(8.0),
    );

    let request = Request::from_parts(handle.take().unwrap(), body);
    assert_eq!(request.headers()["content-length"], "3");
}

#[test]
fn response_host_rejects_invalid_status_without_mutation() {
    let (parts, body) = Response::new(()).into_parts();
    let (object, handle) = response_host(parts);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("response", object).unwrap();

    let err = runtime.eval("response.status = 99").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("invalid HTTP status"));
    assert_eq!(
        Response::from_parts(handle.take().unwrap(), body).status(),
        StatusCode::OK
    );
}

#[test]
fn http_hosts_accept_every_supported_version_alias() {
    for (alias, expected_text, expected_version) in [
        ("HTTP/0.9", "HTTP/0.9", Version::HTTP_09),
        ("0.9", "HTTP/0.9", Version::HTTP_09),
        ("HTTP/1.0", "HTTP/1.0", Version::HTTP_10),
        ("1.0", "HTTP/1.0", Version::HTTP_10),
        ("HTTP/1.1", "HTTP/1.1", Version::HTTP_11),
        ("1.1", "HTTP/1.1", Version::HTTP_11),
        ("HTTP/2", "HTTP/2.0", Version::HTTP_2),
        ("HTTP/2.0", "HTTP/2.0", Version::HTTP_2),
        ("2", "HTTP/2.0", Version::HTTP_2),
        ("2.0", "HTTP/2.0", Version::HTTP_2),
        ("HTTP/3", "HTTP/3.0", Version::HTTP_3),
        ("HTTP/3.0", "HTTP/3.0", Version::HTTP_3),
        ("3", "HTTP/3.0", Version::HTTP_3),
        ("3.0", "HTTP/3.0", Version::HTTP_3),
    ] {
        let (parts, body) = Request::new(()).into_parts();
        let (object, handle) = request_host(parts);
        let mut runtime = JsRuntime::builder().build().unwrap();
        runtime.set_host_global("request", object).unwrap();

        let value = runtime
            .eval(format!("request.version = {alias:?}; request.version"))
            .unwrap();
        assert_eq!(value.as_str(), Some(expected_text));
        assert_eq!(
            Request::from_parts(handle.take().unwrap(), body).version(),
            expected_version
        );
    }
}

#[test]
fn http_error_traits_preserve_the_underlying_error() {
    let js_error = JsRuntime::eval_once("throw new Error('boom')").unwrap_err();
    let error: JsHttpError<std::io::Error> = js_error.into();
    assert!(format!("{error:?}").starts_with("JavaScript("));
    assert!(error.to_string().contains("boom"));
    assert!(std::error::Error::source(&error).is_some());

    let error = JsHttpError::Inner(std::io::Error::other("inner failure"));
    assert_eq!(
        format!("{error:?}"),
        "Inner(Custom { kind: Other, error: \"inner failure\" })"
    );
    assert_eq!(error.to_string(), "inner failure");
    assert!(std::error::Error::source(&error).is_some());
}

const MIDDLEWARE_SCRIPT: &str = r#"
    function onRequest(req) {
        req.method = "POST";
        req.setHeader("x-js-request", "yes");
    }

    function onResponse(res) {
        res.status = 202;
        res.setHeader("x-js-response", "yes");
    }
"#;

#[tokio::test]
async fn http_layer_modifies_request_and_response_around_inner_service() {
    use std::sync::Arc;

    use rama_core::{Layer, Service, service::service_fn};

    let request_body = vec![1_u8, 2, 3];
    let request_body_address = request_body.as_ptr() as usize;
    let response_body = Arc::<[u8]>::from([4_u8, 5, 6]);
    let response_body_address = response_body.as_ptr() as usize;
    let service = JsHttpLayer::new(MIDDLEWARE_SCRIPT).into_layer(service_fn(
        move |request: Request<Vec<u8>>| {
            let response_body = response_body.clone();
            async move {
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.headers()["x-js-request"], "yes");
                assert_eq!(request.body().as_ptr() as usize, request_body_address);
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .body(response_body)
                        .unwrap(),
                )
            }
        },
    ));

    let response = service
        .serve(Request::builder().body(request_body).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["x-js-response"], "yes");
    assert_eq!(response.body().as_ptr() as usize, response_body_address);
}

#[tokio::test]
async fn response_phase_is_skipped_without_an_on_response_hook() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rama_core::{Layer, Service, service::service_fn};
    use rama_js::{JsEngine, JsRuntime};

    async fn serve(script: &'static str) -> usize {
        let inner = service_fn(async |_request: Request<()>| {
            Ok::<_, std::convert::Infallible>(Response::new(()))
        });
        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = ticks.clone();
        let engine = JsEngine::new(JsRuntime::builder().with_fn("tick", move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let service = JsHttpLayer::new(script)
            .with_engine(engine)
            .into_layer(inner);
        service
            .serve(Request::builder().body(()).unwrap())
            .await
            .unwrap();
        ticks.load(Ordering::SeqCst)
    }

    assert_eq!(serve("tick(); function onRequest(req) {}").await, 1);
    assert_eq!(serve("tick();").await, 1);
    assert_eq!(
        serve("tick(); function onRequest(req) {} function onResponse(res) {}").await,
        2
    );
}

#[tokio::test]
async fn response_error_sink_passes_the_response_through() {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use rama_core::{Layer, Service, service::service_fn};

    const FAILING_SCRIPT: &str = r#"
        function onResponse(res) {
            res.setHeader("x-js-response", "yes");
            throw new Error("late failure");
        }
    "#;

    fn inner() -> impl Service<Request<()>, Output = Response<()>, Error = std::convert::Infallible>
    {
        service_fn(async |_request: Request<()>| {
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(())
                .unwrap())
        })
    }

    // fail-closed by default: the upstream response is dropped
    let service = JsHttpLayer::new(FAILING_SCRIPT).into_layer(inner());
    let err = service
        .serve(Request::builder().body(()).unwrap())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("late failure"), "{err}");

    // with a sink the error is observed and the response passes through,
    // including the mutations applied before the throw
    let sunk = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let sunk = sunk.clone();
        move |error: rama_js::JsError| sunk.lock().push(error.to_string())
    };
    let service = JsHttpLayer::new(FAILING_SCRIPT)
        .with_response_error_sink(sink)
        .into_layer(inner());
    let response = service
        .serve(Request::builder().body(()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-js-response"], "yes");
    let sunk = sunk.lock();
    assert_eq!(sunk.len(), 1);
    assert!(sunk[0].contains("late failure"), "{}", sunk[0]);
}

#[derive(Debug)]
struct PathScriptProvider;

impl JsHttpScriptProvider for PathScriptProvider {
    fn script(
        &self,
        request: &rama_http_types::request::Parts,
    ) -> Result<Option<JsScript>, rama_js::JsError> {
        Ok(request
            .uri
            .path()
            .is_some_and(|path| path == "/scripted")
            .then(|| JsScript::from("function onRequest(req) { req.method = 'PATCH'; }")))
    }
}

#[tokio::test]
async fn arc_script_provider_can_bypass_or_select_per_request() {
    use std::sync::Arc;

    use rama_core::{Service, service::service_fn};
    use rama_js::http::JsHttpService;

    let service = JsHttpService::with_provider(
        service_fn(async |request: Request<()>| {
            Ok::<_, std::convert::Infallible>(Response::new(request.method().clone()))
        }),
        Arc::new(PathScriptProvider),
    );

    let response = service
        .serve(Request::builder().uri("/plain").body(()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.into_body(), Method::GET);

    let response = service
        .serve(Request::builder().uri("/scripted").body(()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.into_body(), Method::PATCH);
}
