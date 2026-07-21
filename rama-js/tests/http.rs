#![cfg(feature = "http")]

use rama_http_types::{HeaderValue, Method, Request, Response, StatusCode, Version};
use rama_js::http::{
    JsHttpLayer, JsHttpScriptProvider, request_host, request_host_class, response_host,
    response_host_class,
};
use rama_js::{JsErrorKind, JsRuntime, JsScript, JsValue};

#[test]
fn request_host_exposes_and_mutates_metadata_without_touching_body() {
    let body = Box::new(42_u32);
    let body_address = (&*body) as *const u32;
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/original?x=1")
        .version(Version::HTTP_11)
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
                    && request.version === "HTTP/1.1"
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
        .version(Version::HTTP_11)
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
                    && response.version === "HTTP/1.1"
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

const MIDDLEWARE_SCRIPT: &str = r#"
    function onRequest() {
        request.method = "POST";
        request.setHeader("x-js-request", "yes");
    }

    function onResponse() {
        response.status = 202;
        response.setHeader("x-js-response", "yes");
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
            .then(|| JsScript::from("function onRequest() { request.method = 'PATCH'; }")))
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
