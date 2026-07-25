//! Fuzz native JavaScript access to HTTP request and response metadata.
//!
//! Every operation is attempted through a native host object and compared
//! with the corresponding Rust parser. Rejected mutations must leave the
//! original metadata untouched.
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use rama::{
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version},
    net::uri::Uri,
};
use rama_js::{
    JsRuntime,
    http::{request_host_class, response_host_class},
};

const MAX_TEXT_BYTES: usize = 128;

#[derive(Debug)]
struct Input {
    method: String,
    uri: String,
    header_name: String,
    header_value: String,
    version: &'static str,
    status: u16,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(input: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            method: arbitrary_text(input)?,
            uri: arbitrary_text(input)?,
            header_name: arbitrary_text(input)?,
            header_value: arbitrary_text(input)?,
            version: arbitrary_version(input.arbitrary()?),
            status: input.arbitrary()?,
        })
    }
}

fn arbitrary_text(input: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let requested = usize::from(input.arbitrary::<u8>()?) % (MAX_TEXT_BYTES + 1);
    let bytes = input.bytes(requested.min(input.len()))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn arbitrary_version(selector: u8) -> &'static str {
    const VERSIONS: &[&str] = &[
        "HTTP/0.9", "0.9", "HTTP/1.0", "1.0", "HTTP/1.1", "1.1", "HTTP/2", "HTTP/2.0", "2", "2.0",
        "HTTP/3", "HTTP/3.0", "3", "3.0", "", "HTTP/4",
    ];
    VERSIONS[usize::from(selector) % VERSIONS.len()]
}

fn parse_version(value: &str) -> Option<Version> {
    match value {
        "HTTP/0.9" | "0.9" => Some(Version::HTTP_09),
        "HTTP/1.0" | "1.0" => Some(Version::HTTP_10),
        "HTTP/1.1" | "1.1" => Some(Version::HTTP_11),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Some(Version::HTTP_2),
        "HTTP/3" | "HTTP/3.0" | "3" | "3.0" => Some(Version::HTTP_3),
        _ => None,
    }
}

fuzz_target!(|input: Input| {
    let expected_method = Method::from_bytes(input.method.as_bytes()).ok();
    let expected_uri = input.uri.parse::<Uri>().ok();
    let expected_version = parse_version(input.version);
    let expected_status = StatusCode::from_u16(input.status).ok();
    let expected_header = HeaderName::from_bytes(input.header_name.as_bytes())
        .ok()
        .zip(
            HeaderValue::from_bytes(input.header_value.as_bytes())
                .ok()
                .filter(|value| value.to_str().is_ok()),
        );

    let (request_parts, _) = Request::builder()
        .header("x-stable", "yes")
        .body(())
        .expect("the fixed request must be valid")
        .into_parts();
    let (response_parts, _) = Response::new(()).into_parts();
    let (request, request_handle) = request_host_class().bind(request_parts);
    let (response, response_handle) = response_host_class().bind(response_parts);

    let mut runtime = JsRuntime::builder()
        .with_global("candidateMethod", input.method)
        .with_global("candidateUri", input.uri)
        .with_global("candidateHeaderName", input.header_name)
        .with_global("candidateHeaderValue", input.header_value)
        .with_global("candidateVersion", input.version)
        .with_global("candidateStatus", f64::from(input.status))
        .build()
        .expect("bounded globals must build a runtime");
    runtime
        .set_host_global("request", request)
        .expect("the request class must be valid");
    runtime
        .set_host_global("response", response)
        .expect("the response class must be valid");

    let outcomes = runtime
        .eval(
            r#"
            const attempt = operation => {
                try {
                    operation();
                    return true;
                } catch (error) {
                    if (!(error instanceof TypeError)) throw error;
                    return false;
                }
            };
            [
                attempt(() => { request.method = candidateMethod; }),
                attempt(() => { request.uri = candidateUri; }),
                attempt(() => {
                    request.setHeader(candidateHeaderName, candidateHeaderValue);
                }),
                attempt(() => { request.version = candidateVersion; }),
                attempt(() => { response.status = candidateStatus; }),
                attempt(() => { response.version = candidateVersion; }),
            ];
            "#,
        )
        .expect("metadata errors must be catchable JavaScript TypeErrors");
    let outcomes = outcomes
        .as_array()
        .expect("the fixed script must return an array");
    let outcomes = outcomes
        .iter()
        .map(|value| {
            value
                .as_bool()
                .expect("every operation outcome must be a boolean")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes,
        [
            expected_method.is_some(),
            expected_uri.is_some(),
            expected_header.is_some(),
            expected_version.is_some(),
            expected_status.is_some(),
            expected_version.is_some(),
        ]
    );

    let request = request_handle
        .take()
        .expect("the fixed script must return request ownership");
    assert_eq!(request.method, expected_method.unwrap_or(Method::GET));
    assert_eq!(
        request.uri,
        expected_uri.unwrap_or_else(|| Uri::from_static("/"))
    );
    assert_eq!(
        request.version,
        expected_version.unwrap_or(Version::HTTP_11)
    );

    let mut expected_headers = HeaderMap::new();
    expected_headers.insert("x-stable", HeaderValue::from_static("yes"));
    if let Some((name, value)) = expected_header {
        expected_headers.insert(name, value);
    }
    assert_eq!(request.headers, expected_headers);

    let response = response_handle
        .take()
        .expect("the fixed script must return response ownership");
    assert_eq!(response.status, expected_status.unwrap_or(StatusCode::OK));
    assert_eq!(
        response.version,
        expected_version.unwrap_or(Version::HTTP_11)
    );
});
