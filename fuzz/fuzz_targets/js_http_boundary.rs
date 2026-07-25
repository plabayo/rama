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
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
    },
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
    header_value2: String,
    remove_choice: u8,
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
            header_value2: arbitrary_text(input)?,
            remove_choice: input.arbitrary()?,
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

/// Mirror of the payload/framing header deny-list in rama-js `http/shared.rs`.
fn payload_header_denied(name: &HeaderName) -> bool {
    [
        header::CONTENT_LENGTH,
        header::TRANSFER_ENCODING,
        header::CONTENT_ENCODING,
        header::CONTENT_RANGE,
        header::TRAILER,
        header::TE,
    ]
    .contains(name)
}

fn parse_version(value: &str) -> Option<Version> {
    value.parse().ok()
}

fuzz_target!(|input: Input| {
    let expected_method = Method::from_bytes(input.method.as_bytes()).ok();
    let expected_uri = input.uri.parse::<Uri>().ok();
    let expected_version = parse_version(input.version);
    let expected_status = StatusCode::from_u16(input.status).ok();
    let header_name = HeaderName::from_bytes(input.header_name.as_bytes())
        .ok()
        .filter(|name| !payload_header_denied(name));
    let header_value = HeaderValue::from_bytes(input.header_value.as_bytes())
        .ok()
        .filter(|value| value.to_str().is_ok());
    let header_value2 = HeaderValue::from_bytes(input.header_value2.as_bytes())
        .ok()
        .filter(|value| value.to_str().is_ok());
    let remove_name = match input.remove_choice % 3 {
        0 => "x-stable".to_owned(),
        1 => input.header_name.clone(),
        _ => "content-length".to_owned(),
    };
    let expected_remove = HeaderName::from_bytes(remove_name.as_bytes())
        .ok()
        .filter(|name| !payload_header_denied(name));

    let request = Request::builder().header("x-stable", "yes").body(());
    assert!(
        request.is_ok(),
        "the fixed request must be valid: {:?}",
        request.as_ref().err()
    );
    let Ok(request) = request else {
        return;
    };
    let (request_parts, _) = request.into_parts();
    let (response_parts, _) = Response::new(()).into_parts();
    let (request, request_handle) = request_host_class().bind(request_parts);
    let (response, response_handle) = response_host_class().bind(response_parts);

    let runtime = JsRuntime::builder()
        .with_global("candidateMethod", input.method)
        .with_global("candidateUri", input.uri)
        .with_global("candidateHeaderName", input.header_name)
        .with_global("candidateHeaderValue", input.header_value)
        .with_global("candidateHeaderValue2", input.header_value2)
        .with_global("removeHeaderName", remove_name)
        .with_global("candidateVersion", input.version)
        .with_global("candidateStatus", f64::from(input.status))
        .build();
    assert!(
        runtime.is_ok(),
        "bounded globals must build a runtime: {:?}",
        runtime.as_ref().err()
    );
    let Ok(mut runtime) = runtime else {
        return;
    };
    let bound = runtime.set_host_global("request", request);
    assert!(
        bound.is_ok(),
        "the request class must be valid: {:?}",
        bound.err()
    );
    let bound = runtime.set_host_global("response", response);
    assert!(
        bound.is_ok(),
        "the response class must be valid: {:?}",
        bound.err()
    );

    let outcomes = runtime.eval(
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
                attempt(() => {
                    request.appendHeader(candidateHeaderName, candidateHeaderValue2);
                }),
                attempt(() => { request.removeHeader(removeHeaderName); }),
                attempt(() => { request.version = candidateVersion; }),
                attempt(() => { response.status = candidateStatus; }),
                attempt(() => { response.version = candidateVersion; }),
            ];
            "#,
    );
    assert!(
        outcomes.is_ok(),
        "metadata errors must be catchable JavaScript TypeErrors: {:?}",
        outcomes.as_ref().err()
    );
    let Ok(outcomes) = outcomes else {
        return;
    };
    let outcomes = outcomes.as_array();
    assert!(outcomes.is_some(), "the fixed script must return an array");
    let Some(outcomes) = outcomes else {
        return;
    };
    let mut flags = Vec::with_capacity(outcomes.len());
    for value in outcomes.iter() {
        let flag = value.as_bool();
        assert!(
            flag.is_some(),
            "every operation outcome must be a boolean: {value:?}"
        );
        let Some(flag) = flag else {
            return;
        };
        flags.push(flag);
    }
    let outcomes = flags;

    assert_eq!(
        outcomes,
        [
            expected_method.is_some(),
            expected_uri.is_some(),
            header_name.is_some() && header_value.is_some(),
            header_name.is_some() && header_value2.is_some(),
            expected_remove.is_some(),
            expected_version.is_some(),
            expected_status.is_some(),
            expected_version.is_some(),
        ]
    );

    let request = request_handle.take();
    assert!(
        request.is_ok(),
        "the fixed script must return request ownership: {:?}",
        request.as_ref().err()
    );
    let Ok(request) = request else {
        return;
    };
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
    if let (Some(name), Some(value)) = (header_name.clone(), header_value) {
        expected_headers.insert(name, value);
    }
    if let (Some(name), Some(value)) = (header_name, header_value2) {
        expected_headers.append(name, value);
    }
    if let Some(name) = expected_remove {
        expected_headers.remove(name);
    }
    assert_eq!(request.headers, expected_headers);

    let response = response_handle.take();
    assert!(
        response.is_ok(),
        "the fixed script must return response ownership: {:?}",
        response.as_ref().err()
    );
    let Ok(response) = response else {
        return;
    };
    assert_eq!(response.status, expected_status.unwrap_or(StatusCode::OK));
    assert_eq!(
        response.version,
        expected_version.unwrap_or(Version::HTTP_11)
    );
});
