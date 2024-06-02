//! build requests from command line arguments

use crate::{
    error::{ErrorContext, OpaqueError},
    http::{
        header::{Entry, HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE},
        Body, Method, Request, Uri,
    },
};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
/// A builder to create a request from command line arguments.
pub struct RequestArgsBuilder {
    state: BuilderState,
}

impl Default for RequestArgsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestArgsBuilder {
    /// Create a new [`RequestArgsBuilder`], which auto-detects the content type.
    pub fn new() -> Self {
        Self {
            state: BuilderState::MethodOrUrl { content_type: None },
        }
    }

    /// Create a new [`RequestArgsBuilder`], which expects JSON data.
    pub fn new_json() -> RequestArgsBuilder {
        RequestArgsBuilder {
            state: BuilderState::MethodOrUrl {
                content_type: Some(ContentType::Json),
            },
        }
    }

    /// Create a new [`RequestArgsBuilder`], which expects Form data.
    pub fn new_form() -> RequestArgsBuilder {
        RequestArgsBuilder {
            state: BuilderState::MethodOrUrl {
                content_type: Some(ContentType::Form),
            },
        }
    }

    /// parse a command line argument, the possible meaning
    /// depend on the current state of the builder, driven by the position of the argument.
    pub fn parse_arg(&mut self, arg: String) {
        let new_state = match &mut self.state {
            BuilderState::MethodOrUrl { content_type } => {
                if let Some(method) = parse_arg_as_method(&arg) {
                    Some(BuilderState::Url {
                        content_type: *content_type,
                        method: Some(method),
                    })
                } else {
                    Some(BuilderState::Data {
                        content_type: *content_type,
                        method: None,
                        url: arg,
                        query: HashMap::new(),
                        headers: HashMap::new(),
                        body: HashMap::new(),
                    })
                }
            }
            BuilderState::Url {
                content_type,
                method,
            } => Some(BuilderState::Data {
                content_type: *content_type,
                method: method.clone(),
                url: arg,
                query: HashMap::new(),
                headers: HashMap::new(),
                body: HashMap::new(),
            }),
            BuilderState::Data {
                ref mut query,
                ref mut headers,
                ref mut body,
                ..
            } => match parse_arg_as_data(arg, query, headers, body) {
                Ok(_) => None,
                Err(msg) => Some(BuilderState::Error {
                    message: msg,
                    ignored: vec![],
                }),
            },
            BuilderState::Error {
                ref mut ignored, ..
            } => {
                ignored.push(arg);
                None
            }
        };
        if let Some(new_state) = new_state {
            self.state = new_state;
        }
    }

    /// Build the request from the parsed arguments.
    pub fn build(self) -> Result<Request, OpaqueError> {
        match self.state {
            BuilderState::MethodOrUrl { .. } | BuilderState::Url { .. } => {
                Err(OpaqueError::from_display("no url defined"))
            }
            BuilderState::Error { message, ignored } => {
                Err(OpaqueError::from_display(if ignored.is_empty() {
                    format!("request arg parser failed: {}", message)
                } else {
                    format!(
                        "request arg parser failed: {} (ignored: {:?})",
                        message, ignored
                    )
                }))
            }
            BuilderState::Data {
                content_type,
                method,
                url,
                query,
                headers,
                body,
            } => {
                let mut req = Request::builder();

                let url = expand_url(url);

                let uri: Uri = url
                    .parse()
                    .map_err(OpaqueError::from_std)
                    .context("parse base uri")?;

                if query.is_empty() {
                    req = req.uri(url);
                } else {
                    let mut uri_parts = uri.into_parts();
                    uri_parts.path_and_query = Some(match uri_parts.path_and_query {
                        Some(pq) => match pq.query() {
                            Some(q) => {
                                let mut existing_query: HashMap<String, Vec<String>> =
                                    serde_html_form::from_str(q)
                                        .map_err(OpaqueError::from_std)
                                        .context("parse existing query")?;
                                for (k, v) in query {
                                    existing_query.entry(k).or_default().extend(v);
                                }
                                let query = serde_html_form::to_string(&existing_query)
                                    .map_err(OpaqueError::from_std)
                                    .context("serialize extended query")?;
                                format!("{}?{}", pq.path(), query)
                                    .parse()
                                    .map_err(OpaqueError::from_std)
                                    .context("create new path+query from extended query")?
                            }
                            None => {
                                let query = serde_html_form::to_string(&query)
                                    .map_err(OpaqueError::from_std)
                                    .context("serialize new and only query params")?;
                                format!("{}?{}", pq.path(), query)
                                    .parse()
                                    .map_err(OpaqueError::from_std)
                                    .context("create path+query from given query params")?
                            }
                        },
                        None => {
                            let query = serde_html_form::to_string(&query)
                                .map_err(OpaqueError::from_std)?;
                            format!("/?{}", query)
                                .parse()
                                .map_err(OpaqueError::from_std)?
                        }
                    });
                    req = req.uri(Uri::from_parts(uri_parts).map_err(OpaqueError::from_std)?);
                }

                match method {
                    Some(method) => req = req.method(method),
                    None => {
                        if body.is_empty() {
                            req = req.method(Method::GET);
                        } else {
                            req = req.method(Method::POST);
                        }
                    }
                }
                for (name, value) in headers {
                    req = req.header(name, value);
                }

                if body.is_empty() {
                    return req
                        .body(Body::empty())
                        .map_err(OpaqueError::from_std)
                        .context("create request without body");
                }

                let ct = content_type.unwrap_or_else(|| {
                    match req
                        .headers_ref()
                        .and_then(|h| h.get(CONTENT_TYPE))
                        .and_then(|h| h.to_str().ok())
                    {
                        Some(cv) if cv.contains("application/x-www-form-urlencoded") => {
                            ContentType::Form
                        }
                        _ => ContentType::Json,
                    }
                });

                let req = if req.headers_ref().is_none() {
                    let req = req.header(CONTENT_TYPE, ct.header_value());
                    if ct == ContentType::Json {
                        req.header(ACCEPT, ct.header_value())
                    } else {
                        req
                    }
                } else {
                    let headers = req.headers_mut().unwrap();

                    if let Entry::Vacant(entry) = headers.entry(CONTENT_TYPE) {
                        entry.insert(ct.header_value());
                    }

                    if ct == ContentType::Json {
                        if let Entry::Vacant(entry) = headers.entry(ACCEPT) {
                            entry.insert(ct.header_value());
                        }
                    }

                    req
                };

                match ct {
                    ContentType::Json => {
                        let body = serde_json::to_string(&body)
                            .map_err(OpaqueError::from_std)
                            .context("serialize form body")?;
                        req.header(CONTENT_LENGTH, body.len().to_string())
                            .body(Body::from(body))
                    }
                    ContentType::Form => {
                        let body = serde_html_form::to_string(&body)
                            .map_err(OpaqueError::from_std)
                            .context("serialize json body")?;
                        req.header(CONTENT_LENGTH, body.len().to_string())
                            .body(Body::from(body))
                    }
                }
                .map_err(OpaqueError::from_std)
                .context("create request with body")
            }
        }
    }
}

fn parse_arg_as_data(
    arg: String,
    query: &mut HashMap<String, Vec<String>>,
    headers: &mut HashMap<String, String>,
    body: &mut HashMap<String, Value>,
) -> Result<(), String> {
    let mut state = DataParseArgState::None;
    for (i, c) in arg.chars().enumerate() {
        match state {
            DataParseArgState::None => match c {
                '\\' => state = DataParseArgState::Escaped,
                '=' => state = DataParseArgState::Equal,
                ':' => state = DataParseArgState::Colon,
                _ => (),
            },
            DataParseArgState::Escaped => {
                // \*
                state = DataParseArgState::None;
            }
            DataParseArgState::Equal => {
                let (name, value) = arg.split_at(i - 1);
                if c == '=' {
                    // ==
                    let value = &value[2..];
                    query
                        .entry(name.to_owned())
                        .or_default()
                        .push(value.to_owned());
                } else {
                    // =
                    let value = &value[1..];
                    body.insert(name.to_owned(), Value::String(value.to_owned()));
                }
                break;
            }
            DataParseArgState::Colon => {
                let (name, value) = arg.split_at(i - 1);
                if c == '=' {
                    // :=
                    let value = &value[2..];
                    let value: Value =
                        serde_json::from_str(value).map_err(|err| err.to_string())?;
                    body.insert(name.to_owned(), value);
                } else {
                    // :
                    let value = &value[1..];
                    headers.insert(name.to_owned(), value.to_owned());
                }
                break;
            }
        }
    }
    Ok(())
}

fn parse_arg_as_method(arg: impl AsRef<str>) -> Option<Method> {
    match_ignore_ascii_case_str! {
        match (arg.as_ref()) {
            "GET" => Some(Method::GET),
            "POST" => Some(Method::POST),
            "PUT" => Some(Method::PUT),
            "DELETE" => Some(Method::DELETE),
            "PATCH" => Some(Method::PATCH),
            "HEAD" => Some(Method::HEAD),
            "OPTIONS" => Some(Method::OPTIONS),
            "CONNECT" => Some(Method::CONNECT),
            "TRACE" => Some(Method::TRACE),
            _ => None,

        }
    }
}

/// Expand a URL string to a full URL,
/// e.g. `example.com` -> `http://example.com`
fn expand_url(url: String) -> String {
    if url.is_empty() {
        "http://localhost".to_owned()
    } else if let Some(stripped_url) = url.strip_prefix(':') {
        if stripped_url.is_empty() {
            "http://localhost".to_owned()
        } else if stripped_url
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or_default()
        {
            format!("http://localhost{}", url)
        } else {
            format!("http://localhost{}", stripped_url)
        }
    } else if !url.contains("://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    }
}

enum DataParseArgState {
    None,
    Escaped,
    Equal,
    Colon,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ContentType {
    Json,
    Form,
}

impl ContentType {
    fn header_value(&self) -> HeaderValue {
        HeaderValue::from_static(match self {
            ContentType::Json => "application/json",
            ContentType::Form => "application/x-www-form-urlencoded",
        })
    }
}

#[derive(Debug, Clone)]
enum BuilderState {
    MethodOrUrl {
        content_type: Option<ContentType>,
    },
    Url {
        content_type: Option<ContentType>,
        method: Option<Method>,
    },
    Data {
        content_type: Option<ContentType>,
        method: Option<Method>,
        url: String,
        query: HashMap<String, Vec<String>>,
        headers: HashMap<String, String>,
        body: HashMap<String, Value>,
    },
    Error {
        message: String,
        ignored: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::io::write_http_request;

    #[test]
    fn test_parse_arg_as_method() {
        for (arg, expected) in [
            ("GET", Some(Method::GET)),
            ("POST", Some(Method::POST)),
            ("PUT", Some(Method::PUT)),
            ("DELETE", Some(Method::DELETE)),
            ("PATCH", Some(Method::PATCH)),
            ("HEAD", Some(Method::HEAD)),
            ("OPTIONS", Some(Method::OPTIONS)),
            ("CONNECT", Some(Method::CONNECT)),
            ("TRACE", Some(Method::TRACE)),
            ("get", Some(Method::GET)),
            ("post", Some(Method::POST)),
            ("put", Some(Method::PUT)),
            ("delete", Some(Method::DELETE)),
            ("patch", Some(Method::PATCH)),
            ("head", Some(Method::HEAD)),
            ("options", Some(Method::OPTIONS)),
            ("connect", Some(Method::CONNECT)),
            ("trace", Some(Method::TRACE)),
            ("invalid", None),
            ("", None),
        ] {
            assert_eq!(parse_arg_as_method(arg), expected);
        }
    }

    #[test]
    fn test_expand_url() {
        for (url, expected) in [
            ("example.com", "http://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com", "https://example.com"),
            ("example.com:8080", "http://example.com:8080"),
            (":8080/foo", "http://localhost:8080/foo"),
            (":8080", "http://localhost:8080"),
            ("", "http://localhost"),
        ] {
            assert_eq!(expand_url(url.to_owned()), expected);
        }
    }

    #[tokio::test]
    async fn test_request_args_builder_happy() {
        for (args, expected_request_str) in [
            (vec![":8080"], "GET / HTTP/1.1\r\n\r\n"),
            (vec!["HeAD", ":8000/foo"], "HEAD /foo HTTP/1.1\r\n\r\n"),
            (
                vec![
                    "example.com/foo",
                    "c=d",
                    "Content-Type:application/x-www-form-urlencoded",
                ],
                "POST /foo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 3\r\n\r\nc=d",
            ),
            (
                vec![
                    "example.com/foo",
                    "a=b",
                    "Content-Type:application/json",
                ],
                "POST /foo HTTP/1.1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 9\r\n\r\n{\"a\":\"b\"}",
            ),
            (
                vec![
                    "example.com/foo",
                    "a=b",
                ],
                "POST /foo HTTP/1.1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 9\r\n\r\n{\"a\":\"b\"}",
            ),
            (
                vec![
                    "example.com/foo",
                    "x-a:1",
                    "a=b",
                ],
                "POST /foo HTTP/1.1\r\nx-a: 1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 9\r\n\r\n{\"a\":\"b\"}",
            ),
            (
                vec![
                    "put",
                    "example.com/foo?a=2",
                    "x-a:1",
                    "a:=42",
                    "a==3"
                ],
                "PUT /foo?a=2&a=3 HTTP/1.1\r\nx-a: 1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 8\r\n\r\n{\"a\":42}",
            ),
            (
                vec![
                    ":3000",
                    "Cookie:foo=bar",
                ],
                "GET / HTTP/1.1\r\ncookie: foo=bar\r\n\r\n",
            ),
            (
                vec![
                    ":/foo",
                    "search==rama",
                ],
                "GET /foo?search=rama HTTP/1.1\r\n\r\n",
            ),
            (
                vec![
                    "example.com",
                    "description='CLI HTTP client'",
                ],
                "POST / HTTP/1.1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 35\r\n\r\n{\"description\":\"'CLI HTTP client'\"}",
            )
        ] {
            let mut builder = RequestArgsBuilder::new();
            for arg in args {
                builder.parse_arg(arg.to_owned());
            }
            let request = builder.build().unwrap();
            let mut w = Vec::new();
            let _ = write_http_request(&mut w, request, true, true)
                .await
                .unwrap();
            assert_eq!(String::from_utf8(w).unwrap(), expected_request_str);
        }
    }

    #[tokio::test]
    async fn test_request_args_builder_form_happy() {
        for (args, expected_request_str) in [
            (
                vec![
                    "example.com/foo",
                    "c=d",
                ],
                "POST /foo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 3\r\n\r\nc=d",
            ),
        ] {
            let mut builder = RequestArgsBuilder::new_form();
            for arg in args {
                builder.parse_arg(arg.to_owned());
            }
            let request = builder.build().unwrap();
            let mut w = Vec::new();
            let _ = write_http_request(&mut w, request, true, true)
                .await
                .unwrap();
            assert_eq!(String::from_utf8(w).unwrap(), expected_request_str);
        }
    }

    #[tokio::test]
    async fn test_request_args_builder_json_happy() {
        for (args, expected_request_str) in [
            (
                vec![
                    "example.com/foo",
                    "a=b",
                ],
                "POST /foo HTTP/1.1\r\ncontent-type: application/json\r\naccept: application/json\r\ncontent-length: 9\r\n\r\n{\"a\":\"b\"}",
            ),
        ] {
            let mut builder = RequestArgsBuilder::new();
            for arg in args {
                builder.parse_arg(arg.to_owned());
            }
            let request = builder.build().unwrap();
            let mut w = Vec::new();
            let _ = write_http_request(&mut w, request, true, true)
                .await
                .unwrap();
            assert_eq!(String::from_utf8(w).unwrap(), expected_request_str);
        }
    }

    #[tokio::test]
    async fn test_request_args_builder_error() {
        for test in [
            vec![],
            vec!["invalid url"],
            vec!["get"],
            vec!["get", "invalid url"],
        ] {
            let mut builder = RequestArgsBuilder::new();
            for arg in test {
                builder.parse_arg(arg.to_owned());
            }
            let request = builder.build();
            assert!(request.is_err());
        }
    }
}
