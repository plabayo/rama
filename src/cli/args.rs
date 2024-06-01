//! build requests from command line arguments

use crate::{
    error::{ErrorContext, OpaqueError},
    http::{
        header::{Entry, HeaderValue, ACCEPT, CONTENT_TYPE},
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
            BuilderState::Error { message, ignored } => Err(OpaqueError::from_display(format!(
                "request arg parser failed: {} (ignored: {:?})",
                message, ignored
            ))),
            BuilderState::Data {
                content_type,
                method,
                url,
                query,
                headers,
                body,
            } => {
                let mut req = Request::builder();

                let url = if let Some(stripped_url) = url.strip_prefix(':') {
                    format!("http://localhost{}", stripped_url)
                } else if !url.contains("://") {
                    format!("http://{}", url)
                } else {
                    url.to_string()
                };

                if query.is_empty() {
                    req = req.uri(url);
                } else {
                    let uri: Uri = url.parse().map_err(OpaqueError::from_std)?;
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
                    return req.body(Body::empty()).map_err(OpaqueError::from_std);
                }

                let ct = content_type.unwrap_or(ContentType::Json);

                let req = if req.headers_ref().is_none() {
                    req.header(
                        CONTENT_TYPE,
                        match ct {
                            ContentType::Json => "application/json",
                            ContentType::Form => "application/x-www-form-urlencoded",
                        },
                    )
                    .header(
                        ACCEPT,
                        match ct {
                            ContentType::Json => "application/json",
                            ContentType::Form => "application/x-www-form-urlencoded",
                        },
                    )
                } else {
                    let headers = req.headers_mut().unwrap();

                    if let Entry::Vacant(entry) = headers.entry(CONTENT_TYPE) {
                        entry.insert(HeaderValue::from_static(match ct {
                            ContentType::Json => "application/json",
                            ContentType::Form => "application/x-www-form-urlencoded",
                        }));
                    }

                    if let Entry::Vacant(entry) = headers.entry(ACCEPT) {
                        entry.insert(HeaderValue::from_static(match ct {
                            ContentType::Json => "application/json",
                            ContentType::Form => "application/x-www-form-urlencoded",
                        }));
                    }

                    req
                };

                match ct {
                    ContentType::Json => {
                        let body = serde_json::to_string(&body)
                            .map_err(OpaqueError::from_std)
                            .context("serialize form body")?;
                        req.body(Body::from(body))
                    }
                    ContentType::Form => {
                        let body = serde_html_form::to_string(&body)
                            .map_err(OpaqueError::from_std)
                            .context("serialize json body")?;
                        req.body(Body::from(body))
                    }
                }
                .map_err(OpaqueError::from_std)
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
                state = DataParseArgState::None;
            }
            DataParseArgState::Equal => {
                let (name, value) = arg.split_at(i - 1);
                if c == '=' {
                    let value = &value[2..];
                    query
                        .entry(name.to_owned())
                        .or_default()
                        .push(value.to_owned());
                } else {
                    let value = &value[1..];
                    body.insert(name.to_owned(), Value::String(value.to_owned()));
                }
                break;
            }
            DataParseArgState::Colon => {
                let (name, value) = arg.split_at(i - 1);
                if c == '=' {
                    let value = &value[2..];
                    let value: Value =
                        serde_json::from_str(value).map_err(|err| err.to_string())?;
                    body.insert(name.to_owned(), value);
                } else {
                    let value = &value[1..];
                    headers.insert(name.to_owned(), value.to_owned());
                }
                break;
            }
        }
    }
    Ok(())
}

enum DataParseArgState {
    None,
    Escaped,
    Equal,
    Colon,
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum ContentType {
    Json,
    Form,
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
