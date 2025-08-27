use std::borrow::Cow;
use std::fmt::Debug;
use std::net::SocketAddr;

use crate::dep::http::request::Parts as ReqParts;
use crate::layer::har::request_comment::RequestComment;
use crate::proto::HeaderByteLength;
use crate::service::web::extract::Query;

use mime::Mime;

use rama_core::Context;
use rama_core::telemetry::tracing;
use rama_error::OpaqueError;
use rama_http_headers::HeaderEncode;
use rama_http_headers::{ContentType, Cookie as RamaCookie, HeaderMapExt, Location};
use rama_http_types::dep::http;
use rama_http_types::proto::h1::headers::original::OriginalHttp1Headers;
use rama_http_types::{HeaderMap, Version as HttpVersion, proto::h1::Http1HeaderMap};
use serde::{Deserialize, Serialize};

mod mime_serde {
    use mime::Mime;
    use serde::Serializer;

    pub(super) fn serialize<S>(mime: &Option<Mime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match mime {
            Some(m) => serializer.serialize_str(m.as_ref()),
            None => serializer.serialize_none(),
        }
    }
}

// this needs to be refactored somewhere else as
// it's widely used across the codebase
fn into_string_version(v: HttpVersion) -> Result<String, OpaqueError> {
    match v {
        HttpVersion::HTTP_09 => Ok(String::from("0.9")),
        HttpVersion::HTTP_10 => Ok(String::from("1.0")),
        HttpVersion::HTTP_11 => Ok(String::from("1.1")),
        HttpVersion::HTTP_2 => Ok(String::from("2")),
        HttpVersion::HTTP_3 => Ok(String::from("3")),
        _ => Err(OpaqueError::from_display("Unsupported HTTP Version")),
    }
}

fn into_query_string(parts: &ReqParts) -> Vec<QueryStringPair> {
    let query_str = parts.uri.query().unwrap_or("?");
    match Query::parse_query_str(query_str) {
        Ok(q) => q.0,
        Err(err) => {
            tracing::debug!("Failure to parse query string: {err:?}");
            vec![]
        }
    }
}

fn get_mime(headers: &HeaderMap) -> Option<Mime> {
    headers.typed_get::<ContentType>().map(|ct| ct.into_mime())
}

fn parse_cookies(input: &str) -> Vec<Cookie> {
    input
        .split(';') // split by semicolon
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut split = trimmed.splitn(2, '=');
            let name = split.next()?.trim().to_owned();
            let value = split.next()?.trim().to_owned();
            Some(Cookie {
                name,
                value,
                ..Default::default()
            })
        })
        .collect()
}

fn into_har_headers(header_map: &HeaderMap) -> Vec<Header> {
    header_map
        .iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: value.to_str().unwrap_or_default().to_owned(),
            comment: None,
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Log {
    pub version: Cow<'static, str>,
    pub creator: Creator,
    pub browser: Option<Browser>,
    pub pages: Vec<Page>,
    pub entries: Vec<Entry>,
    pub comment: Option<String>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            version: std::borrow::Cow::Borrowed("1.0"),
            creator: Creator {
                name: "har generator".to_owned(),
                version: std::borrow::Cow::Borrowed("1.0"),
                comment: None,
            },
            browser: None,
            pages: vec![],
            entries: vec![],
            comment: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Creator {
    pub name: String,
    pub version: Cow<'static, str>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Browser {
    pub name: String,
    pub version: Cow<'static, str>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    pub page_timings: PageTimings,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PageTimings {
    pub on_content_load: Option<f64>,
    pub on_load: Option<f64>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub pageref: Option<String>,
    pub started_date_time: String,
    /// milliseconds
    pub time: u64,
    pub request: Request,
    /// Different from spec - but a response may not arrive.
    pub response: Option<Response>,
    pub cache: Cache,
    pub timings: Timings,
    pub server_ip_address: Option<SocketAddr>,
    pub connection: Option<String>,
    pub comment: Option<String>,
}

impl Entry {
    pub fn new(
        started_date_time: String,
        time: u64,
        request: Request,
        response: Option<Response>,
        cache: Cache,
        timings: Timings,
        server_ip_address: Option<SocketAddr>,
    ) -> Self {
        Self {
            pageref: None,
            started_date_time,
            time,
            request,
            response,
            cache,
            timings,
            server_ip_address,
            connection: None,
            comment: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub query_string: Vec<QueryStringPair>,
    pub post_data: Option<PostData>,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
}

impl Request {
    pub fn from_rama_request_parts<State>(
        _ctx: &Context<State>,
        parts: http::request::Parts,
        payload: &[u8],
    ) -> Result<Self, OpaqueError>
    where
        State: Clone + Send + Sync + 'static,
    {
        let http_version = into_string_version(parts.version)?;

        let post_data = if parts.method == "POST" {
            let mime_type = get_mime(&parts.headers);
            let params = match mime_type {
                None => None,
                Some(ref ct) => {
                    if ct.subtype() == "x-www-form-urlencoded" {
                        serde_html_form::from_bytes(payload)
                            .map_err(OpaqueError::from_std)
                            .ok()
                    } else {
                        None
                    }
                }
            };

            let text = (!payload.is_empty()).then(|| String::from_utf8_lossy(payload).to_string());

            Some(PostData {
                mime_type,
                params,
                text,
                comment: None,
            })
        } else {
            None
        };

        let comment = parts
            .extensions
            .get::<RequestComment>()
            .map(|req_comment| req_comment.0.clone());

        let cookies = parts
            .headers
            .typed_get::<RamaCookie>()
            .map(|h| h.encode_to_value())
            .and_then(|hv| hv.to_str().ok().map(String::from))
            .as_deref()
            .map_or_else(Vec::new, parse_cookies);

        let query_string = into_query_string(&parts);
        let mut ext = parts.extensions;
        let headers_order: OriginalHttp1Headers = ext.remove().expect("Original order");
        let header_map =
            Http1HeaderMap::from_parts(parts.headers.clone(), headers_order).into_headers();

        let headers_size_ext = ext.get::<HeaderByteLength>();
        let headers_size = headers_size_ext.map(|v| v.0 as i64).unwrap_or(-1);

        Ok(Self {
            method: parts.method.to_string(),
            url: parts.uri.to_string(),
            http_version,
            cookies,
            headers: into_har_headers(&header_map),
            query_string,
            post_data,
            headers_size,
            body_size: payload.len() as i64,
            comment,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Response status.
    pub status: u16,
    /// Response status description.
    pub status_text: String,
    /// Response HTTP Version.
    pub http_version: String,
    /// List of cookie objects.
    pub cookies: Vec<Cookie>,
    /// List of header objects.
    pub headers: Vec<Header>,
    /// Details about the response body.
    pub content: Content,
    /// Redirection target URL from the Location response header.
    pub redirect_url: Option<String>,
    /// Total number of bytes from the start of the HTTP response message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
    pub headers_size: i64,
    /// Size of the received response body in bytes. Set to zero in case of responses coming from the cache (304). Set to -1 if the info is not available.
    pub body_size: i64,
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
}

impl Response {
    pub fn from_rama_response_parts(
        resp_parts: http::response::Parts,
        payload: &[u8],
    ) -> Result<Self, OpaqueError> {
        let http_version = into_string_version(resp_parts.version)?;

        let content = Content {
            size: payload.len() as i64,
            compression: None,
            mime_type: get_mime(&resp_parts.headers),
            text: (!payload.is_empty()).then(|| String::from_utf8_lossy(payload).to_string()),
            encoding: None,
            comment: None,
        };

        let redirect_url = resp_parts
            .headers
            .typed_get::<Location>()
            .and_then(|h| h.encode_to_value().to_str().ok().map(String::from));

        let cookies = resp_parts
            .headers
            .typed_get::<RamaCookie>()
            .map(|h| h.encode_to_value())
            .and_then(|hv| hv.to_str().ok().map(String::from))
            .as_deref()
            .map_or_else(Vec::new, parse_cookies);

        let mut ext = resp_parts.extensions;
        let headers_order: OriginalHttp1Headers = ext.remove().expect("Original order");
        let header_map =
            Http1HeaderMap::from_parts(resp_parts.headers.clone(), headers_order).into_headers();

        let headers_size_ext = ext.get::<HeaderByteLength>();
        let headers_size = headers_size_ext.map(|v| v.0 as i64).unwrap_or(-1);

        Ok(Self {
            status: 0,
            status_text: String::new(),
            http_version,
            cookies,
            headers: into_har_headers(&header_map),
            content,
            redirect_url,
            headers_size,
            body_size: payload.len() as i64,
            comment: None,
        })
    }
}

// TODO: https://github.com/plabayo/rama/issues/44
// For now this will have to be manually parsed. Needs an http-cookie logic
#[derive(Debug, Clone, Serialize, Default)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub expires: Option<String>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStringPair {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostData {
    #[serde(with = "mime_serde")]
    pub mime_type: Option<Mime>,
    pub params: Option<Vec<PostParam>>,
    pub text: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostParam {
    pub name: String,
    pub value: Option<String>,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Content {
    pub size: i64,
    pub compression: Option<i64>,
    #[serde(with = "mime_serde")]
    pub mime_type: Option<Mime>,
    pub text: Option<String>,
    /// Encoding used for response text field e.g "base64".
    /// Leave out this field if the text field is HTTP decoded (decompressed & unchunked),
    /// than trans-coded from its original character set into UTF-8.
    pub encoding: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Cache {
    pub before_request: Option<CacheState>,
    pub after_request: Option<CacheState>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheState {
    pub expires: Option<String>,
    pub last_access: Option<String>,
    pub e_tag: Option<String>,
    pub hit_count: Option<i64>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Timings {
    pub blocked: Option<u64>,
    pub dns: Option<u64>,
    pub connect: Option<u64>,
    pub send: u64,
    pub wait: u64,
    pub receive: u64,
    pub ssl: Option<u64>,
    pub comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookies() {
        let input = "name=value; name2=value2; name3=value3";
        let cookies = parse_cookies(input);

        assert_eq!(cookies.len(), 3);

        assert_eq!(cookies[0].name, "name");
        assert_eq!(cookies[0].value, "value");

        assert_eq!(cookies[1].name, "name2");
        assert_eq!(cookies[1].value, "value2");

        assert_eq!(cookies[2].name, "name3");
        assert_eq!(cookies[2].value, "value3");
    }
}
