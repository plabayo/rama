// NOTE: spec can be found in ./spec.md

use std::borrow::Cow;
use std::fmt::Debug;
use std::str::FromStr;

use crate::dep::http::request::Parts as ReqParts;
use crate::layer::har::extensions::RequestComment;
use crate::proto::HeaderByteLength;
use crate::service::web::extract::Query;

use rama_core::Context;
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use rama_http_headers::{ContentType, Cookie as RamaCookie, HeaderMapExt, Location};
use rama_http_headers::{HeaderEncode, SetCookie};
use rama_http_types::dep::http;
use rama_http_types::proto::h1::Http1HeaderName;
use rama_http_types::{HeaderMap, Version as RamaHttpVersion, proto::h1::Http1HeaderMap};
use rama_net::address::SocketAddress;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use chrono::{DateTime, Utc};
use mime::Mime;
use serde::{Deserialize, Serialize};

mod mime_serde {
    use mime::Mime;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{borrow::Cow, str::FromStr};

    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S>(mime: &Option<Mime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(mime) = mime {
            serializer.serialize_str(mime.as_ref())
        } else {
            serializer.serialize_none()
        }
    }

    pub(super) fn deserialize<'de, D>(d: D) -> Result<Option<Mime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = <Option<Cow<'de, str>>>::deserialize(d)?;
        if let Some(s) = opt {
            Mime::from_str(&s).map_err(Error::custom).map(Some)
        } else {
            Ok(None)
        }
    }
}

mod chrono_serializer {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::borrow::Cow;

    pub(super) fn serialize<S>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&dt.to_rfc3339())
    }

    pub(super) fn deserialize<'de, D>(d: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Cow<'de, str>>::deserialize(d)?;
        Ok(DateTime::parse_from_rfc3339(&s)
            .map_err(Error::custom)?
            .to_utc())
    }
}

rama_utils::macros::enums::enum_builder! {
    @String
    pub enum HttpVersion {
        Http09 => "0.9" | "HTTP/0.9",
        Http10 => "1.0" | "HTTP/1" | "HTTP/1.0",
        Http11 => "1.1" | "HTTP/1.1",
        Http2 => "2" | "HTTP/2" | "h2",
        Http3 => "3" | "HTTP/3" | "h3",
    }
}

impl From<RamaHttpVersion> for HttpVersion {
    fn from(rhv: RamaHttpVersion) -> Self {
        match rhv {
            RamaHttpVersion::HTTP_09 => Self::Http09,
            RamaHttpVersion::HTTP_10 => Self::Http10,
            RamaHttpVersion::HTTP_11 => Self::Http11,
            RamaHttpVersion::HTTP_2 => Self::Http2,
            RamaHttpVersion::HTTP_3 => Self::Http3,
            other => Self::Unknown(format!("{other:?}")),
        }
    }
}

impl TryFrom<HttpVersion> for RamaHttpVersion {
    type Error = HttpVersion;

    fn try_from(rhv: HttpVersion) -> Result<Self, Self::Error> {
        match rhv {
            HttpVersion::Http09 => Ok(Self::HTTP_09),
            HttpVersion::Http10 => Ok(Self::HTTP_10),
            HttpVersion::Http11 => Ok(Self::HTTP_11),
            HttpVersion::Http2 => Ok(Self::HTTP_2),
            HttpVersion::Http3 => Ok(Self::HTTP_3),
            v @ HttpVersion::Unknown(_) => Err(v),
        }
    }
}

fn into_query_string(parts: &ReqParts) -> Vec<QueryStringPair> {
    let Some(query_str) = parts.uri.query() else {
        return Vec::default();
    };

    match Query::parse_query_str(query_str) {
        Ok(q) => q.0,
        Err(err) => {
            tracing::debug!("failure to parse query string: {err:?}");
            vec![]
        }
    }
}

fn get_mime(headers: &HeaderMap) -> Option<Mime> {
    headers.typed_get::<ContentType>().map(|ct| ct.into_mime())
}

fn parse_cookie_part(part: &str) -> Option<Cookie> {
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
}

fn into_har_headers(header_map: Http1HeaderMap) -> Vec<Header> {
    header_map
        .into_iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: match value.to_str() {
                Ok(s) => s.to_owned(),
                Err(_) => format!("{value:x?}"),
            },
            comment: None,
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object represents the exported data structure.
pub struct LogFile {
    /// The HAR log data.
    pub log: Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object represents the root of exported data.
pub struct Log {
    /// Version number of the format. If empty, string "1.1" is assumed by default.
    pub version: Cow<'static, str>,
    /// Name and version info of the log creator application.
    pub creator: Creator,
    /// Name and version info of used browser.
    pub browser: Option<Browser>,
    /// List of all exported (tracked) pages.
    ///
    /// Leave out this field if the application does not support grouping by pages.
    pub pages: Option<Vec<Page>>,
    /// List of all exported (tracked) requests.
    pub entries: Vec<Entry>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

/// HAR Log Version used by rama
pub const HAR_LOG_VERSION: &str = "1.2";

impl Default for Log {
    fn default() -> Self {
        Self {
            version: std::borrow::Cow::Borrowed(HAR_LOG_VERSION),
            creator: Creator {
                name: rama_utils::info::NAME.into(),
                version: rama_utils::info::VERSION.into(),
                comment: None,
            },
            browser: None,
            pages: None,
            entries: vec![],
            comment: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Creator and browser objects share the same structure.
pub struct Creator {
    pub name: Cow<'static, str>,
    pub version: Cow<'static, str>,
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Browser {
    /// Name of the application/browser used to export the log.
    pub name: String,
    /// Version of the application/browser used to export the log.
    pub version: Option<String>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    /// Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    #[serde(with = "chrono_serializer", rename = "startedDateTime")]
    pub started_date_time: DateTime<Utc>,
    /// Unique identifier of a page within the [Log]. Entries use it to refer the parent page.
    pub id: String,
    /// Page title
    pub title: String,
    /// Detailed timing info about page load.
    #[serde(rename = "pageTimings")]
    pub page_timings: PageTimings,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object describes timings for various events (states) fired during the page load.
///
/// All times are specified in milliseconds.
/// If a time info is not available appropriate field is set to -1.
pub struct PageTimings {
    /// Content of the page loaded.
    ///
    /// Number of milliseconds since page load started (page.startedDateTime).
    /// Use -1 if the timing does not apply to the current request.
    #[serde(rename = "onContentLoad")]
    pub on_content_load: Option<u64>,
    /// Page is loaded (onLoad event fired).
    ///
    /// Number of milliseconds since page load started (page.startedDateTime).
    /// Use -1 if the timing does not apply to the current request.
    #[serde(rename = "onLoad")]
    pub on_load: Option<u64>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object represents a single exportred request with its response and metadata.
pub struct Entry {
    /// Reference to the parent page.
    ///
    /// Leave out this field if the application does not support grouping by pages.
    #[serde(rename = "pageref")]
    pub page_ref: Option<String>,
    /// Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    #[serde(with = "chrono_serializer", rename = "startedDateTime")]
    pub started_date_time: DateTime<Utc>,
    /// Total elapsed time of the request in milliseconds.
    ///
    /// This is the sum of all timings available in the timings object (i.e. not including -1 values).
    pub time: u64,
    /// Detailed info about the request.
    pub request: Request,
    /// Detailed info about the response.
    pub response: Option<Response>,
    /// Info about cache usage.
    pub cache: Cache,
    /// Detailed timing info about request/response round trip.
    pub timings: Timings,
    /// IP address of the server that was connected
    ///
    /// (result of DNS resolution).
    #[serde(rename = "serverAddress")]
    pub server_address: Option<SocketAddress>, // TODO: be able to provide for client middleware
    /// Unique ID of the parent TCP/IP connection,
    /// can be the client or server port number.
    ///
    /// Note that a port number doesn't have to be unique identifier
    /// in cases where the port is shared for more connections.
    /// If the port isn't available for the application,
    /// any other unique connection ID can be used instead (e.g. connection index).
    ///
    /// Leave out this field if the application doesn't support this info.
    pub connection: Option<String>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object contains detailed info about performed request.
pub struct Request {
    /// Request method (GET, POST, ...).
    pub method: String,
    /// Absolute URL of the request (fragments are not included).
    pub url: String,
    /// Request HTTP Version.
    #[serde(rename = "httpVersion")]
    pub http_version: HttpVersion,
    /// List of cookie objects.
    pub cookies: Vec<Cookie>,
    /// List of header objects.
    pub headers: Vec<Header>,
    /// List of query parameter objects.
    #[serde(rename = "queryString")]
    pub query_string: Vec<QueryStringPair>,
    /// Posted data info.
    #[serde(rename = "postData")]
    pub post_data: Option<PostData>,
    /// Total number of bytes from the start of the HTTP request message
    ///
    /// Until (and including) the double CRLF before the body.
    ///
    /// Set to -1 if the info is not available.
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    /// Size of the request body (POST data payload) in bytes.
    ///
    /// Set to -1 if the info is not available.
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

impl TryFrom<Request> for crate::Request {
    type Error = OpaqueError;

    fn try_from(har_request: Request) -> Result<Self, Self::Error> {
        let body = if let Some(text) = har_request.post_data.and_then(|pd| pd.text) {
            if let Ok(bin) = ENGINE.decode(&text) {
                crate::Body::from(bin)
            } else {
                crate::Body::from(text)
            }
        } else {
            crate::Body::empty()
        };

        let mut orig_headers = Http1HeaderMap::with_capacity(har_request.headers.len());
        for header in har_request.headers {
            orig_headers.append(
                Http1HeaderName::from_str(&header.name).context("convert http header name")?,
                crate::HeaderValue::from_maybe_shared(header.value)
                    .context("convert http header value")?,
            );
        }
        let (headers, orig_headers) = orig_headers.into_parts();

        let builder = crate::Request::builder()
            .method(
                har_request
                    .method
                    .parse::<crate::Method>()
                    .context("parse HAR HTTP Method")?,
            )
            .uri(har_request.url);

        let builder = if let Ok(ver) = har_request.http_version.try_into() {
            builder.version(ver)
        } else {
            builder
        };

        let mut req = builder
            .body(body)
            .context("build http request from HAR data")?;

        *req.headers_mut() = headers;
        req.extensions_mut().insert(orig_headers);

        if let Some(comment) = har_request.comment {
            req.extensions_mut().insert(RequestComment::new(comment));
        }

        Ok(req)
    }
}

impl Request {
    pub fn from_http_request_parts(
        ctx: &Context,
        parts: &http::request::Parts,
        payload: &[u8],
    ) -> Result<Self, OpaqueError> {
        let post_data = if !payload.is_empty() {
            let mime_type = get_mime(&parts.headers);
            let params = if mime_type
                .as_ref()
                .map(|m| m.subtype() == mime::WWW_FORM_URLENCODED)
                .unwrap_or_default()
            {
                Some(serde_html_form::from_bytes(payload).context("decode form body payload")?)
            } else {
                None
            };

            let text = match std::str::from_utf8(payload) {
                Ok(s) => s.to_owned(),
                Err(_) => ENGINE.encode(payload),
            };

            Some(PostData {
                mime_type,
                params,
                text: Some(text),
                comment: None,
            })
        } else {
            None
        };

        let comment = parts
            .extensions
            .get::<RequestComment>()
            .or_else(|| ctx.get::<RequestComment>())
            .map(|req_comment| req_comment.0.clone());

        let cookies = parts
            .headers
            .typed_get::<RamaCookie>()
            .map(|c| {
                c.iter()
                    .map(|(k, v)| Cookie {
                        name: k.to_owned(),
                        value: v.to_owned(),
                        path: None,
                        domain: None,
                        expires: None,
                        http_only: None,
                        secure: None,
                        comment: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let query_string = into_query_string(parts);
        let headers_order = parts.extensions.get().cloned().unwrap_or_default();
        let header_map = Http1HeaderMap::from_parts(parts.headers.clone(), headers_order);

        let headers_size_ext = parts.extensions.get::<HeaderByteLength>();
        let headers_size = headers_size_ext.map(|v| v.0 as i64).unwrap_or(-1);

        Ok(Self {
            method: parts.method.to_string(),
            url: parts.uri.to_string(),
            http_version: parts.version.into(),
            cookies,
            headers: into_har_headers(header_map),
            query_string,
            post_data,
            headers_size,
            body_size: payload.len() as i64,
            comment,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object contains detailed info about the response.
pub struct Response {
    /// Response status.
    pub status: u16,
    /// Response status description.
    #[serde(rename = "statusText")]
    pub status_text: Option<Cow<'static, str>>,
    /// Response HTTP Version.
    pub http_version: HttpVersion,
    /// List of cookie objects.
    pub cookies: Vec<Cookie>,
    /// List of header objects.
    pub headers: Vec<Header>,
    /// Details about the response body.
    pub content: Content,
    /// Redirection target URL from the Location response header.
    #[serde(rename = "redirectUrl")]
    pub redirect_url: Option<String>,
    /// Total number of bytes from the start of the HTTP response message
    ///
    /// Until (and including) the double CRLF before the body.
    ///
    /// Set to -1 if the info is not available.
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    /// Size of the received response body in bytes.
    ///
    /// Set to zero in case of responses coming from the cache (304). Set to -1 if the info is not available.
    ///
    /// The size of received response-headers is computed only from headers
    /// that are really received from the server. Additional headers appended
    /// by the browser are not included in this number,
    /// but they appear in the list of header objects.
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

impl Response {
    pub fn from_http_response_parts(
        parts: &http::response::Parts,
        payload: &[u8],
    ) -> Result<Self, OpaqueError> {
        let content = Content {
            size: payload.len() as i64,
            compression: None,
            mime_type: get_mime(&parts.headers),
            text: (!payload.is_empty()).then(|| match std::str::from_utf8(payload) {
                Ok(s) => s.to_owned(),
                Err(_) => ENGINE.encode(payload),
            }),
            encoding: parts
                .headers
                .typed_get::<crate::headers::ContentEncoding>()
                .and_then(|ce| ce.first_str().map(Into::into)),
            comment: None,
        };

        let redirect_url = parts
            .headers
            .typed_get::<Location>()
            .and_then(|h| h.encode_to_value().to_str().ok().map(ToOwned::to_owned));

        let cookies = parts
            .headers
            .typed_get::<SetCookie>()
            .map(|sc| {
                sc.iter_header_values()
                    .filter_map(|v| {
                        v.to_str().ok().and_then(|s| {
                            let raw = s.split(';').next()?;
                            parse_cookie_part(raw)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let headers_order = parts.extensions.get().cloned().unwrap_or_default();
        let header_map = Http1HeaderMap::from_parts(parts.headers.clone(), headers_order);

        let headers_size_ext = parts.extensions.get::<HeaderByteLength>();
        let headers_size = headers_size_ext.map(|v| v.0 as i64).unwrap_or(-1);

        Ok(Self {
            status: parts.status.as_u16(),
            status_text: parts.status.canonical_reason().map(Cow::Borrowed),
            http_version: parts.version.into(),
            cookies,
            headers: into_har_headers(header_map),
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// This object contains list of all cookies
///
/// (used in [Request] and [Response] objects).
pub struct Cookie {
    /// The name of the cookie.
    pub name: String,
    /// The cookie value.
    pub value: String,
    /// The path pertaining to the cookie.
    pub path: Option<String>,
    /// The host of the cookie.
    pub domain: Option<String>,
    /// Date and time stamp of the request start
    ///
    /// (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    pub expires: Option<DateTime<Utc>>,
    /// Set to true if the cookie is HTTP only, false otherwise.
    #[serde(rename = "httpOnly")]
    pub http_only: Option<bool>,
    /// True if the cookie was transmitted over ssl, false otherwise.
    pub secure: Option<bool>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Single HTTP Header.
pub struct Header {
    /// Name of header.
    pub name: String,
    /// Value of header.
    pub value: String,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object contains list of all parameters & values parsed from a query string,
/// if any (embedded in [Request] object).
pub struct QueryStringPair {
    /// Name of parameter.
    pub name: String,
    /// Value of parameter.
    pub value: String,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object describes posted data,
///
/// if any (embedded in [Request] object).
pub struct PostData {
    #[serde(with = "mime_serde", rename = "mimeType")]
    /// Mime type of posted data.
    pub mime_type: Option<Mime>,
    /// List of posted parameters
    ///
    /// (in case of URL encoded parameters).
    pub params: Option<Vec<PostParam>>,
    /// Plain text posted data
    pub text: Option<String>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostParam {
    pub name: String,
    pub value: Option<String>,
    #[serde(rename = "fileName")]
    pub file_name: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub comment: Option<String>,
}

rama_utils::macros::enums::enum_builder! {
    @String
    pub enum ContentEncoding {
        Base64 => "base64",
        Gzip => "gzip",
        Deflate => "deflate",
        Brotli => "br",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object describes details about response content
///
/// (embedded in <response> object).
///
/// Before setting the text field,
/// the HTTP response is decoded (decompressed & unchunked),
/// than trans-coded from its original character set into UTF-8. Additionally,
/// it can be encoded using e.g. base64. Ideally,
/// the application should be able to unencode a
/// base64 blob and get a byte-for-byte identical resource to what the browser operated on.
pub struct Content {
    /// Length of the returned content in bytes.
    ///
    /// Should be equal to response.bodySize if there is no compression
    /// and bigger when the content has been compressed.
    pub size: i64, // TODO: support
    /// Number of bytes saved.
    ///
    /// Leave out this field if the information is not available.
    pub compression: Option<i64>, // TODO: support
    #[serde(with = "mime_serde", rename = "mimetype")]
    /// MIME type of the response text
    ///
    /// (value of the Content-Type response header).
    ///
    /// The charset attribute of the MIME type is included
    /// (if available).
    pub mime_type: Option<Mime>,
    pub text: Option<String>,
    /// Response body sent from the server or loaded from the browser cache.
    ///
    /// This field is populated with textual content only.
    /// The text field is either HTTP decoded text or a encoded
    /// (e.g. "base64") representation of the response body.
    ///
    /// Leave out this field if the information is not available.
    pub encoding: Option<ContentEncoding>,
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// This objects contains info about a request coming from browser cache.
pub struct Cache {
    /// State of a cache entry before the request.
    ///
    /// Leave out this field if the information is not available.
    #[serde(rename = "beforeRequest")]
    pub before_request: Option<CacheState>,
    /// State of a cache entry after the request.
    ///
    /// Leave out this field if the information is not available.
    #[serde(rename = "afterRequest")]
    pub after_request: Option<CacheState>,
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
} // TODO: support this once we have cache support in rama, e.g. based on extension info

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheState {
    /// Date and time stamp of the request start
    ///
    /// (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    #[serde(with = "chrono_serializer")]
    /// Expiration time of the cache entry.
    pub expires: DateTime<Utc>,
    /// The last time the cache entry was opened.
    #[serde(rename = "lastAccess")]
    pub last_access: Option<String>,
    /// Etag
    #[serde(rename = "eTag")]
    pub e_tag: Option<String>,
    /// The number of times the cache entry has been opened.
    #[serde(rename = "hitCount")]
    pub hit_count: Option<i64>,
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// This object describes various phases within request-response round trip.
///
/// All times are specified in milliseconds.
pub struct Timings {
    /// Time spent in a queue waiting for a network connection.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub blocked: Option<u64>, // TODO
    /// DNS resolution time.
    ///
    /// The time required to resolve a host name.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub dns: Option<u64>, // TODO
    /// Time required to create TCP connection.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub connect: Option<u64>, // TODO
    /// Time required to send HTTP request to the server.
    pub send: u64, // TODO
    /// Waiting for a response from the server.
    pub wait: u64, // TODO
    /// Time required to read entire response from the server (or cache).
    pub receive: u64, // TODO
    /// Time required for SSL/TLS negotiation.
    ///
    /// If this field is defined then the time is also included in the connect field
    /// (to ensure backward compatibility with HAR 1.1).
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub ssl: Option<u64>, // TODO
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
}
