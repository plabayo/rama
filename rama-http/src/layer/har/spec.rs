// NOTE: spec can be found in ./spec.md

use std::fmt::Debug;
use std::str::FromStr;

use crate::layer::har::extensions::RequestComment;
use crate::proto::HeaderByteLength;
use crate::request::Parts as ReqParts;
use crate::response::Parts as RespParts;
use crate::service::web::extract::Query;

use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::ExtensionsMut;
use rama_core::telemetry::tracing;
use rama_http_headers::{
    ContentEncoding, ContentEncodingDirective, ContentType, Cookie as RamaCookie, HeaderMapExt,
    Location,
};
use rama_http_headers::{HeaderEncode, SetCookie};
use rama_http_types::mime::Mime;
use rama_http_types::proto::h1::Http1HeaderName;
use rama_http_types::proto::h1::ext::ReasonPhrase;
use rama_http_types::{HeaderMap, Version as RamaHttpVersion, proto::h1::Http1HeaderMap};
use rama_net::address::SocketAddress;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use chrono::{DateTime, Utc};
use rama_utils::str::arcstr::ArcStr;
use rama_utils::str::smol_str::{ToSmolStr, format_smolstr};
use rama_utils::str::{NonEmptyStr, non_empty_str};
use serde::{Deserialize, Serialize};

mod mime_serde {
    use rama_http_types::mime::Mime;
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

    match Query::<Vec<(ArcStr, ArcStr)>>::parse_query_str(query_str) {
        Ok(Query(v)) => v
            .into_iter()
            .map(|(name, value)| QueryStringPair {
                name,
                value,
                comment: None,
            })
            .collect(),
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
    let name = split.next()?.trim().into();
    let value = split.next()?.trim().into();
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
            name: name.as_str().into(),
            value: match value.to_str() {
                Ok(s) => s.into(),
                Err(_) => format_smolstr!("{value:x?}").into(),
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
    pub version: NonEmptyStr,
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
    pub comment: Option<ArcStr>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            version: non_empty_str!("1.2"),
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
    pub name: ArcStr,
    pub version: ArcStr,
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Browser {
    /// Name of the application/browser used to export the log.
    pub name: ArcStr,
    /// Version of the application/browser used to export the log.
    pub version: Option<ArcStr>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    /// Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    #[serde(with = "chrono_serializer", rename = "startedDateTime")]
    pub started_date_time: DateTime<Utc>,
    /// Unique identifier of a page within the [Log]. Entries use it to refer the parent page.
    pub id: ArcStr,
    /// Page title
    pub title: ArcStr,
    /// Detailed timing info about page load.
    #[serde(rename = "pageTimings")]
    pub page_timings: PageTimings,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
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
    pub on_content_load: Option<i64>,
    /// Page is loaded (onLoad event fired).
    ///
    /// Number of milliseconds since page load started (page.startedDateTime).
    /// Use -1 if the timing does not apply to the current request.
    #[serde(rename = "onLoad")]
    pub on_load: Option<i64>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object represents a single exportred request with its response and metadata.
pub struct Entry {
    /// Reference to the parent page.
    ///
    /// Leave out this field if the application does not support grouping by pages.
    #[serde(rename = "pageRef")]
    pub page_ref: Option<ArcStr>,
    /// Date and time stamp of the request start (ISO 8601 - YYYY-MM-DDThh:mm:ss.sTZD)
    #[serde(with = "chrono_serializer", rename = "startedDateTime")]
    pub started_date_time: DateTime<Utc>,
    /// Total elapsed time of the request in milliseconds.
    ///
    /// This is the sum of all timings available in the timings object (i.e. not including -1 values).
    pub time: i64,
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
    pub connection: Option<ArcStr>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object contains detailed info about performed request.
pub struct Request {
    /// Request method (GET, POST, ...).
    pub method: ArcStr,
    /// Absolute URL of the request (fragments are not included).
    pub url: ArcStr,
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
    pub comment: Option<ArcStr>,
}

impl TryFrom<Request> for crate::Request {
    type Error = BoxError;

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
            .uri(har_request.url.as_str());

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
            req.extensions_mut().insert(RequestComment(comment));
        }

        Ok(req)
    }
}

impl Request {
    pub fn from_http_request_parts(parts: &ReqParts, payload: &[u8]) -> Result<Self, BoxError> {
        let post_data = if !payload.is_empty() {
            let mime_type = get_mime(&parts.headers);
            let params = if mime_type
                .as_ref()
                .map(|m| m.subtype() == crate::mime::WWW_FORM_URLENCODED)
                .unwrap_or_default()
            {
                Some(serde_html_form::from_bytes(payload).context("decode form body payload")?)
            } else {
                None
            };

            let text = match std::str::from_utf8(payload) {
                Ok(s) => s.into(),
                Err(_) => ENGINE.encode(payload).into(),
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
            .map(|req_comment| req_comment.0.clone());

        let cookies = parts
            .headers
            .typed_get::<RamaCookie>()
            .map(|c| {
                c.iter()
                    .map(|(k, v)| Cookie {
                        name: k.into(),
                        value: v.into(),
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
            method: parts.method.to_smolstr().into(),
            url: parts.uri.to_string().into(),
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
    pub status_text: Option<ArcStr>,
    /// Response HTTP Version.
    #[serde(rename = "httpVersion")]
    pub http_version: HttpVersion,
    /// List of cookie objects.
    pub cookies: Vec<Cookie>,
    /// List of header objects.
    pub headers: Vec<Header>,
    /// Details about the response body.
    pub content: Content,
    /// Redirection target URL from the Location response header.
    #[serde(rename = "redirectUrl")]
    pub redirect_url: Option<ArcStr>,
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
    pub comment: Option<ArcStr>,
}

impl TryFrom<Response> for crate::Response {
    type Error = BoxError;

    fn try_from(har_response: Response) -> Result<Self, Self::Error> {
        let body = match har_response.content.text {
            Some(s) => match ENGINE.decode(&s) {
                Ok(v) => crate::Body::from(v),
                Err(_) => crate::Body::from(s),
            },
            None => crate::Body::empty(),
        };

        let mut orig_headers = Http1HeaderMap::with_capacity(har_response.headers.len());
        for header in har_response.headers {
            orig_headers.append(
                Http1HeaderName::from_str(&header.name).context("convert http header name")?,
                crate::HeaderValue::from_maybe_shared(header.value)
                    .context("convert http header value")?,
            );
        }
        let (headers, orig_headers) = orig_headers.into_parts();

        let builder = crate::Response::builder().status(
            crate::StatusCode::from_u16(har_response.status).context("convert HAR status code")?,
        );

        let builder = if let Ok(ver) = har_response.http_version.try_into() {
            builder.version(ver)
        } else {
            builder
        };

        let mut res = builder
            .body(body)
            .context("build http response from HAR data")?;

        *res.headers_mut() = headers;
        res.extensions_mut().insert(orig_headers);

        Ok(res)
    }
}

impl Response {
    pub fn from_http_response_parts(parts: &RespParts, payload: &[u8]) -> Result<Self, BoxError> {
        let content = Content {
            size: payload.len() as i64,
            compression: None,
            mime_type: get_mime(&parts.headers),
            text: (!payload.is_empty()).then(|| match std::str::from_utf8(payload) {
                Ok(s) => s.into(),
                Err(_) => ENGINE.encode(payload).into(),
            }),
            encoding: parts
                .headers
                .typed_get::<ContentEncoding>()
                .map(|ContentEncoding(ce)| ce.head),
            comment: None,
        };

        let redirect_url = parts
            .headers
            .typed_get::<Location>()
            .and_then(|h| h.encode_to_value())
            .and_then(|v| v.to_str().ok().map(Into::into));

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
            status_text: match parts.extensions.get::<ReasonPhrase>() {
                Some(reason) => Some(
                    String::from_utf8_lossy(reason.as_bytes())
                        .into_owned()
                        .into(),
                ),
                None => parts.status.canonical_reason().map(Into::into),
            },
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
    pub name: ArcStr,
    /// The cookie value.
    pub value: ArcStr,
    /// The path pertaining to the cookie.
    pub path: Option<ArcStr>,
    /// The host of the cookie.
    pub domain: Option<ArcStr>,
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
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Single HTTP Header.
pub struct Header {
    /// Name of header.
    pub name: ArcStr,
    /// Value of header.
    pub value: ArcStr,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object contains list of all parameters & values parsed from a query string,
/// if any (embedded in [Request] object).
pub struct QueryStringPair {
    /// Name of parameter.
    pub name: ArcStr,
    /// Value of parameter.
    pub value: ArcStr,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
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
    pub text: Option<ArcStr>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostParam {
    pub name: ArcStr,
    pub value: Option<ArcStr>,
    #[serde(rename = "fileName")]
    pub file_name: Option<ArcStr>,
    #[serde(rename = "contentType")]
    pub content_type: Option<ArcStr>,
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// This object describes details about response content
///
/// (embedded in `<response>` object).
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
    #[serde(with = "mime_serde", rename = "mimeType")]
    /// MIME type of the response text
    ///
    /// (value of the Content-Type response header).
    ///
    /// The charset attribute of the MIME type is included
    /// (if available).
    pub mime_type: Option<Mime>,
    pub text: Option<ArcStr>,
    /// Response body sent from the server or loaded from the browser cache.
    ///
    /// This field is populated with textual content only.
    /// The text field is either HTTP decoded text or a encoded
    /// (e.g. "base64") representation of the response body.
    ///
    /// Leave out this field if the information is not available.
    pub encoding: Option<ContentEncodingDirective>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
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
    pub comment: Option<ArcStr>,
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
    pub last_access: Option<ArcStr>,
    /// Etag
    #[serde(rename = "eTag")]
    pub e_tag: Option<ArcStr>,
    /// The number of times the cache entry has been opened.
    #[serde(rename = "hitCount")]
    pub hit_count: Option<i64>,
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// This object describes various phases within request-response round trip.
///
/// All times are specified in milliseconds.
pub struct Timings {
    /// Time spent in a queue waiting for a network connection.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub blocked: Option<i64>, // TODO
    /// DNS resolution time.
    ///
    /// The time required to resolve a host name.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub dns: Option<i64>, // TODO
    /// Time required to create TCP connection.
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub connect: Option<i64>, // TODO
    /// Time required to send HTTP request to the server.
    pub send: i64, // TODO
    /// Waiting for a response from the server.
    pub wait: i64, // TODO
    /// Time required to read entire response from the server (or cache).
    pub receive: i64, // TODO
    /// Time required for SSL/TLS negotiation.
    ///
    /// If this field is defined then the time is also included in the connect field
    /// (to ensure backward compatibility with HAR 1.1).
    ///
    /// Use -1 if the timing does not apply to the current request.
    pub ssl: Option<i64>, // TODO
    /// A comment provided by the user or the application.
    pub comment: Option<ArcStr>,
}

#[cfg(test)]
mod tests {
    use rama_http_types::body::util::BodyExt as _;

    use super::*;

    #[test]
    #[tracing_test::traced_test]
    fn test_load_har_entries() {
        let log_file: LogFile = serde_json::from_str(HAR_LOG_FILE_EXAMPLE).unwrap();

        assert_eq!(6, log_file.log.entries.len());

        let entry0 = &log_file.log.entries[0];
        assert_eq!("http://www.igvita.com/", entry0.request.url);
        assert_eq!("GET", entry0.request.method);
        assert!(matches!(entry0.request.http_version, HttpVersion::Http11));
        assert_eq!(0, entry0.request.query_string.len());

        let entry1 = &log_file.log.entries[1];
        assert_eq!(
            "http://fonts.googleapis.com/css?family=Open+Sans:400,600",
            entry1.request.url
        );
        assert_eq!(1, entry1.request.query_string.len());
        assert_eq!("family", entry1.request.query_string[0].name);
        assert_eq!("Open+Sans:400,600", entry1.request.query_string[0].value);

        let entry5 = &log_file.log.entries[5];
        assert_eq!(
            "http://1-ps.googleusercontent.com/beacon?org=50_1_cn&ets=load:93&ifr=0&hft=32&url=http%3A%2F%2Fwww.igvita.com%2F",
            entry5.request.url
        );
        assert_eq!(5, entry5.request.query_string.len());

        // HAR Request to rama Request
        let req0: crate::Request = entry0.request.clone().try_into().unwrap();
        let (req0_parts, req0_body) = req0.into_parts();
        drop(req0_body);

        assert_eq!(crate::Method::GET, req0_parts.method);
        assert_eq!(entry0.request.url, req0_parts.uri.to_string());
        assert_eq!(RamaHttpVersion::HTTP_11, req0_parts.version);

        let host = req0_parts
            .headers
            .get("Host")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!("www.igvita.com", host);

        // rama Request to HAR Request
        let req0_back = Request::from_http_request_parts(&req0_parts, &[]).unwrap();
        assert_eq!(entry0.request.method, req0_back.method);
        assert_eq!(entry0.request.url, req0_back.url);
        assert!(matches!(req0_back.http_version, HttpVersion::Http11));
        assert_eq!(0, req0_back.body_size);

        let ua = req0_back
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("User-Agent"))
            .map(|h| h.value.as_str())
            .unwrap();
        assert!(ua.contains("Chrome/21.0.1180.82"));

        // Query parsing sanity check when converting rama Request parts back into HAR Request
        let req5: crate::Request = entry5.request.clone().try_into().unwrap();
        let (req5_parts, req5_body) = req5.into_parts();
        drop(req5_body);

        let req5_back = Request::from_http_request_parts(&req5_parts, &[]).unwrap();
        assert_eq!(5, req5_back.query_string.len(), "req: {req5_back:?}");
        assert!(
            req5_back
                .query_string
                .iter()
                .any(|p| p.name == "org" && p.value == "50_1_cn"),
            "query string: {:?}",
            req5_back.query_string
        );
        assert!(
            req5_back
                .query_string
                .iter()
                .any(|p| p.name == "ets" && p.value == "load:93"),
            "query string: {:?}",
            req5_back.query_string
        );
        assert!(
            req5_back
                .query_string
                .iter()
                .any(|p| p.name == "url" && p.value == "http://www.igvita.com/"),
            "query string: {:?}",
            req5_back.query_string
        );

        // HAR Response to rama Response
        let har_res0 = entry0.response.clone().unwrap();
        let res0: crate::Response = har_res0.try_into().unwrap();
        let (res0_parts, res0_body) = res0.into_parts();
        drop(res0_body);

        assert_eq!(crate::StatusCode::OK, res0_parts.status);
        assert_eq!(RamaHttpVersion::HTTP_11, res0_parts.version);

        let ct = res0_parts
            .headers
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(ct.starts_with("text/html"));

        let ce = res0_parts
            .headers
            .get("Content-Encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_eq!("gzip", ce);

        // rama Response to HAR Response
        let res0_back = Response::from_http_response_parts(&res0_parts, &[]).unwrap();
        assert_eq!(200, res0_back.status);
        assert_eq!(Some("OK"), res0_back.status_text.as_deref());
        assert!(matches!(res0_back.http_version, HttpVersion::Http11));

        let mime = res0_back.content.mime_type.unwrap();
        assert_eq!("text/html; charset=utf-8", mime.as_ref());

        let encoding = res0_back.content.encoding.unwrap();
        assert_eq!(ContentEncodingDirective::Gzip, encoding);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_load_har_entries_payload_roundtrip() {
        let log_file: LogFile = serde_json::from_str(HAR_LOG_FILE_PAYLOAD_EXAMPLE).unwrap();
        assert_eq!(1, log_file.log.entries.len());

        let entry = &log_file.log.entries[0];

        // HAR -> rama request payload
        let req: crate::Request = entry.request.clone().try_into().unwrap();
        let (req_parts, req_body) = req.into_parts();

        let req_payload = vec![0u8, 255, 1, 2, 3];
        let req_bytes = req_body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(req_payload, req_bytes);

        // rama request parts + payload -> HAR request payload
        let har_req_back = Request::from_http_request_parts(&req_parts, &req_payload).unwrap();
        let post_data = har_req_back.post_data.unwrap();
        assert_eq!(
            Some(Mime::from_str("application/octet-stream").unwrap()),
            post_data.mime_type
        );
        assert_eq!(Some("AP8BAgM="), post_data.text.as_deref());
        assert_eq!(req_payload.len() as i64, har_req_back.body_size);

        // HAR -> rama response payload
        let har_res = entry.response.clone().unwrap();
        let res: crate::Response = har_res.try_into().unwrap();
        let (res_parts, res_body) = res.into_parts();

        let res_payload = vec![10u8, 20, 30, 255, 0];
        let res_bytes = res_body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(res_payload, res_bytes);

        // rama response parts + payload -> HAR response payload
        let har_res_back = Response::from_http_response_parts(&res_parts, &res_payload).unwrap();
        assert_eq!(res_payload.len() as i64, har_res_back.content.size);
        assert_eq!(
            Some(Mime::from_str("application/octet-stream").unwrap()),
            har_res_back.content.mime_type
        );
        assert_eq!(Some("ChQe/wA="), har_res_back.content.text.as_deref());
        assert_eq!(res_payload.len() as i64, har_res_back.body_size);
    }

    const HAR_LOG_FILE_EXAMPLE: &str = r##"{"log":{"version":"1.2","creator":{"name":"WebInspector","version":"537.1"},"pages":[{"startedDateTime":"2012-08-28T05:14:24.803Z","id":"page_1","title":"http://www.igvita.com/","pageTimings":{"onContentLoad":299,"onLoad":301}}],"entries":[{"startedDateTime":"2012-08-28T05:14:24.803Z","time":121,"request":{"method":"GET","url":"http://www.igvita.com/","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"www.igvita.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"Cache-Control","value":"max-age=0"}],"queryString":[],"cookies":[],"headersSize":678,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Tue, 28 Aug 2012 05:14:24 GMT"},{"name":"Via","value":"HTTP/1.1 GWA"},{"name":"Transfer-Encoding","value":"chunked"},{"name":"Content-Encoding","value":"gzip"},{"name":"X-XSS-Protection","value":"1; mode=block"},{"name":"X-UA-Compatible","value":"IE=Edge,chrome=1"},{"name":"X-Page-Speed","value":"50_1_cn"},{"name":"Server","value":"nginx/1.0.11"},{"name":"Vary","value":"Accept-Encoding"},{"name":"Content-Type","value":"text/html; charset=utf-8"},{"name":"Cache-Control","value":"max-age=0, no-cache"},{"name":"Expires","value":"Tue, 28 Aug 2012 05:14:24 GMT"}],"cookies":[],"content":{"size":9521,"mimeType":"text/html","compression":5896},"redirectURL":"","headersSize":379,"bodySize":3625},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":1,"wait":112,"receive":6,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.011Z","time":10,"request":{"method":"GET","url":"http://fonts.googleapis.com/css?family=Open+Sans:400,600","httpVersion":"HTTP/1.1","headers":[],"queryString":[{"name":"family","value":"Open+Sans:400,600"}],"cookies":[],"headersSize":71,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[],"cookies":[],"content":{"size":542,"mimeType":"text/css"},"redirectURL":"","headersSize":17,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":-1,"wait":-1,"receive":2,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.017Z","time":31,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/h/www.igvita.com/css/style.css.pagespeed.ce.LzjUDNB25e.css","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"If-Modified-Since","value":"Mon, 27 Aug 2012 15:28:34 GMT"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"text/css,*/*;q=0.1"},{"name":"Cache-Control","value":"max-age=0"},{"name":"If-None-Match","value":"W/0"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[],"cookies":[],"headersSize":539,"bodySize":0},"response":{"status":304,"statusText":"Not Modified","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Mon, 27 Aug 2012 06:01:49 GMT"},{"name":"Age","value":"83556"},{"name":"Server","value":"GFE/2.0"},{"name":"ETag","value":"W/0"},{"name":"Expires","value":"Tue, 27 Aug 2013 06:01:49 GMT"}],"cookies":[],"content":{"size":14679,"mimeType":"text/css"},"redirectURL":"","headersSize":146,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":1,"wait":24,"receive":2,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.021Z","time":30,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/h/www.igvita.com/js/libs/modernizr.84728.js.pagespeed.jm._DgXLhVY42.js","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"If-Modified-Since","value":"Sat, 25 Aug 2012 14:30:37 GMT"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"*/*"},{"name":"Cache-Control","value":"max-age=0"},{"name":"If-None-Match","value":"W/0"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[],"cookies":[],"headersSize":536,"bodySize":0},"response":{"status":304,"statusText":"Not Modified","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Sat, 25 Aug 2012 14:30:37 GMT"},{"name":"Age","value":"225828"},{"name":"Server","value":"GFE/2.0"},{"name":"ETag","value":"W/0"},{"name":"Expires","value":"Sun, 25 Aug 2013 14:30:37 GMT"}],"cookies":[],"content":{"size":11831,"mimeType":"text/javascript"},"redirectURL":"","headersSize":147,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":0,"send":1,"wait":27,"receive":1,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.103Z","time":0,"request":{"method":"GET","url":"http://www.google-analytics.com/ga.js","httpVersion":"HTTP/1.1","headers":[],"queryString":[],"cookies":[],"headersSize":52,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Mon, 27 Aug 2012 21:57:00 GMT"},{"name":"Content-Encoding","value":"gzip"},{"name":"X-Content-Type-Options","value":"nosniff, nosniff"},{"name":"Age","value":"23052"},{"name":"Last-Modified","value":"Thu, 16 Aug 2012 07:05:05 GMT"},{"name":"Server","value":"GFE/2.0"},{"name":"Vary","value":"Accept-Encoding"},{"name":"Content-Type","value":"text/javascript"},{"name":"Expires","value":"Tue, 28 Aug 2012 09:57:00 GMT"},{"name":"Cache-Control","value":"max-age=43200, public"},{"name":"Content-Length","value":"14804"}],"cookies":[],"content":{"size":36893,"mimeType":"text/javascript"},"redirectURL":"","headersSize":17,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":-1,"wait":-1,"receive":0,"ssl":-1},"pageref":"page_1"},{"startedDateTime":"2012-08-28T05:14:25.123Z","time":91,"request":{"method":"GET","url":"http://1-ps.googleusercontent.com/beacon?org=50_1_cn&ets=load:93&ifr=0&hft=32&url=http%3A%2F%2Fwww.igvita.com%2F","httpVersion":"HTTP/1.1","headers":[{"name":"Accept-Encoding","value":"gzip,deflate,sdch"},{"name":"Accept-Language","value":"en-US,en;q=0.8"},{"name":"Connection","value":"keep-alive"},{"name":"Accept-Charset","value":"ISO-8859-1,utf-8;q=0.7,*;q=0.3"},{"name":"Host","value":"1-ps.googleusercontent.com"},{"name":"User-Agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.82 Safari/537.1"},{"name":"Accept","value":"*/*"},{"name":"Referer","value":"http://www.igvita.com/"}],"queryString":[{"name":"org","value":"50_1_cn"},{"name":"ets","value":"load:93"},{"name":"ifr","value":"0"},{"name":"hft","value":"32"},{"name":"url","value":"http%3A%2F%2Fwww.igvita.com%2F"}],"cookies":[],"headersSize":448,"bodySize":0},"response":{"status":204,"statusText":"No Content","httpVersion":"HTTP/1.1","headers":[{"name":"Date","value":"Tue, 28 Aug 2012 05:14:25 GMT"},{"name":"Content-Length","value":"0"},{"name":"X-XSS-Protection","value":"1; mode=block"},{"name":"Server","value":"PagespeedRewriteProxy 0.1"},{"name":"Content-Type","value":"text/plain"},{"name":"Cache-Control","value":"no-cache"}],"cookies":[],"content":{"size":0,"mimeType":"text/plain","compression":0},"redirectURL":"","headersSize":202,"bodySize":0},"cache":{},"timings":{"blocked":0,"dns":-1,"connect":-1,"send":0,"wait":70,"receive":7,"ssl":-1},"pageref":"page_1"}]}}"##;

    const HAR_LOG_FILE_PAYLOAD_EXAMPLE: &str = r##"{"log":{"version":"1.2","creator":{"name":"rama-test","version":"0.0"},"entries":[{"startedDateTime":"2012-08-28T05:14:24.803Z","time":1,"request":{"method":"POST","url":"http://example.test/upload","httpVersion":"HTTP/1.1","headers":[{"name":"Host","value":"example.test"},{"name":"Content-Type","value":"application/octet-stream"}],"queryString":[],"cookies":[],"postData":{"mimeType":"application/octet-stream","text":"AP8BAgM="},"headersSize":-1,"bodySize":5},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Content-Type","value":"application/octet-stream"}],"cookies":[],"content":{"size":5,"mimeType":"application/octet-stream","text":"ChQe/wA="},"redirectURL":"","headersSize":-1,"bodySize":5},"cache":{},"timings":{"send":0,"wait":1,"receive":0}}]}}"##;
}
