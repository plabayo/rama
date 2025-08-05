use std::fmt::{Debug, Write};

use crate::dep::core::bytes::Bytes;
use crate::dep::http::request::Parts as ReqParts;
use crate::service::web::extract::Query;

use mime::Mime;

use rama_core::telemetry::tracing;
use rama_error::OpaqueError;
use rama_http_types::{
    HeaderMap, HeaderName, Request as RamaRequest, Response as RamaResponse,
    Version as HttpVersion,
    dep::{http_body::Body as RamaBody, http_body_util::BodyExt},
    header::{CONTENT_TYPE, LOCATION},
    proto::h1::Http1HeaderMap,
};
use serde::{Deserialize, Serialize};

macro_rules! har_data {
    ($name:ident, { $($field:tt)* }) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            $($field)*
        }
    };
}

macro_rules! har_data_with_serde {
    ($name:ident, { $($field:tt)* }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $name {
            $($field)*
        }
    };
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
            tracing::trace!("Failure to parse query string: {err:?}");
            vec![]
        }
    }
}

fn get_mime(headers: HeaderMap) -> Mime {
    headers
        .get(CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .and_then(|content_type| content_type.parse::<mime::Mime>().ok())
        .unwrap()
}

fn get_header(headers: HeaderMap, header_name: HeaderName) -> String {
    if headers.contains_key(&header_name) {
        headers
            .get(header_name)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    } else {
        // TODO should we set a default?
        String::new()
    }
}

fn into_har_headers(headers: HeaderMap, version: HttpVersion) -> Vec<Header> {
    let header_map = Http1HeaderMap::new(headers, None);

    header_map
        .into_iter()
        .map(|(name, value)| match version {
            HttpVersion::HTTP_2 | HttpVersion::HTTP_3 => Header {
                name: name.header_name().as_str().to_owned(),
                value: value.to_str().unwrap_or_default().to_owned(),
                comment: None,
            },
            _ => Header {
                name: name.to_string(),
                value: value.to_str().unwrap_or_default().to_owned(),
                comment: None,
            },
        })
        .collect()
}

har_data!(Log, {
    pub version: String,
    pub creator: Creator,
    pub browser: Option<Browser>,
    pub pages: Vec<Page>,
    pub entries: Vec<Entry>,
    pub comment: Option<String>,
});

impl Default for Log {
    fn default() -> Self {
        Self {
            version: "1.0".to_owned(),
            creator: Creator {
                name: "har generator".to_owned(),
                version: "1.0".to_owned(),
                comment: None,
            },
            browser: None,
            pages: vec![],
            entries: vec![],
            comment: None,
        }
    }
}

har_data!(Creator, {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
});

har_data!(Browser, {
    pub name: String,
    pub version: String,
    pub comment: Option<String>,
});

har_data!(Page, {
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    pub page_timings: PageTimings,
    pub comment: Option<String>,
});

har_data!(PageTimings, {
    pub on_content_load: Option<f64>,
    pub on_load: Option<f64>,
    pub comment: Option<String>,
});

har_data!(Entry, {
    pub pageref: Option<String>,
    pub started_date_time: String,
    /// milliseconds
    pub time: u64,
    pub request: Request,
    /// Different from spec - but a response may not arrive.
    pub response: Option<Response>,
    pub cache: Cache,
    pub timings: Timings,
    pub server_ip_address: Option<String>,
    pub connection: Option<String>,
    pub comment: Option<String>,
});

impl Entry {
    pub fn new(
        started_date_time: String,
        time: u64,
        request: Request,
        response: Option<Response>,
        cache: Cache,
        timings: Timings,
    ) -> Self {
        Self {
            pageref: None,
            started_date_time,
            time,
            request,
            response,
            cache,
            timings,
            server_ip_address: None,
            connection: None,
            comment: None,
        }
    }
}
har_data!(Request, {
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
});

impl Request {
    /// Compute the total number of bytes from the start of the HTTP request
    /// until (and including) the double CRLF before the body.
    pub fn headers_size_from_request<B>(req: &RamaRequest<B>) -> i64
    where
        B: RamaBody<Data = Bytes> + Clone + Send + 'static,
    {
        let mut raw = String::new();

        // Write the request line: METHOD URI VERSION\r\n
        let method = req.method();
        let uri = req.uri();
        let version = match req.version() {
            HttpVersion::HTTP_11 => "HTTP/1.1",
            HttpVersion::HTTP_10 => "HTTP/1.0",
            HttpVersion::HTTP_2 => "HTTP/2.0",
            HttpVersion::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        };
        writeln!(raw, "{method} {uri} {version}\r").unwrap();

        // Format: Header-Name: value\r\n
        for (name, value) in req.headers() {
            let value_str = value.to_str().unwrap_or_default();
            writeln!(raw, "{name}: {value_str}\r").unwrap();
        }

        // Final CRLF (the empty line between headers and body)
        raw.push_str("\r\n");

        raw.len() as i64
    }

    pub async fn from_rama_request<B>(req: &RamaRequest<B>) -> Result<Self, OpaqueError>
    where
        B: RamaBody<Data = Bytes> + Clone + Send + 'static,
    {
        let (parts, body) = req.clone().into_parts();

        let body_bytes = body
            .collect()
            .await
            .map_err(|_| OpaqueError::from_display("Failed to read body"))?
            .to_bytes();

        let http_version = into_string_version(parts.version)?;

        let post_data = if parts.method == "POST" {
            Some(PostData {
                mime_type: get_mime(req.headers().clone()),
                // TODO params
                params: None,
                text: Some(String::from_utf8_lossy(&body_bytes).to_string()),
                comment: None,
            })
        } else {
            None
        };

        Ok(Self {
            method: parts.method.to_string(),
            url: parts.uri.to_string(),
            http_version,
            cookies: vec![],
            headers: into_har_headers(parts.headers.clone(), parts.version),
            query_string: into_query_string(&parts),
            post_data,
            headers_size: Self::headers_size_from_request(req),
            body_size: body_bytes.len() as i64,
            comment: None,
        })
    }
}

har_data!(Response, {
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
    pub redirect_url: String,
    /// Total number of bytes from the start of the HTTP response message until (and including) the double CRLF before the body. Set to -1 if the info is not available.
    pub headers_size: i64,
    /// Size of the received response body in bytes. Set to zero in case of responses coming from the cache (304). Set to -1 if the info is not available.
    pub body_size: i64,
    /// A comment provided by the user or the application.
    pub comment: Option<String>,
});

impl Response {
    pub async fn from_rama_response<B>(resp: &RamaResponse<B>) -> Result<Self, OpaqueError>
    where
        B: RamaBody<Data = Bytes> + Clone + Send + 'static,
    {
        let (parts, body) = resp.clone().into_parts();

        let body_bytes = body
            .collect()
            .await
            .map_err(|_| OpaqueError::from_display("Failed to read body"))?
            .to_bytes();

        let http_version = into_string_version(parts.version)?;

        let content = Content {
            size: body_bytes.len() as i64,
            compression: None,
            mime_type: get_mime(resp.headers().clone()),
            text: Some(String::from_utf8_lossy(&body_bytes).to_string()),
            encoding: None,
            comment: None,
        };

        Ok(Self {
            status: 0,
            status_text: String::new(),
            http_version,
            cookies: vec![],
            headers: into_har_headers(parts.headers.clone(), parts.version),
            content,
            redirect_url: get_header(parts.headers.clone(), LOCATION),
            headers_size: -1,
            body_size: body_bytes.len() as i64,
            comment: None,
        })
    }
}

// TODO: https://github.com/plabayo/rama/issues/44
// For now this will have to be manually parsed. Needs an http-cookie logic
har_data!(Cookie, {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub expires: Option<String>,
    pub http_only: Option<bool>,
    pub secure: Option<bool>,
    pub comment: Option<String>,
});

har_data!(Header, {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
});

har_data_with_serde!(QueryStringPair, {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
});

har_data!(PostData, {
    pub mime_type: Mime,
    pub params: Option<Vec<PostParam>>,
    pub text: Option<String>,
    pub comment: Option<String>,
});

har_data!(PostParam, {
    pub name: String,
    pub value: Option<String>,
    pub file_name: Option<String>,
    pub content_type: Option<String>,
    pub comment: Option<String>,
});

har_data!(Content, {
    pub size: i64,
    pub compression: Option<i64>,
    pub mime_type: Mime,
    pub text: Option<String>,
    /// Encoding used for response text field e.g "base64".
    /// Leave out this field if the text field is HTTP decoded (decompressed & unchunked),
    /// than trans-coded from its original character set into UTF-8.
    pub encoding: Option<String>,
    pub comment: Option<String>,
});

har_data!(Cache, {
    pub before_request: Option<CacheState>,
    pub after_request: Option<CacheState>,
    pub comment: Option<String>,
});

har_data!(CacheState, {
    pub expires: Option<String>,
    pub last_access: Option<String>,
    pub e_tag: Option<String>,
    pub hit_count: Option<i64>,
    pub comment: Option<String>,
});

har_data!(Timings, {
    pub blocked: Option<u64>,
    pub dns: Option<u64>,
    pub connect: Option<u64>,
    pub send: u64,
    pub wait: u64,
    pub receive: u64,
    pub ssl: Option<u64>,
    pub comment: Option<String>,
});
