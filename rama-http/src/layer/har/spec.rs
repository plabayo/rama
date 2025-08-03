use crate::dep::core::bytes::Bytes;
use crate::dep::http::request::Parts as ReqParts;
use crate::service::web::extract::Query;
use rama_error::OpaqueError;
use rama_http_types::dep::http_body;
use rama_http_types::proto::h1::Http1HeaderMap;
use rama_http_types::{Request as RamaRequest, Version as HttpVersion};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

macro_rules! har_data {
    ($name:ident, { $($field:tt)* }) => {
        #[derive(Debug, Default, Clone, Serialize, Deserialize)]
        pub struct $name {
            $($field)*
        }
    };
}

har_data!(Log, {
    pub version: String,
    pub creator: Creator,
    pub browser: Option<Browser>,
    #[serde(default)]
    pub pages: Vec<Page>,
    pub entries: Vec<Entry>,
    pub comment: Option<String>,
});

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
    pub time: f64,
    pub request: Request,
    pub response: Response,
    pub cache: Cache,
    pub timings: Timings,
    pub server_ip_address: Option<String>,
    pub connection: Option<String>,
    pub comment: Option<String>,
});

har_data!(Request, {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub query_string: Vec<QueryString>,
    pub post_data: Option<PostData>,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
});

impl Request {
    pub fn from_rama_request<B>(req: &RamaRequest<B>) -> Result<Self, OpaqueError>
    where
        B: http_body::Body<Data = Bytes> + Clone + Send + 'static,
    {
        let (parts, _body) = req.clone().into_parts();
        // body could be used for computing body_size?

        let http_version = Self::into_string_version(parts.version)?;

        Ok(Self {
            method: parts.method.to_string(),
            url: parts.uri.to_string(),
            http_version,
            cookies: vec![],
            headers: Self::into_har_headers(&parts),
            query_string: Self::into_har_query_string(&parts),
            post_data: None,
            headers_size: 0,
            body_size: -1,
            comment: None,
        })
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

    fn into_har_query_string(parts: &ReqParts) -> Vec<QueryString> {
        let query_str = parts.uri.query().unwrap_or("");
        let query = Query::<HashMap<String, String>>::parse_query_str(query_str);

        match query {
            Ok(q) => q.0.into_iter().map(Into::into).collect(),
            Err(_) => vec![]
        }
    }

    fn into_har_headers(parts: &ReqParts) -> Vec<Header> {
        let header_map = Http1HeaderMap::new(parts.headers.clone(), None);

        header_map
            .into_iter()
            .map(|(name, value)| match parts.version {
                rama_http_types::Version::HTTP_2 | rama_http_types::Version::HTTP_3 => Header {
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
}

har_data!(Response, {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub content: Content,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
    pub comment: Option<String>,
});

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

har_data!(QueryString, {
    pub name: String,
    pub value: String,
    pub comment: Option<String>,
});

impl From<(String, String)> for QueryString {
    fn from((name, value): (String, String)) -> Self {
        Self {
            name,
            value,
            comment: None,
        }
    }
}

har_data!(PostData, {
    pub mime_type: String,
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
    pub mime_type: String,
    pub text: Option<String>,
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
    pub blocked: Option<f64>,
    pub dns: Option<f64>,
    pub connect: Option<f64>,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    pub ssl: Option<f64>,
    pub comment: Option<String>,
});
