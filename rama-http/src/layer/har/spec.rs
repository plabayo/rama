use serde::{Deserialize, Serialize};

macro_rules! har_data {
    ($name:ident, { $($field:tt)* }) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
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
