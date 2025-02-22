use rama_http_types::{
    HeaderName,
    proto::{h1::Http1HeaderMap, h2::PseudoHeader},
};
use serde::{Deserialize, Serialize};

pub static CUSTOM_HEADER_MARKER: HeaderName =
    HeaderName::from_static("x-rama-custom-header-marker");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpProfile {
    pub h1: Http1Profile,
    pub h2: Http2Profile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpHeadersProfile {
    pub navigate: Http1HeaderMap,
    pub fetch: Option<Http1HeaderMap>,
    pub xhr: Option<Http1HeaderMap>,
    pub form: Option<Http1HeaderMap>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http1Profile {
    pub headers: HttpHeadersProfile,
    pub title_case_headers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Profile {
    pub headers: HttpHeadersProfile,
    pub http_pseudo_headers: Vec<PseudoHeader>,
}
