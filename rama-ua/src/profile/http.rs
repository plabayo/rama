use rama_http_types::proto::{h1::Http1HeaderMap, h2::PseudoHeader};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpProfile {
    pub headers: HttpHeadersProfile,
    pub h1: Http1Profile,
    pub h2: Http2Profile,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpHeadersProfile {
    pub navigate: Http1HeaderMap,
    pub fetch: Http1HeaderMap,
    pub xhr: Http1HeaderMap,
    pub form: Http1HeaderMap,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http1Profile {
    pub title_case_headers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http2Profile {
    pub http_pseudo_headers: Vec<PseudoHeader>,
}
