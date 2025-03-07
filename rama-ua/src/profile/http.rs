use rama_http_types::{
    HeaderName,
    proto::{h1::Http1HeaderMap, h2::PseudoHeader},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub static CUSTOM_HEADER_MARKER: HeaderName =
    HeaderName::from_static("x-rama-custom-header-marker");

#[derive(Debug, Clone)]
pub struct HttpProfile {
    pub h1: Arc<Http1Profile>,
    pub h2: Arc<Http2Profile>,
}

impl<'de> Deserialize<'de> for HttpProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = HttpProfileDeserialize::deserialize(deserializer)?;
        Ok(Self {
            h1: Arc::new(input.h1),
            h2: Arc::new(input.h2),
        })
    }
}

impl Serialize for HttpProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        HttpProfileSerialize {
            h1: self.h1.as_ref(),
            h2: self.h2.as_ref(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
struct HttpProfileSerialize<'a> {
    pub h1: &'a Http1Profile,
    pub h2: &'a Http2Profile,
}

#[derive(Debug, Deserialize)]
struct HttpProfileDeserialize {
    pub h1: Http1Profile,
    pub h2: Http2Profile,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpHeadersProfile {
    pub navigate: Http1HeaderMap,
    pub fetch: Option<Http1HeaderMap>,
    pub xhr: Option<Http1HeaderMap>,
    pub form: Option<Http1HeaderMap>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Http1Profile {
    pub headers: HttpHeadersProfile,
    pub settings: Http1Settings,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Http1Settings {
    pub title_case_headers: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Http2Profile {
    pub headers: HttpHeadersProfile,
    pub settings: Http2Settings,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Http2Settings {
    pub http_pseudo_headers: Option<Vec<PseudoHeader>>,
}
