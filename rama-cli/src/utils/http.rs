use rama::{
    error::{BoxError, ErrorExt as _},
    http,
    utils::str::smol_str::StrExt,
};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    Auto,
    H1,
    H2,
}

impl From<HttpVersion> for Option<http::Version> {
    fn from(value: HttpVersion) -> Self {
        match value {
            HttpVersion::Auto => None,
            HttpVersion::H1 => Some(http::Version::HTTP_11),
            HttpVersion::H2 => Some(http::Version::HTTP_2),
        }
    }
}

impl FromStr for HttpVersion {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase_smolstr().as_str() {
            "" | "auto" => Self::Auto,
            "h1" | "http1" | "http/1" | "http/1.0" | "http/1.1" => Self::H1,
            "h2" | "http2" | "http/2" | "http/2.0" => Self::H2,
            version => {
                return Err(BoxError::from("unsupported http version")
                    .context_str_field("version", version));
            }
        })
    }
}
