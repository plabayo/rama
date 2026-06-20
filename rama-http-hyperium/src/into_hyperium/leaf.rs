//! Leaf-type conversions (method, status, version, uri, header map).

use rama_http_types::{HeaderMap, Method, StatusCode, Uri, Version};

use super::TryIntoHyperiumHttp;

impl TryIntoHyperiumHttp for Method {
    type Output = http::Method;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Method, http::Error> {
        // Both are byte-identical forks; round-trip through the method bytes.
        Ok(http::Method::from_bytes(self.as_str().as_bytes())?)
    }
}

impl TryIntoHyperiumHttp for StatusCode {
    type Output = http::StatusCode;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::StatusCode, http::Error> {
        Ok(http::StatusCode::from_u16(self.as_u16())?)
    }
}

impl TryIntoHyperiumHttp for Version {
    type Output = http::Version;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Version, http::Error> {
        // Total: rama and hyperium expose the same five versions.
        Ok(match self {
            Self::HTTP_09 => http::Version::HTTP_09,
            Self::HTTP_10 => http::Version::HTTP_10,
            Self::HTTP_11 => http::Version::HTTP_11,
            Self::HTTP_2 => http::Version::HTTP_2,
            Self::HTTP_3 => http::Version::HTTP_3,
        })
    }
}

impl TryIntoHyperiumHttp for Uri {
    type Output = http::Uri;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::Uri, http::Error> {
        // The HTTP asterisk-form has no `http::Uri` representation beyond `*`.
        if self.is_asterisk() {
            return Ok(http::Uri::from_static("*"));
        }
        Ok(http::Uri::try_from(self.as_str().as_ref())?)
    }
}

impl TryIntoHyperiumHttp for HeaderMap {
    type Output = http::HeaderMap;
    type Error = http::Error;
    fn try_into_hyperium_http(self) -> Result<http::HeaderMap, http::Error> {
        // Both are byte-identical forks; round-trip each name/value through its
        // bytes, preserving multi-value ordering and the sensitivity flag.
        let mut out = http::HeaderMap::with_capacity(self.len());
        let mut last: Option<http::header::HeaderName> = None;
        for (name, hv) in self {
            let mut out_hv = http::header::HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            match name {
                Some(name) => {
                    let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())?;
                    out.append(name.clone(), out_hv);
                    last = Some(name);
                }
                // `None` name repeats the previous name (multi-value).
                None => {
                    if let Some(name) = &last {
                        out.append(name.clone(), out_hv);
                    }
                }
            }
        }
        Ok(out)
    }
}
