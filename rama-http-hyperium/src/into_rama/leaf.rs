//! Leaf-type conversions (method, status, version, uri, header map).

use rama_http_types::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};

use super::TryIntoRamaHttp;

impl TryIntoRamaHttp for http::Method {
    type Output = Method;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Method, rama_http_types::Error> {
        Ok(Method::from_bytes(self.as_str().as_bytes())?)
    }
}

impl TryIntoRamaHttp for http::StatusCode {
    type Output = StatusCode;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<StatusCode, rama_http_types::Error> {
        Ok(StatusCode::from_u16(self.as_u16())?)
    }
}

impl TryIntoRamaHttp for http::Version {
    type Output = Version;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Version, rama_http_types::Error> {
        Ok(match self {
            Self::HTTP_09 => Version::HTTP_09,
            Self::HTTP_10 => Version::HTTP_10,
            Self::HTTP_2 => Version::HTTP_2,
            Self::HTTP_3 => Version::HTTP_3,
            // `http::Version` exposes no other variant; defensive for its
            // `#[non_exhaustive]` future-proofing.
            _ => Version::HTTP_11,
        })
    }
}

impl TryIntoRamaHttp for http::Uri {
    type Output = Uri;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<Uri, rama_http_types::Error> {
        if self == Self::from_static("*") {
            return Ok(Uri::from_static("*"));
        }
        Ok(Uri::parse(self.to_string().as_str())?)
    }
}

impl TryIntoRamaHttp for http::HeaderMap {
    type Output = HeaderMap;
    type Error = rama_http_types::Error;
    fn try_into_rama_http(self) -> Result<HeaderMap, rama_http_types::Error> {
        let mut out = HeaderMap::with_capacity(self.len());
        let mut last: Option<HeaderName> = None;
        for (name, hv) in self {
            let mut out_hv = HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            match name {
                Some(name) => {
                    let name = HeaderName::from_bytes(name.as_str().as_bytes())?;
                    out.append(name.clone(), out_hv);
                    last = Some(name);
                }
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

impl TryIntoRamaHttp for &http::HeaderMap {
    type Output = HeaderMap;
    type Error = rama_http_types::Error;
    /// Borrowing variant, for boundaries that only hand out a `&http::HeaderMap`
    /// (e.g. a `multer` multipart field). Iterating by reference already repeats
    /// the name per value, so no multi-value bookkeeping is needed.
    fn try_into_rama_http(self) -> Result<HeaderMap, rama_http_types::Error> {
        let mut out = HeaderMap::with_capacity(self.len());
        for (name, hv) in self {
            let name = HeaderName::from_bytes(name.as_str().as_bytes())?;
            let mut out_hv = HeaderValue::from_bytes(hv.as_bytes())?;
            out_hv.set_sensitive(hv.is_sensitive());
            out.append(name, out_hv);
        }
        Ok(out)
    }
}
