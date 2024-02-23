use std::ops::Deref;

use super::FromRequestParts;
use crate::http::{
    dep::http::request::Parts,
    header::{HeaderMap, FORWARDED},
    StatusCode,
};
use crate::service::Context;

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

/// Extractor that resolves the hostname of the request.
///
/// Hostname is resolved through the following, in order:
/// - `Forwarded` header
/// - `X-Forwarded-Host` header
/// - `Host` header
/// - request target / URI
///
/// Note that user agents can set `X-Forwarded-Host` and `Host` headers to arbitrary values so make
/// sure to validate them to avoid security issues.
#[derive(Debug, Clone)]
pub struct Host(pub String);

impl<S> FromRequestParts<S> for Host
where
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        if let Some(host) = parse_forwarded(&parts.headers) {
            return Ok(Host(host.to_owned()));
        }

        if let Some(host) = parts
            .headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Host(host.to_owned()));
        }

        if let Some(host) = parts
            .headers
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Host(host.to_owned()));
        }

        if let Some(host) = parts.uri.host() {
            return Ok(Host(host.to_owned()));
        }

        Err(StatusCode::BAD_REQUEST)
    }
}

#[allow(warnings)]
fn parse_forwarded(headers: &HeaderMap) -> Option<&str> {
    // if there are multiple `Forwarded` `HeaderMap::get` will return the first one
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;

    // get the first set of values
    let first_value = forwarded_values.split(',').nth(0)?;

    // find the value of the `host` field
    first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    })
}

impl Deref for Host {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::http::dep::http_body_util::BodyExt as _;
    use crate::http::service::web::WebService;
    use crate::http::{Body, HeaderName, Request};
    use crate::service::Service;

    async fn test_host_from_request(host: &str, headers: Vec<(HeaderName, &str)>) {
        let svc = WebService::default().get("/", |Host(host): Host| async move { host });

        let mut builder = Request::builder().method("GET").uri("http://example.com/");
        for (header, value) in headers {
            builder = builder.header(header, value);
        }
        let req = builder.body(Body::empty()).unwrap();

        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, host);
    }

    #[tokio::test]
    async fn host_header() {
        test_host_from_request(
            "some-domain:123",
            vec![(http::header::HOST, "some-domain:123")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_header() {
        test_host_from_request(
            "some-domain:456",
            vec![(
                HeaderName::try_from(X_FORWARDED_HOST_HEADER_KEY).unwrap(),
                "some-domain:456",
            )],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_precedence_over_host_header() {
        test_host_from_request(
            "some-domain:456",
            vec![
                (
                    HeaderName::try_from(X_FORWARDED_HOST_HEADER_KEY).unwrap(),
                    "some-domain:456",
                ),
                (http::header::HOST, "some-domain:123"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn uri_host() {
        test_host_from_request("example.com", vec![]).await;
    }

    #[test]
    fn forwarded_parsing() {
        // the basic case
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // is case insensitive
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // ipv6
        let headers = header_map(&[(FORWARDED, "host=\"[2001:db8:cafe::17]:4711\"")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "[2001:db8:cafe::17]:4711");

        // multiple values in one header
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60, host=127.0.0.1")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // multiple header values
        let headers = header_map(&[
            (FORWARDED, "host=192.0.2.60"),
            (FORWARDED, "host=127.0.0.1"),
        ]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");
    }

    fn header_map(values: &[(HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in values {
            headers.append(key, value.parse().unwrap());
        }
        headers
    }
}
