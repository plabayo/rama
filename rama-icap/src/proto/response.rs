use rama_http_types::HeaderMap;
use bytes::Bytes;
use crate::proto::StatusCode;

#[derive(Debug)]
pub struct Response {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) http_request: Option<Vec<u8>>,
    pub(crate) http_response: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Body {
    pub(crate) content: Bytes,
    pub(crate) is_preview: bool,
}

impl Response {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: None,
            http_request: None,
            http_response: None,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }

    pub fn http_request(&self) -> Option<&[u8]> {
        self.http_request.as_deref()
    }

    pub fn http_response(&self) -> Option<&[u8]> {
        self.http_response.as_deref()
    }

    pub fn is_preview(&self) -> bool {
        self.body.as_ref().map_or(false, |b| b.is_preview)
    }

    pub fn into_parts(self) -> (StatusCode, HeaderMap, Option<Body>) {
        (self.status, self.headers, self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rama_http_types::header::HeaderValue;

    #[test]
    fn test_response_creation() {
        let resp = Response::new(StatusCode::OK);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().is_empty());
        assert!(resp.body().is_none());
        assert!(resp.http_request().is_none());
        assert!(resp.http_response().is_none());
    }

    #[test]
    fn test_response_headers() {
        let mut resp = Response::new(StatusCode::OK);
        resp.headers.insert(
            "X-Custom".parse().unwrap(),
            HeaderValue::from_static("value1"),
        );
        resp.headers.insert(
            "X-Another".parse().unwrap(),
            HeaderValue::from_static("value2"),
        );

        assert!(resp.headers().contains_key("x-custom"));
        assert!(resp.headers().contains_key("x-another"));
        assert_eq!(
            resp.headers().get("x-custom").unwrap(),
            &HeaderValue::from_static("value1")
        );
    }

    #[test]
    fn test_response_body() {
        let mut resp = Response::new(StatusCode::OK);
        resp.body = Some(Body {
            content: Bytes::from("Hello, World!"),
            is_preview: false,
        });

        assert!(resp.body().is_some());
        assert_eq!(resp.body().unwrap().content, "Hello, World!");
        assert!(!resp.is_preview());

        resp.body = Some(Body {
            content: Bytes::from("Preview"),
            is_preview: true,
        });

        assert!(resp.is_preview());
    }

    #[test]
    fn test_response_http_content() {
        let mut resp = Response::new(StatusCode::OK);
        
        let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        resp.http_request = Some(http_req.clone());
        assert_eq!(resp.http_request().unwrap(), http_req.as_slice());

        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello".to_vec();
        resp.http_response = Some(http_resp.clone());
        assert_eq!(resp.http_response().unwrap(), http_resp.as_slice());
    }

    #[test]
    fn test_response_into_parts() {
        let mut resp = Response::new(StatusCode::OK);
        resp.headers.insert(
            "X-Custom".parse().unwrap(),
            HeaderValue::from_static("value1"),
        );
        resp.body = Some(Body {
            content: Bytes::from("Hello"),
            is_preview: false,
        });

        let (status, headers, body) = resp.into_parts();
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key("x-custom"));
        assert_eq!(body.unwrap().content, "Hello");
    }
}
