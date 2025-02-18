use rama_http_types::HeaderMap;
use url::Url;
use bytes::Bytes;
use crate::Method;
use crate::proto::Encapsulated;

#[derive(Debug)]
pub struct Request {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) encapsulated: Encapsulated,
}

#[derive(Debug)]
pub struct Body {
    pub(crate) content: Bytes,
    pub(crate) preview: Option<Bytes>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
            http_request: None,
            http_response: None,
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) -> &mut Self {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            if let Ok(value) = HeaderValue::from_str(value) {
                self.headers.insert(name, value);
            }
        }
        self
    }

    pub fn set_body(&mut self, content: impl Into<Bytes>) -> &mut Self {
        self.body = Some(Body {
            content: content.into(),
            preview: None,
        });
        self
    }

    pub fn set_preview(&mut self, preview: impl Into<Bytes>) -> &mut Self {
        if let Some(body) = &mut self.body {
            body.preview = Some(preview.into());
        }
        self
    }

    pub fn set_http_request(&mut self, request: Vec<u8>) -> &mut Self {
        self.http_request = Some(request);
        self
    }

    pub fn set_http_response(&mut self, response: Vec<u8>) -> &mut Self {
        self.http_response = Some(response);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rama_http_types::HeaderValue;

    #[test]
    fn test_request_creation() {
        let url = Url::parse("icap://localhost:1344/reqmod").unwrap();
        
        // Test OPTIONS request
        let req = Request::new(Method::Options, url.clone());
        assert_eq!(req.method, Method::Options);
        assert_eq!(req.url, url);
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert!(req.http_request.is_none());
        assert!(req.http_response.is_none());

        // Test REQMOD request
        let mut req = Request::new(Method::ReqMod, url.clone());
        let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        req.set_http_request(http_req.clone());
        assert_eq!(req.method, Method::ReqMod);
        assert_eq!(req.http_request.unwrap(), http_req);

        // Test RESPMOD request
        let mut req = Request::new(Method::RespMod, url);
        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello".to_vec();
        req.set_http_response(http_resp.clone());
        assert_eq!(req.method, Method::RespMod);
        assert_eq!(req.http_response.unwrap(), http_resp);
    }

    #[test]
    fn test_request_headers() {
        let url = Url::parse("icap://localhost:1344/reqmod").unwrap();
        let mut req = Request::new(Method::ReqMod, url);

        req.set_header("X-Custom", "value1");
        req.set_header("X-Another", "value2");

        assert!(req.headers.contains_key("x-custom"));
        assert!(req.headers.contains_key("x-another"));
        assert_eq!(
            req.headers.get("x-custom").unwrap(),
            &HeaderValue::from_static("value1")
        );
    }

    #[test]
    fn test_request_body() {
        let url = Url::parse("icap://localhost:1344/reqmod").unwrap();
        let mut req = Request::new(Method::ReqMod, url);

        let content = Bytes::from("Hello, World!");
        req.set_body(content.clone());

        assert!(req.body.is_some());
        assert_eq!(req.body.as_ref().unwrap().content, content);
        assert!(req.body.as_ref().unwrap().preview.is_none());

        let preview = Bytes::from("Hello");
        req.set_preview(preview.clone());

        assert_eq!(req.body.as_ref().unwrap().preview.as_ref().unwrap(), &preview);
    }

    #[test]
    fn test_request_chaining() {
        let url = Url::parse("icap://localhost:1344/reqmod").unwrap();
        let mut req = Request::new(Method::ReqMod, url);

        req.set_header("X-Custom", "value1")
           .set_header("X-Another", "value2")
           .set_body(Bytes::from("Hello"))
           .set_preview(Bytes::from("He"));

        assert!(req.headers.contains_key("x-custom"));
        assert!(req.body.is_some());
        assert!(req.body.as_ref().unwrap().preview.is_some());
    }
}
