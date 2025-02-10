//! ICAP (Internet Content Adaptation Protocol) implementation according to RFC 3507.
//! 
//! This module provides support for the ICAP protocol, which allows HTTP messages to be 
//! adapted/transformed by an ICAP server.

pub mod proto;
pub mod parser;

use std::collections::HashMap;
use thiserror::Error;
use rama_http_types::{header::{InvalidHeaderValue, InvalidHeaderName, HeaderName}, HeaderMap};
use bytes::Bytes;

/// Default ICAP port as specified in RFC 3507
pub const DEFAULT_ICAP_PORT: u16 = 1344;

/// Error types that can occur in ICAP operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("Invalid HTTP header name: {0}")]
    InvalidHeaderName(#[from] InvalidHeaderName),
    #[error("Invalid ICAP version: {0}")]
    InvalidVersion(String),
    #[error("Invalid ICAP method: {0}")]
    InvalidMethod(String),
    #[error("Invalid status code")]
    InvalidStatus,
    #[error("Invalid ICAP message format: {0}")]
    InvalidFormat(String),
    #[error("Invalid encapsulated header: {0}")]
    InvalidEncapsulated(String),
    #[error("Missing required header: {0}")]
    MissingHeader(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Result type for ICAP operations
pub type Result<T> = std::result::Result<T, Error>;

/// ICAP version string
pub const ICAP_VERSION: &str = "ICAP/1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Options,
    ReqMod,
    RespMod,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Options => "OPTIONS",
            Method::ReqMod => "REQMOD",
            Method::RespMod => "RESPMOD",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Options => write!(f, "OPTIONS"),
            Method::ReqMod => write!(f, "REQMOD"),
            Method::RespMod => write!(f, "RESPMOD"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1_0 = 0,
    V1_1 = 1,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1_0 => "ICAP/1.0",
            Version::V1_1 => "ICAP/1.1",
        }
    }
    
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Version::V1_0),
            1 => Some(Version::V1_1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: HeaderMap,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: 200,
            reason: String::from("OK"),
            headers: HeaderMap::new(),
        }
    }
}

impl Response {
    pub fn new(headers: HeaderMap) -> Response {
        Response {
            status: 200,
            reason: String::from("OK"),
            headers,
        }
    }

    pub fn len(&self) -> usize {
        let mut len = 0;
        for (name, value) in self.headers.iter() {
            len += name.as_str().len() + 2 + value.len() + 2; // name: value\r\n
        }
        len + 2 // final \r\n
    }
}

#[derive(Debug, Clone)]
pub enum Encapsulated {
    NullBody,
    Options {
        body: Option<Bytes>,
    },
    RequestOnly {
        header: Option<Request>,
        body: Option<Bytes>,
    },
    ResponseOnly {
        header: Option<Response>,
        body: Option<Bytes>,
    },
    RequestResponse {
        req_header: Option<Request>,
        req_body: Option<Bytes>,
        res_header: Option<Response>,
        res_body: Option<Bytes>,
    },
}

impl Encapsulated {
    /// Check if this encapsulated message contains a specific section type
    pub fn contains(&self, section_type: &SectionType) -> bool {
        match (self, section_type) {
            (Encapsulated::RequestOnly { header: Some(_), .. }, SectionType::RequestHeader) => true,
            (Encapsulated::RequestOnly { body: Some(_), .. }, SectionType::RequestBody) => true,
            (Encapsulated::ResponseOnly { header: Some(_), .. }, SectionType::ResponseHeader) => true,
            (Encapsulated::ResponseOnly { body: Some(_), .. }, SectionType::ResponseBody) => true,
            (Encapsulated::RequestResponse { req_header: Some(_), .. }, SectionType::RequestHeader) => true,
            (Encapsulated::RequestResponse { req_body: Some(_), .. }, SectionType::RequestBody) => true,
            (Encapsulated::RequestResponse { res_header: Some(_), .. }, SectionType::ResponseHeader) => true,
            (Encapsulated::RequestResponse { res_body: Some(_), .. }, SectionType::ResponseBody) => true,
            (Encapsulated::NullBody, SectionType::NullBody) => true,
            (Encapsulated::Options { body: Some(_) }, SectionType::OptionsBody) => true,
            _ => false,
        }
    }

    pub fn from_sections(sections: HashMap<SectionType, Vec<u8>>) -> Self {
        match (
            sections.contains_key(&SectionType::RequestHeader),
            sections.contains_key(&SectionType::RequestBody),
            sections.contains_key(&SectionType::ResponseHeader),
            sections.contains_key(&SectionType::ResponseBody),
            sections.contains_key(&SectionType::OptionsBody),
            sections.contains_key(&SectionType::NullBody),
        ) {
            (_, _, _, _, _, true) => Self::NullBody,
            (_, _, _, _, true, _) => Self::Options {
                body: sections.get(&SectionType::OptionsBody)
                    .map(|v| Bytes::from(v.to_vec())),
            },
            (true, _, true, _, _, _) | (_, true, true, _, _, _) |
            (true, _, _, true, _, _) | (_, true, _, true, _, _) => Self::RequestResponse {
                req_header: sections.get(&SectionType::RequestHeader)
                    .map(|_| Request::default()),
                req_body: sections.get(&SectionType::RequestBody)
                    .map(|v| Bytes::from(v.to_vec())),
                res_header: sections.get(&SectionType::ResponseHeader)
                    .map(|_| Response::default()),
                res_body: sections.get(&SectionType::ResponseBody)
                    .map(|v| Bytes::from(v.to_vec())),
            },
            (true, _, _, _, _, _) | (_, true, _, _, _, _) => Self::RequestOnly {
                header: sections.get(&SectionType::RequestHeader)
                    .map(|_| Request::default()),
                body: sections.get(&SectionType::RequestBody)
                    .map(|v| Bytes::from(v.to_vec())),
            },
            (_, _, true, _, _, _) | (_, _, _, true, _, _) => Self::ResponseOnly {
                header: sections.get(&SectionType::ResponseHeader)
                    .map(|_| Response::default()),
                body: sections.get(&SectionType::ResponseBody)
                    .map(|v| Bytes::from(v.to_vec())),
            },
            _ => Self::NullBody,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::NullBody)
    }

    pub fn get_section(&self, section_type: SectionType) -> Option<&[u8]> {
        match (self, section_type) {
            (Self::Options { body: Some(b) }, SectionType::OptionsBody) => Some(b),
            (Self::RequestOnly { body: Some(b), .. }, SectionType::RequestBody) => Some(b),
            (Self::ResponseOnly { body: Some(b), .. }, SectionType::ResponseBody) => Some(b),
            (Self::RequestResponse { req_body: Some(b), .. }, SectionType::RequestBody) => Some(b),
            (Self::RequestResponse { res_body: Some(b), .. }, SectionType::ResponseBody) => Some(b),
            _ => None,
        }
    }
}

impl Default for Encapsulated {
    fn default() -> Self {
        Self::RequestOnly {
            header: None,
            body: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IcapMessage {
    Request {
        method: Method,
        uri: String,
        version: Version,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    },
    Response {
        status: u16,
        reason: String,
        version: Version,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    }
}

impl IcapMessage {
    fn calculate_icap_header_offset(&self) -> Result<usize> {
        match self {
            IcapMessage::Request { method, uri, version, headers, encapsulated: _ } => {
                let request_line = format!("{} {} ICAP/{}.0\r\n", 
                    method.to_string(), uri, if *version == Version::V1_0 { "1" } else { "2" });
                let mut offset = request_line.len();
                
                for (name, value) in headers.iter() {
                    offset += name.as_str().len() + 2 + value.len() + 2; // name: value\r\n
                }
                
                offset += 2; // "\r\n"
                
                Ok(offset)
            },
            IcapMessage::Response { version, status, reason, headers, encapsulated: _ } => {
                let response_line = format!("ICAP/{}.0 {} {}\r\n",
                    if *version == Version::V1_0 { "1" } else { "2" }, status, reason);
                let mut offset = response_line.len();
                
                for (name, value) in headers.iter() {
                    offset += name.as_str().len() + 2 + value.len() + 2; // name: value\r\n
                }
                
                offset += 2; // "\r\n"
                
                Ok(offset)
            }
        }
    }

    /// Prepares the headers for an ICAP message before sending.
    /// 
    /// This function calculates the offset values for the Encapsulated header,
    /// which is required by the ICAP protocol to indicate the positions of 
    /// encapsulated sections in the message body.
    /// 
    /// # Example
    /// ```
    /// use rama_http_types::HeaderMap;
    /// use crate::{IcapMessage, Method, Version, SectionType};
    /// 
    /// let mut request = IcapMessage::Request {
    ///     method: Method::ReqMod,
    ///     uri: "/modify".to_string(),
    ///     version: Version::V1_0,
    ///     headers: HeaderMap::new(),
    ///     encapsulated: Encapsulated::RequestOnly {
    ///         header: Some(Request::default()),
    ///         body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
    ///     },
    /// };
    /// request.prepare_headers().unwrap();
    /// ```
    pub fn prepare_headers(&mut self) -> Result<()> {
        // Remove any existing Encapsulated header
        match self {
            IcapMessage::Request { headers, .. } | IcapMessage::Response { headers, .. } => {
                headers.remove("encapsulated");
                headers.remove("Encapsulated");
            }
        }

        // Calculate offset before adding new Encapsulated header
        let offset = self.calculate_icap_header_offset()?;
        
        match self {
            IcapMessage::Request { headers, encapsulated, .. } => {
                // Set Encapsulated header based on what sections we have
                let mut parts = Vec::new();
                let mut current_offset = offset;

                match encapsulated {
                    Encapsulated::RequestOnly { header, body } => {
                        if let Some(header) = header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.len();
                        }
                        if let Some(header) = res_header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = res_body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::ResponseOnly { header, body } => {
                        if let Some(header) = header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::Options { body } => {
                        if let Some(body) = body {
                            parts.push(format!("opt-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::NullBody => {
                        parts.push("null-body=0".to_string());
                    }
                }

                if !parts.is_empty() {
                    headers.insert(
                        "Encapsulated",
                        parts.join(", ").parse().unwrap(),
                    );
                }
            },
            IcapMessage::Response { headers, encapsulated, .. } => {
                // Set Encapsulated header based on what sections we have
                let mut parts = Vec::new();
                let mut current_offset = offset;

                match encapsulated {
                    Encapsulated::RequestOnly { header, body } => {
                        if let Some(header) = header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.len();
                        }
                        if let Some(header) = res_header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = res_body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::ResponseOnly { header, body } => {
                        if let Some(header) = header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.len();
                        }
                        if let Some(body) = body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::Options { body } => {
                        if let Some(body) = body {
                            parts.push(format!("opt-body={}", current_offset));
                            current_offset += body.len();
                        }
                    },
                    Encapsulated::NullBody => {
                        parts.push("null-body=0".to_string());
                    }
                }

                if !parts.is_empty() {
                    headers.insert(
                        "Encapsulated",
                        parts.join(", ").parse().unwrap(),
                    );
                }
            }
        }
        
        Ok(())
    }

    /// Convert the ICAP message to its byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        match self {
            IcapMessage::Request { method, uri, version, headers, encapsulated: _ } => {
                // Write request line
                let request_line = format!("{} {} ICAP/{}.0\r\n", 
                    method.to_string(), uri, if *version == Version::V1_0 { "1" } else { "2" });
                bytes.extend_from_slice(request_line.as_bytes());
                
                // Write headers
                for (name, value) in headers.iter() {
                    bytes.extend_from_slice(name.as_str().as_bytes());
                    bytes.extend_from_slice(b": ");
                    bytes.extend_from_slice(value.as_bytes());
                    bytes.extend_from_slice(b"\r\n");
                }
                
                // End of headers
                bytes.extend_from_slice(b"\r\n");
            },
            IcapMessage::Response { version, status, reason, headers, encapsulated: _ } => {
                // Write response line
                let response_line = format!("ICAP/{}.0 {} {}\r\n",
                    if *version == Version::V1_0 { "1" } else { "2" }, status, reason);
                bytes.extend_from_slice(response_line.as_bytes());
                
                // Write headers
                for (name, value) in headers.iter() {
                    bytes.extend_from_slice(name.as_str().as_bytes());
                    bytes.extend_from_slice(b": ");
                    bytes.extend_from_slice(value.as_bytes());
                    bytes.extend_from_slice(b"\r\n");
                }
                
                // End of headers
                bytes.extend_from_slice(b"\r\n");
            }
        }
        
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    StartLine,
    Headers,
    EncapsulatedHeader,
    Body,
    Complete,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum SectionType {
    NullBody,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    OptionsBody,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HeaderMap,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            method: String::from("GET"),
            uri: String::from("/"),
            version: String::from("HTTP/1.1"),
            headers: HeaderMap::new(),
        }
    }
}

impl Request {
    pub fn len(&self) -> usize {
        let mut len = 0;
        for (name, value) in self.headers.iter() {
            len += name.as_str().len() + 2 + value.len() + 2; // name: value\r\n
        }
        len + 2 // final \r\n
    }

    pub fn parse(&mut self, buf: &[u8]) -> Result<Status<()>> {
        let buf_str = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => return Err(Error::Protocol("Invalid UTF-8 in request".to_string())),
        };
        
        let mut parts = buf_str.splitn(3, ' ');
        
        self.method = parts.next()
            .ok_or_else(|| Error::Protocol("Missing method".to_string()))?
            .to_string();
            
        self.uri = parts.next()
            .ok_or_else(|| Error::Protocol("Missing URI".to_string()))?
            .to_string();
            
        self.version = parts.next()
            .ok_or_else(|| Error::Protocol("Missing version".to_string()))?
            .trim_end()
            .to_string();
            
        Ok(Status::Complete(()))
    }
}

/// Response status
#[derive(Debug)]
pub enum Status<T> {
    /// Represents a complete result
    Complete(T),
    /// Represents a partial result, needing more data
    Partial,
}

pub use parser::MessageParser;

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::HeaderMap;

    const NUM_OF_HEADERS: usize = 4;

    #[test]
    fn test_request_simple() {
        let mut headers = HeaderMap::new();
        let mut req = Request::default();
        let buf = b"OPTIONS / ICAP/1.0\r\nEncapsulated:null-body=0\r\n\r\n";
        let status = req.parse(buf);
        
        assert!(matches!(status, Ok(Status::Complete(_))));
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.uri, "/");
        assert_eq!(req.version, "ICAP/1.0");
    }

    #[test]
    fn test_request_partial() {
        let mut headers = HeaderMap::new();
        let mut req = Request::default();
        let buf = b"RESP";
        let status = req.parse(buf);
        
        assert!(matches!(status, Ok(Status::Partial)));
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(Method::Options.as_str(), "OPTIONS");
        assert_eq!(Method::ReqMod.as_str(), "REQMOD");
        assert_eq!(Method::RespMod.as_str(), "RESPMOD");
    }

    #[test]
    fn test_icap_message_request() {
        let headers = {
            let mut headers = HeaderMap::new();
            headers.insert("Host", "icap.example.org".parse().unwrap());
            headers
        };
        
        let encapsulated = Encapsulated::RequestOnly {
            header: Some(Request::default()),  
            body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
        };
        
        let msg = IcapMessage::Request {
            method: Method::ReqMod,
            uri: String::from("/modify"),
            version: Version::V1_0,
            headers,
            encapsulated,
        };
        
        match msg {
            IcapMessage::Request { method, uri, version, headers, encapsulated } => {
                assert_eq!(method, Method::ReqMod);
                assert_eq!(uri, "/modify");
                assert_eq!(version, Version::V1_0);
                assert_eq!(headers.get("Host").unwrap(), "icap.example.org");
                assert!(encapsulated.contains(&SectionType::RequestHeader));
            }
            _ => panic!("Expected Request variant"),
        }
    }

    #[test]
    fn test_icap_message_response() {
        let mut headers = HeaderMap::new();
        headers.insert("Server", "IcapServer/1.0".parse().unwrap());
        
        let mut encapsulated = Encapsulated::RequestOnly {
            header: Some(Request::default()),
            body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
        };
        
        let msg = IcapMessage::Response {
            version: Version::V1_0,
            status: 200,
            reason: String::from("OK"),
            headers,
            encapsulated,
        };
        
        match msg {
            IcapMessage::Response { version, status, reason, headers, encapsulated } => {
                assert_eq!(version, Version::V1_0);
                assert_eq!(status, 200);
                assert_eq!(reason, "OK");
                assert_eq!(headers.get("Server").unwrap(), "IcapServer/1.0");
                assert!(encapsulated.contains(&SectionType::RequestHeader));
            }
            _ => panic!("Expected Response variant"),
        }
    }

    #[test]
    fn test_section_type() {
        let sections = vec![
            SectionType::NullBody,
            SectionType::RequestHeader,
            SectionType::RequestBody,
            SectionType::ResponseHeader,
            SectionType::ResponseBody,
            SectionType::OptionsBody,
        ];
        
        for section in sections {
            match section {
                SectionType::NullBody => {},
                SectionType::RequestHeader => {},
                SectionType::RequestBody => {},
                SectionType::ResponseHeader => {},
                SectionType::ResponseBody => {},
                SectionType::OptionsBody => {},
            }
        }
    }

    #[test]
    fn test_calculate_icap_header_offset() {
        let mut headers = HeaderMap::new();
        headers.insert("Host", "icap-server.net".parse().unwrap());
        headers.insert("Connection", "close".parse().unwrap());
        
        // Test request
        let request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "icap://icap-server.net/virus_scan".to_string(),
            version: Version::V1_0,
            headers: headers.clone(),
            encapsulated: Encapsulated::RequestOnly {
                header: Some(Request::default()),  
                body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
            },
        };

        // The request line "REQMOD icap://icap-server.net/virus_scan ICAP/1.0\r\n" is 51 bytes
        // Headers: "Host: icap-server.net\r\n" (23 bytes) + "Connection: close\r\n" (19 bytes)
        // Final \r\n (2 bytes)
        // Total: 51 + 23 + 19 + 2 = 95 bytes
        // This is the offset where the encapsulated sections start
        assert_eq!(request.calculate_icap_header_offset().unwrap(), 95);
        
        // Test response
        let response = IcapMessage::Response {
            version: Version::V1_0,
            status: 200,
            reason: "OK".to_string(),
            headers: headers.clone(),
            encapsulated: Encapsulated::RequestOnly {
                header: Some(Request::default()),
                body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
            },
        };
        // The response line "ICAP/1.0 200 OK\r\n" is 17 bytes
        // Headers: "Host: icap-server.net\r\n" (23 bytes) + "Connection: close\r\n" (19 bytes)
        // Final \r\n (2 bytes)
        // Total: 17 + 23 + 19 + 2 = 61 bytes
        assert_eq!(response.calculate_icap_header_offset().unwrap(), 61);
    }

    #[test]
    fn test_prepare_headers() {
        // Test 1: Request with both header and body
        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "icap://icap-server.net/virus_scan".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated: Encapsulated::RequestOnly {
                header: Some(Request::default()),
                body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
            },
        };
        
        request.prepare_headers().unwrap();
        
        let headers = match &request {
            IcapMessage::Request { headers, .. } => headers,
            _ => panic!("Expected Request"),
        };
        
        // Verify Encapsulated header format: "req-hdr=0, req-body=X"
        let enc = headers.get("Encapsulated").unwrap().to_str().unwrap();
        assert!(enc.starts_with("req-hdr=0, req-body="));
        
        // Test 2: Request with only header (null-body)
        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "icap://icap-server.net/virus_scan".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated: Encapsulated::RequestOnly {
                header: Some(Request {
                    method: "REQMOD".to_string(),
                    uri: String::new(),
                    version: "ICAP/1.0".to_string(),
                    headers: HeaderMap::new(),
                }),
                body: None,
            },
        };
        request.prepare_headers().unwrap();
        
        let headers = match &request {
            IcapMessage::Request { headers, .. } => headers,
            _ => panic!("Expected Request"),
        };
        
        // Verify Encapsulated header format: "req-hdr=0, null-body=X"
        let enc = headers.get("Encapsulated").unwrap().to_str().unwrap();
        assert!(enc.starts_with("req-hdr=0, null-body="));
        
        // Test 3: Response with body
        let mut response = IcapMessage::Response {
            version: Version::V1_0,
            status: 200,
            reason: "OK".to_string(),
            headers: HeaderMap::new(),
            encapsulated: Encapsulated::RequestOnly {
                header: Some(Request::default()),
                body: Some(b"GET / HTTP/1.1\r\n".to_vec().into()),
            },
        };
        
        response.prepare_headers().unwrap();
        
        let headers = match &response {
            IcapMessage::Response { headers, .. } => headers,
            _ => panic!("Expected Response"),
        };
        
        // Verify Encapsulated header format: "res-hdr=0, res-body=X"
        let enc = headers.get("Encapsulated").unwrap().to_str().unwrap();
        assert!(enc.starts_with("res-hdr=0, res-body="));
    }
}

/// Represents what the connection wants to do next
#[derive(Debug, Clone, Copy)]
pub enum Wants {
    /// Connection wants to read
    Read,
    /// Connection wants to write
    Write,
}

/// Represents an ICAP message (either request or response)
#[derive(Debug)]
pub struct Message {
    /// Headers specific to ICAP
    pub headers: HashMap<String, String>,
    /// Sections contained in the message body
    pub sections: HashMap<SectionType, Vec<u8>>,
}

impl Message {
    /// Create a new empty ICAP message
    pub fn new() -> Self {
        Message {
            headers: HashMap::new(),
            sections: HashMap::new(),
        }
    }

    /// Add a header to the message
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }

    /// Add a section to the message
    pub fn add_section(&mut self, section_type: SectionType, content: Vec<u8>) {
        self.sections.insert(section_type, content);
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcapHeaderName(String);

impl IcapHeaderName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::Protocol("Header name cannot be empty".to_string()));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for IcapHeaderName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
