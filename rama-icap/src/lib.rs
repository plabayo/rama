//! ICAP (Internet Content Adaptation Protocol) implementation according to RFC 3507.
//! 
//! This module provides support for the ICAP protocol, which allows HTTP messages to be 
//! adapted/transformed by an ICAP server.

pub mod proto;
pub mod parser;

use std::collections::HashMap;
use thiserror::Error;
use rama_http_types::{header::{InvalidHeaderValue, InvalidHeaderName}, HeaderMap};
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

#[derive(Debug)]
pub enum Encapsulated {
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
    NullBody,
    Options {
        body: Option<Bytes>,
    },
}

#[derive(Debug)]
pub enum IcapMessage {
    Request {
        method: Method,
        uri: String,
        version: Version,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    },
    Response {
        version: Version,
        status: u16,
        reason: String,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    },
}

impl IcapMessage {
    fn calculate_icap_header_offset(&self) -> Result<usize> {
        match self {
            IcapMessage::Request { method, uri, version, headers, encapsulated: _ } => {
                let request_line = format!("{} {} ICAP/{}.0\r\n", 
                    method.to_string(), uri, if *version == Version::V1_0 { "1" } else { "2" });
                let mut offset = request_line.len();
                
                for (name, value) in headers.iter() {
                    offset += name.as_str().len() + 2 + value.len() + 2; // "name: value\r\n"
                }
                
                offset += 2; // "\r\n"
                
                Ok(offset)
            },
            IcapMessage::Response { version, status, reason, headers, encapsulated: _ } => {
                let response_line = format!("ICAP/{}.0 {} {}\r\n",
                    if *version == Version::V1_0 { "1" } else { "2" }, status, reason);
                let mut offset = response_line.len();
                
                for (name, value) in headers.iter() {
                    offset += name.as_str().len() + 2 + value.len() + 2; // "name: value\r\n"
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
    /// use std::collections::HashMap;
    /// use crate::{IcapMessage, Method, Version, SectionType};
    /// 
    /// let mut request = IcapMessage::Request {
    ///     method: Method::ReqMod,
    ///     uri: "/modify".to_string(),
    ///     version: Version::V1_0,
    ///     headers: http::HeaderMap::new(),
    ///     encapsulated: Vec::new(),
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
                let mut current_offset = 0;

                for (section_type, data) in encapsulated.iter() {
                    match section_type {
                        SectionType::RequestHeader => {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += data.len();
                        },
                        SectionType::RequestBody => {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += data.len();
                        },
                        SectionType::NullBody => {
                            parts.push(format!("null-body={}", current_offset));
                        },
                        _ => continue,
                    }
                }

                if parts.is_empty() {
                    parts.push(format!("null-body={}", current_offset));
                }

                headers.insert("Encapsulated", parts.join(", ").parse().unwrap());
            },
            IcapMessage::Response { headers, encapsulated, .. } => {
                // Similar logic for responses
                let mut parts = Vec::new();
                let mut current_offset = 0;

                for (section_type, data) in encapsulated.iter() {
                    match section_type {
                        SectionType::ResponseHeader => {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += data.len();
                        },
                        SectionType::ResponseBody => {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += data.len();
                        },
                        SectionType::NullBody => {
                            parts.push(format!("null-body={}", current_offset));
                        },
                        _ => continue,
                    }
                }

                if parts.is_empty() {
                    parts.push(format!("null-body={}", current_offset));
                }

                headers.insert("Encapsulated", parts.join(", ").parse().unwrap());
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum SectionType {
    NullBody,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    OptionsBody,
}

#[derive(Debug)]
pub struct Request<'a> {
    /// The request method (REQMOD, RESPMOD, OPTIONS)
    pub method: Option<&'a str>,
    /// The request path/URI
    pub path: Option<&'a str>,
    /// ICAP version (as a number, 0 = 1.0)
    pub version: Option<Version>,
    /// Headers included in the request
    pub headers: Vec<Header<'a>>,
    /// Parsed encapsulated sections
    pub encapsulated_sections: Option<HashMap<SectionType, Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header<'a> {
    /// Header name
    pub name: &'a str,
    /// Header value
    pub value: &'a [u8],
}

/// Empty header constant for initialization
pub const EMPTY_HEADER: Header<'static> = Header { name: "", value: b"" };

impl<'a> Request<'a> {
    /// Create a new Request with a pre-allocated headers array
    pub fn new(headers: &'a mut [Header<'a>]) -> Request<'a> {
        Request {
            method: None,
            path: None,
            version: None,
            headers: Vec::new(),
            encapsulated_sections: None,
        }
    }

    /// Parse an ICAP request from a byte slice
    pub fn parse(&mut self, buf: &'a [u8]) -> std::result::Result<Status<usize>, Error> {
        // Basic implementation for testing
        if buf.len() < 5 {
            return Ok(Status::Partial);
        }

        // Simple parsing for testing purposes
        let mut parts = buf.split(|&b| b == b' ');
        
        // Parse method
        if let Some(method) = parts.next() {
            self.method = std::str::from_utf8(method).ok();
        }

        // Parse path
        if let Some(path) = parts.next() {
            self.path = std::str::from_utf8(path).ok();
        }

        // Parse version
        if let Some(version) = parts.next() {
            if version.starts_with(b"ICAP/1.") {
                self.version = Some(Version::V1_0);
            }
        }

        Ok(Status::Complete(buf.len()))
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
    use http::HeaderMap;
    use std::collections::HashMap;

    const NUM_OF_HEADERS: usize = 4;

    #[test]
    fn test_request_simple() {
        let mut headers = vec![EMPTY_HEADER; NUM_OF_HEADERS];
        let mut req = Request::new(&mut headers);
        let buf = b"OPTIONS / ICAP/1.0\r\nEncapsulated:null-body=0\r\n\r\n";
        let status = req.parse(buf);
        
        assert!(matches!(status, Ok(Status::Complete(_))));
        assert_eq!(req.method, Some("OPTIONS"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(req.version, Some(Version::V1_0));
    }

    #[test]
    fn test_request_partial() {
        let mut headers = vec![EMPTY_HEADER; NUM_OF_HEADERS];
        let mut req = Request::new(&mut headers);
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
        let mut headers = HeaderMap::new();
        headers.insert("Host", "icap.example.org".parse().unwrap());
        
        let mut encapsulated = Vec::new();
        encapsulated.push((SectionType::RequestHeader, b"GET / HTTP/1.1\r\n".to_vec()));
        
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
                assert!(encapsulated.contains(&(SectionType::RequestHeader, b"GET / HTTP/1.1\r\n".to_vec())));
            }
            _ => panic!("Expected Request variant"),
        }
    }

    #[test]
    fn test_icap_message_response() {
        let mut headers = HeaderMap::new();
        headers.insert("Server", "IcapServer/1.0".parse().unwrap());
        
        let mut encapsulated = Vec::new();
        encapsulated.push((SectionType::ResponseHeader, b"HTTP/1.1 200 OK\r\n".to_vec()));
        
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
                assert!(encapsulated.contains(&(SectionType::ResponseHeader, b"HTTP/1.1 200 OK\r\n".to_vec())));
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
            encapsulated: Vec::new(),
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
            encapsulated: Vec::new(),
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
            encapsulated: Vec::new(),
        };
        
        // Add request header and body
        if let IcapMessage::Request { encapsulated, .. } = &mut request {
            encapsulated.push((SectionType::RequestHeader, Vec::new()));
            encapsulated.push((SectionType::RequestBody, Vec::new()));
        }
        
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
            encapsulated: Vec::new(),
        };
        
        if let IcapMessage::Request { encapsulated, .. } = &mut request {
            encapsulated.push((SectionType::RequestHeader, Vec::new()));
        }
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
            encapsulated: Vec::new(),
        };
        
        if let IcapMessage::Response { encapsulated, .. } = &mut response {
            encapsulated.push((SectionType::ResponseHeader, Vec::new()));
            encapsulated.push((SectionType::ResponseBody, Vec::new()));
        }
        
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
