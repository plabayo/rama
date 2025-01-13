use bytes::{Buf, BytesMut};
use http::HeaderMap;
use std::collections::HashMap;

use crate::{Error, IcapMessage, Method, Result, SectionType, State, Version};

const MAX_HEADERS: usize = 100;
const MAX_HEADER_NAME_LEN: usize = 100;
const MAX_HEADER_VALUE_LEN: usize = 4096;
const MAX_LINE_LENGTH: usize = 8192;

pub struct ByteParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteParser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    pub fn advance(&mut self) {
        self.pos += 1;
    }

    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        &self.bytes[..self.pos]
    }

    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }
}

pub struct MessageParser {
    state: State,
    headers: HeaderMap,
    encapsulated: HashMap<SectionType, Vec<u8>>,
    buffer: BytesMut,
    method: Option<Method>,
    uri: Option<String>,
    version: Option<Version>,
    status: Option<u16>,
    reason: Option<String>,
}

impl MessageParser {
    pub fn new() -> Self {
        Self {
            state: State::StartLine,
            headers: HeaderMap::new(),
            encapsulated: HashMap::new(),
            buffer: BytesMut::with_capacity(4096),
            method: None,
            uri: None,
            version: None,
            status: None,
            reason: None,
        }
    }

    pub fn parse(&mut self, buf: &[u8]) -> Result<Option<IcapMessage>> {
        // Append new data to our buffer
        self.buffer.extend_from_slice(buf);

        loop {
            match self.state {
                State::StartLine => {
                    if !self.parse_start_line()? {
                        return Ok(None);
                    }
                }
                State::Headers => {
                    if !self.parse_headers()? {
                        return Ok(None);
                    }
                }
                State::EncapsulatedHeader => {
                    if !self.parse_encapsulated()? {
                        return Ok(None);
                    }
                }
                State::Body => {
                    if !self.parse_body()? {
                        return Ok(None);
                    }
                }
                State::Complete => {
                    return Ok(Some(self.build_message()?));
                }
            }
        }
    }

    fn parse_start_line(&mut self) -> Result<bool> {
        if let Some(line) = self.read_line()? {
            if line.is_empty() {
                return Ok(false);
            }

            // Parse line
            let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
            if parts.len() != 3 {
                return Err(Error::InvalidMethod);
            }

            // Check if this is a response (starts with ICAP/)
            if let Some(version) = self.parse_version(parts[0])? {
                self.version = Some(version);
                // Parse status code
                let status = std::str::from_utf8(parts[1])
                    .map_err(|_| Error::InvalidStatus)?
                    .parse::<u16>()
                    .map_err(|_| Error::InvalidStatus)?;
                self.status = Some(status);
                // Parse reason
                let reason = std::str::from_utf8(parts[2])
                    .map_err(|_| Error::InvalidReason)?
                    .to_string();
                self.reason = Some(reason);
            } else {
                // This is a request
                // Parse method
                let method = match parts[0] {
                    b"REQMOD" => Method::ReqMod,
                    b"RESPMOD" => Method::RespMod,
                    b"OPTIONS" => Method::Options,
                    _ => return Err(Error::InvalidMethod),
                };
                self.method = Some(method);

                // Parse URI
                let uri = std::str::from_utf8(parts[1])
                    .map_err(|_| Error::InvalidUri)?
                    .to_string();
                self.uri = Some(uri);

                // Parse version
                if let Some(version) = self.parse_version(parts[2])? {
                    self.version = Some(version);
                } else {
                    return Err(Error::InvalidVersion);
                }
            }

            self.state = State::Headers;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_version(&self, bytes: &[u8]) -> Result<Option<Version>> {
        if bytes.len() < 8 {
            return Ok(None);
        }
        match bytes {
            [b'I', b'C', b'A', b'P', b'/', b'1', b'.', b'0', ..] => Ok(Some(Version::V1_0)),
            [b'I', b'C', b'A', b'P', b'/', b'1', b'.', b'1', ..] => Ok(Some(Version::V1_1)),
            [b'I', b'C', b'A', b'P', b'/', ..] => Err(Error::InvalidVersion),
            _ => Ok(None),
        }
    }

    fn parse_headers(&mut self) -> Result<bool> {
        let mut found_encapsulated = false;
        
        while let Some(line) = self.read_line()? {
            // Empty line indicates end of headers
            if line.is_empty() {
                // Check if Encapsulated header is required
                if !found_encapsulated {
                    // For responses, Encapsulated header is not required if there's no body
                    if self.status.is_some() {
                        // This is a response
                        self.state = State::EncapsulatedHeader;
                        return Ok(true);
                    } else if let Some(method) = &self.method {
                        // This is a request
                        match method {
                            Method::Options => {}, // Encapsulated header is optional for OPTIONS
                            _ => return Err(Error::MissingEncapsulated)
                        }
                    }
                }
                self.state = State::EncapsulatedHeader;
                return Ok(true);
            }

            // Split into name and value
            let mut parts = line.splitn(2, |&b| b == b':');
            let name = parts.next().ok_or(Error::InvalidHeader)?;
            let value = parts.next().ok_or(Error::InvalidHeader)?;

            // Validate lengths
            if name.len() > MAX_HEADER_NAME_LEN {
                return Err(Error::MessageTooLarge);
            }
            if value.len() > MAX_HEADER_VALUE_LEN {
                return Err(Error::MessageTooLarge);
            }

            // Convert to strings and add to headers
            let name = http::HeaderName::from_bytes(name)?;
            let value = String::from_utf8_lossy(value).trim().to_string();
            
            // Check for Encapsulated header
            if name.as_str().eq_ignore_ascii_case("encapsulated") {
                found_encapsulated = true;
            }
            
            self.headers.insert(name, value.parse()?);

            if self.headers.len() > MAX_HEADERS {
                return Err(Error::MessageTooLarge);
            }
        }

        Ok(false)
    }

    fn parse_encapsulated(&mut self) -> Result<bool> {
        // Parse the Encapsulated header
        if let Some(enc) = self.headers.get("Encapsulated") {
            let enc = enc.to_str().map_err(|_| Error::InvalidEncoding)?;
            
            // Parse each section
            for section in enc.split(',') {
                let mut parts = section.trim().split('=');
                let name = parts.next().ok_or(Error::InvalidHeader)?;
                let offset = parts.next()
                    .ok_or(Error::InvalidHeader)?
                    .parse::<usize>()
                    .map_err(|_| Error::InvalidHeader)?;

                let section_type = match name {
                    "null-body" => SectionType::NullBody,
                    "req-hdr" => SectionType::RequestHeader,
                    "req-body" => SectionType::RequestBody,
                    "res-hdr" => SectionType::ResponseHeader,
                    "res-body" => SectionType::ResponseBody,
                    "opt-body" => SectionType::OptionsBody,
                    _ => return Err(Error::InvalidHeader),
                };

                self.encapsulated.insert(section_type, Vec::new());
            }
        } else if self.method != Some(Method::Options) {
            return Err(Error::MissingEncapsulated);
        }

        self.state = State::Body;
        Ok(true)
    }

    fn parse_body(&mut self) -> Result<bool> {
        // For now, just collect all remaining data as body
        if !self.buffer.is_empty() {
            let data = self.buffer.split().freeze();
            
            // Add body data to appropriate section
            if let Some(section) = self.encapsulated.values_mut().next() {
                section.extend_from_slice(&data);
            }
        }

        self.state = State::Complete;
        Ok(true)
    }

    fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        let mut found_line = false;

        for (i, &b) in self.buffer.iter().enumerate() {
            if b == b'\n' {
                line.extend_from_slice(&self.buffer[..i]);
                if line.ends_with(b"\r") {
                    line.pop();
                }
                self.buffer.advance(i + 1);
                found_line = true;
                break;
            }
        }

        if found_line {
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }

    fn build_message(&self) -> Result<IcapMessage> {
        match (self.method.as_ref(), self.status.as_ref()) {
            (Some(method), None) => {
                // Build request
                Ok(IcapMessage::Request {
                    method: method.clone(),
                    uri: self.uri.clone().unwrap(),
                    version: self.version.unwrap(),
                    headers: self.headers.clone(),
                    encapsulated: self.encapsulated.clone(),
                })
            }
            (None, Some(status)) => {
                // Build response
                Ok(IcapMessage::Response {
                    version: self.version.unwrap(),
                    status: *status,
                    reason: self.reason.clone().unwrap_or_default(),
                    headers: self.headers.clone(),
                    encapsulated: self.encapsulated.clone(),
                })
            }
            _ => Err(Error::IncompleteMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_byte_parser() {
        let data = b"ICAP/1.0 200 OK\r\n";
        let mut parser = ByteParser::new(data);

        assert_eq!(parser.peek(), Some(b'I'));
        parser.advance();
        assert_eq!(parser.peek(), Some(b'C'));
        
        assert_eq!(parser.slice(), b"I");
        assert_eq!(parser.remaining(), b"CAP/1.0 200 OK\r\n");
        assert_eq!(parser.position(), 1);
    }

    #[test]
    fn test_parse_request_line() {
        let mut parser = MessageParser::new();
        let data = b"REQMOD icap://example.org/modify ICAP/1.0\r\n";
        
        let result = parser.parse(data).unwrap();
        assert!(result.is_none()); // Need more data for complete message
        
        match parser.state {
            State::Headers => {},
            _ => panic!("Expected Headers state"),
        }
    }

    #[test]
    fn test_parse_headers() {
        let mut parser = MessageParser::new();
        let data = b"REQMOD icap://example.org/modify ICAP/1.0\r\n\
                    Host: example.org\r\n\
                    Connection: close\r\n\
                    Encapsulated: req-hdr=0\r\n";  // No final \r\n and no HTTP message
        
        let result = parser.parse(data).unwrap();
        assert!(result.is_none()); // Need more data for complete message
        
        match parser.state {
            State::Headers => {},  // Still in Headers state because we haven't seen the final \r\n
            _ => panic!("Expected Headers state"),
        }
    }

    #[test]
    fn test_parse_encapsulated() {
        let mut parser = MessageParser::new();
        let data = b"REQMOD icap://example.org/modify ICAP/1.0\r\n\
                    Host: example.org\r\n\
                    Encapsulated: req-hdr=0, req-body=178\r\n\r\n\
                    GET / HTTP/1.1\r\n\
                    Host: www.origin-server.com\r\n\
                    Accept: text/html\r\n\r\n\
                    Some body content";
        
        let result = parser.parse(data).unwrap().unwrap();
        match result {
            IcapMessage::Request { method, uri, headers, encapsulated, .. } => {
                assert_eq!(method, Method::ReqMod);
                assert_eq!(uri, "icap://example.org/modify");
                assert_eq!(headers.get("Host").unwrap(), "example.org");
                assert!(encapsulated.contains_key(&SectionType::RequestHeader));
                assert!(encapsulated.contains_key(&SectionType::RequestBody));
            }
            _ => panic!("Expected Request"),
        }
    }

    #[test]
    fn test_parse_response() {
        let mut parser = MessageParser::new();
        let data = b"ICAP/1.0 200 OK\r\n\
                    Server: IcapServer/1.0\r\n\
                    Connection: close\r\n\
                    Encapsulated: null-body=0\r\n\r\n";
        
        let result = parser.parse(data).unwrap().unwrap();
        match result {
            IcapMessage::Response { version, status, reason, headers, .. } => {
                assert_eq!(version, Version::V1_0);
                assert_eq!(status, 200);
                assert_eq!(reason, "OK");
                assert_eq!(headers.get("Server").unwrap(), "IcapServer/1.0");
            } 
            _ => panic!("Expected Response"),
        }
    }

    #[test]
    fn test_parse_error_cases() {
        let mut parser = MessageParser::new();
        
        // Invalid method
        let data = b"INVALID icap://example.org/modify ICAP/1.0\r\n\r\n";
        assert!(parser.parse(data).is_err());
        
        // Reset parser
        parser = MessageParser::new();
        
        // Invalid version
        let data = b"REQMOD icap://example.org/modify ICAP/2.0\r\n\r\n";
        assert!(parser.parse(data).is_err());
        
        // Reset parser
        parser = MessageParser::new();
        
        // Missing Encapsulated header for REQMOD
        let data = b"REQMOD icap://example.org/modify ICAP/1.0\r\n\
                    Host: example.org\r\n\r\n";
        assert!(parser.parse(data).is_err());
        
        // Reset parser
        parser = MessageParser::new();
        
        // Missing Encapsulated header for RESPMOD
        let data = b"RESPMOD icap://example.org/modify ICAP/1.0\r\n\
                    Host: example.org\r\n\r\n";
        assert!(parser.parse(data).is_err());
        
        // Reset parser
        parser = MessageParser::new();
        
        // OPTIONS request without Encapsulated header should be OK
        let data = b"OPTIONS icap://example.org/modify ICAP/1.0\r\n\
                    Host: example.org\r\n\r\n";
        assert!(parser.parse(data).is_ok());
        
        // Reset parser
        parser = MessageParser::new();
        
        // Response without Encapsulated header should be OK
        let data = b"ICAP/1.0 200 OK\r\n\
                    Server: test-server/1.0\r\n\r\n";
        assert!(parser.parse(data).is_ok());
    }

    #[test]
    fn test_read_line() {
        let mut parser = MessageParser::new();
        parser.buffer.extend_from_slice(b"line1\r\nline2\r\n");
        
        let line1 = parser.read_line().unwrap().unwrap();
        assert_eq!(line1, b"line1");
        
        let line2 = parser.read_line().unwrap().unwrap();
        assert_eq!(line2, b"line2");
        
        assert!(parser.read_line().unwrap().is_none());
    }
}
