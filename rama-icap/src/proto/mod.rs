mod conn;
pub(crate) mod encode;
pub(crate) mod decode;

pub(crate) mod transport;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod role;
pub(crate) mod dispatch;
mod status;

use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use parking_lot::{Mutex, RwLock};
use rama_http_types::{
    Request, Response, HeaderMap, Body,
};

pub use status::StatusCode as IcapStatusCode;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    StartLine,
    Headers,
    EncapsulatedHeader,
    Body,
    Complete,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum SectionType {
    NullBody,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    OptionsBody,
}

#[derive(Debug)]
pub enum Encapsulated {
    NullBody,
    Options {
        opt_body: Option<Body>,
    },
    RequestOnly {
        req_header: Option<HeaderMap>,
        req_body: Option<Body>,
    },
    ResponseOnly {
        res_header: Option<Response<Body>>,
        res_body: Option<Body>,
    },
    RequestResponse {
        req_header: Option<Request<Body>>,
        req_body: Option<Body>,
        res_header: Option<Response<Body>>,
        res_body: Option<Body>,
    },
}

impl Encapsulated {
    /// Check if this encapsulated message contains a specific section type
    pub fn contains(&self, section_type: &SectionType) -> bool {
        match (self, section_type) {
            (Encapsulated::RequestOnly { req_header: Some(_), .. }, SectionType::RequestHeader) => true,
            (Encapsulated::RequestOnly { req_body: Some(_), .. }, SectionType::RequestBody) => true,
            (Encapsulated::ResponseOnly { res_header: Some(_), .. }, SectionType::ResponseHeader) => true,
            (Encapsulated::ResponseOnly { res_body: Some(_), .. }, SectionType::ResponseBody) => true,
            (Encapsulated::RequestResponse { req_header: Some(_), .. }, SectionType::RequestHeader) => true,
            (Encapsulated::RequestResponse { req_body: Some(_), .. }, SectionType::RequestBody) => true,
            (Encapsulated::RequestResponse { res_header: Some(_), .. }, SectionType::ResponseHeader) => true,
            (Encapsulated::RequestResponse { res_body: Some(_), .. }, SectionType::ResponseBody) => true,
            (Encapsulated::NullBody, SectionType::NullBody) => true,
            (Encapsulated::Options { opt_body: Some(_) }, SectionType::OptionsBody) => true,
            _ => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::NullBody)
    }
}

impl Default for Encapsulated {
    fn default() -> Self {
        Self::NullBody
    }
}


// TODO: move to lib and make public
#[derive(Debug)]
pub enum IcapMessage {
    Request {
        method: Method,
        uri: String,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    },
    Response {
        status: u16,
        reason: String,
        headers: HeaderMap,
        encapsulated: Encapsulated,
    }
}

impl IcapMessage {
    fn calculate_icap_header_offset(&self) -> Result<usize> {
        match self {
            IcapMessage::Request { method, uri, headers, encapsulated: _ } => {
                let request_line = format!("{} {} ICAP/{}.0\r\n", 
                    method.to_string(), uri, ICAP_VERSION);
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
                    Encapsulated::RequestOnly { req_header, req_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                        if let Some(header) = res_header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = res_body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::ResponseOnly { header, body } => {
                        if let Some(header) = header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::Options { body } => {
                        if let Some(body) = body {
                            parts.push(format!("opt-body={}", current_offset));
                            current_offset += body.get_ref().len();
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
                    Encapsulated::RequestOnly { req_header, req_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        if let Some(header) = req_header {
                            parts.push(format!("req-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = req_body {
                            parts.push(format!("req-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                        if let Some(header) = res_header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = res_body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::ResponseOnly { res_header, res_body } => {
                        if let Some(header) = res_header {
                            parts.push(format!("res-hdr={}", current_offset));
                            current_offset += header.headers().len();
                        }
                        if let Some(body) = res_body {
                            parts.push(format!("res-body={}", current_offset));
                            current_offset += body.into_stream().get_ref().len();
                        }
                    },
                    Encapsulated::Options { opt_body } => {
                        if let Some(body) = opt_body {
                            parts.push(format!("opt-body={}", current_offset));
                            current_offset += body.get_ref().len();
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


/// Trait for implementing ICAP services
pub trait IcapService {
    /// The response type returned by this service
    type Response;
    /// The error type returned by this service
    type Error;
    /// The future returned by this service
    type Future: Future<Output = Result<Self::Response>>;

    /// Process an ICAP request
    fn call(&self, request: IcapMessage) -> Self::Future;
}

use bytes::BytesMut;
use rama_http_types::{HeaderMap, Method};

use crate::body::DecodedLength;
use crate::proto::{BodyLength, MessageHead};

pub(crate) use self::conn::Conn;
pub(crate) use self::decode::Decoder;
pub(crate) use self::dispatch::Dispatcher;
pub(crate) use self::encode::{EncodedBuf, Encoder};
//TODO: move out of h1::io
pub(crate) use self::io::MINIMUM_MAX_BUFFER_SIZE;

mod conn;
mod decode;
pub(crate) mod dispatch;
mod encode;
mod io;
mod role;

pub(crate) type ClientTransaction = role::Client;
pub(crate) type ServerTransaction = role::Server;

pub(crate) trait IcapTransaction {
    type Incoming;
    type Outgoing: Default;
    const LOG: &'static str;
    fn parse(bytes: &mut BytesMut, ctx: ParseContext<'_>) -> ParseResult<Self::Incoming>;
    fn encode(enc: Encode<'_, Self::Outgoing>, dst: &mut Vec<u8>) -> crate::Result<Encoder>;

    fn on_error(err: &crate::Error) -> Option<MessageHead<Self::Outgoing>>;

    fn is_client() -> bool {
        !Self::is_server()
    }

    fn is_server() -> bool {
        !Self::is_client()
    }

    fn should_error_on_parse_eof() -> bool {
        Self::is_client()
    }

    fn should_read_first() -> bool {
        Self::is_server()
    }

    fn update_date() {}
}

/// Result newtype for Http1Transaction::parse.
pub(crate) type ParseResult<T> = Result<Option<ParsedMessage<T>>, crate::error::Parse>;

#[derive(Debug)]
pub(crate) struct ParsedMessage<T> {
    head: MessageHead<T>,
    decode: DecodedLength,
    expect_continue: bool,
    keep_alive: bool,
    wants_upgrade: bool,
}

pub(crate) struct ParseContext<'a> {
    cached_headers: &'a mut Option<HeaderMap>,
    req_method: &'a mut Option<Method>,
    max_headers: Option<usize>,
}

/// Passed to Http1Transaction::encode
pub(crate) struct Encode<'a, T> {
    head: &'a mut MessageHead<T>,
    body: Option<BodyLength>,
    keep_alive: bool,
    req_method: &'a mut Option<Method>,
    title_case_headers: bool,
    date_header: bool,
}

/// Extra flags that a request "wants", like expect-continue or upgrades.
#[derive(Clone, Copy, Debug)]
struct Wants(u8);

impl Wants {
    const EMPTY: Wants = Wants(0b00);
    const EXPECT: Wants = Wants(0b01);
    const UPGRADE: Wants = Wants(0b10);

    #[must_use]
    fn add(self, other: Wants) -> Wants {
        Wants(self.0 | other.0)
    }

    fn contains(&self, other: Wants) -> bool {
        (self.0 & other.0) == other.0
    }
}
