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

use crate::{Error, Method, Result, ICAP_VERSION};
pub use status::StatusCode as IcapStatusCode;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    StartLine,
    Headers,
    EncapsulatedHeader,
    Body,
    Complete,
}

#[derive(Debug, Clone)]
pub enum Wants {
    /// Connection wants to read
    Read,
    /// Connection wants to write
    Write,
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

/// A connection that can be shared between tasks
pub struct SharedConn<T> {
    /// The inner connection
    inner: Arc<Mutex<Conn<T>>>,
    /// The current state
    state: Arc<RwLock<State>>,
}

impl<T> SharedConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new shared connection
    pub fn new(io: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Conn::new(io))),
            state: Arc::new(RwLock::new(State::StartLine)),
        }
    }

    /// Send a message on this connection
    pub async fn send_message(&self, message: IcapMessage) -> Result<()> {
        self.inner.lock().send_message(message).await
    }

    /// Receive a message from this connection
    pub async fn recv_message(&self) -> Result<Option<IcapMessage>> {
        self.inner.lock().recv_message().await
    }

    /// Clone this connection
    pub fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            state: Arc::clone(&self.state),
        }
    }
}

/// A service that adapts HTTP requests
pub struct RequestModService<S, T = tokio::net::TcpStream> {
    /// The inner service
    service: S,
    /// Connection pool
    connections: Arc<Mutex<Vec<SharedConn<T>>>>,
    /// Server address to connect to
    addr: String,
}

impl<S> RequestModService<S, tokio::net::TcpStream>
where
    S: IcapService,
{
    /// Create a new request modification service
    pub fn new(service: S) -> Self {
        Self {
            service,
            connections: Arc::new(Mutex::new(Vec::new())),
            addr: "127.0.0.1:1344".to_string(),
        }
    }
}

impl<S, T> RequestModService<S, T>
where
    S: IcapService,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new request modification service with custom connection type
    pub fn with_connection_type(service: S, addr: String) -> Self {
        Self {
            service,
            connections: Arc::new(Mutex::new(Vec::new())),
            addr,
        }
    }

    /// Process an HTTP request through ICAP
    pub async fn process_request(&self, uri: String, headers: HeaderMap) -> Result<IcapMessage> {
        // Create ICAP request
        let request = IcapMessage::Request {
            method: Method::ReqMod,
            uri,
            headers,
            encapsulated: Default::default(),
        };
        
        // Get connection from pool or create new one
        let conn = {
            let mut conns = self.connections.lock();
            if let Some(conn) = conns.pop() {
                
                conn
            } else {
                // Connect to ICAP server - this would be implemented by the specific connection type
                unimplemented!("Connection creation should be implemented by specific type")
            }
        };
        // Send request
        conn.send_message(request).await?;
        
        // Get response
        let response = conn.recv_message().await?
            .ok_or_else(|| Error::Protocol("Incomplete message received".to_string()))?;

        // Return connection to pool
        self.connections.lock().push(conn);

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::pin::Pin;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    struct EchoService;

    impl IcapService for EchoService {
        type Response = IcapMessage;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

        fn call(&self, request: IcapMessage) -> Self::Future {
            Box::pin(async move { Ok(request) })
        }
    }

    // Helper function to setup the test environment
    fn setup_test_service() -> (
        RequestModService<EchoService, tokio::io::DuplexStream>,
        SharedConn<tokio::io::DuplexStream>
    ) {
        println!("Setting up test service...");
        let service = RequestModService::with_connection_type(
            EchoService,
            "test".to_string(),
        );

        // Create mock connection
        let (client, _server) = duplex(1024);
        println!("Created mock connection");
        let conn = SharedConn::new(client);
        service.connections.lock().push(conn.clone());
        
        (service, conn)
    }

    // Helper function to create test headers
    fn create_test_headers() -> HeaderMap {
        println!("Creating test headers...");
        let mut headers = HeaderMap::new();
        headers.insert("Host", "example.com".parse().unwrap());
        headers
    }

    // Helper function to handle server side
    async fn handle_server(mut server: tokio::io::DuplexStream) {
        println!("Server handler started");
        let mut buf = vec![0; 1024];
        match server.read(&mut buf).await {
            Ok(n) => {
                println!("Server received {} bytes", n);
                if let Err(e) = server.write_all(&buf[..n]).await {
                    println!("Server write error: {:?}", e);
                }
            }
            Err(e) => println!("Server read error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_request_mod_service() {
        println!("Starting test_request_mod_service");
        
        // Setup phase
        let (service, _conn) = setup_test_service();
        let headers = create_test_headers();
        
        // Create server handler
        let (_, server) = duplex(1024);
        let server_handle = tokio::spawn(handle_server(server));
        
        // Process request
        println!("Processing request...");
        let response = service
            .process_request("http://example.com".to_string(), headers)
            .await
            .unwrap();
            
        println!("Got response: {:?}", response);
        
        // Wait for server handler
        server_handle.await.unwrap();
        
        // Verify response
        match response {
            IcapMessage::Request { method, uri, .. } => {
                assert_eq!(method, Method::ReqMod);
                assert_eq!(uri, "http://example.com");
            }
            _ => panic!("Expected request"),
        }
    }
}
