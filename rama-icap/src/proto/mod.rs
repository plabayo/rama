mod conn;

use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use parking_lot::{Mutex, RwLock};
use rama_http_types::HeaderMap;

use crate::{Error, IcapMessage, Method, Result, State, Version};
pub use self::conn::Conn;

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
    pub async fn send_message(&self, message: &mut IcapMessage) -> Result<()> {
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
        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri,
            version: Version::V1_0,
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
        conn.send_message(&mut request).await?;
        
        // Get response
        let mut response = conn.recv_message().await?
            .ok_or_else(|| Error::IncompleteMessage)?;

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
