use std::collections::HashMap;
use std::sync::Arc;
use bytes::{BytesMut, BufMut};
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use rama_http_types::{
    Request, Response, HeaderMap, Method as HttpMethod, Version as HttpVersion,
    Body, StatusCode, Uri,
};

use crate::{IcapMessage, Method, Result, SectionType, State, Version, Wants, Encapsulated};

/// A connection to an ICAP server
pub struct Conn<T> {
    io: T,
    state: Arc<RwLock<State>>,
    parser: Arc<Mutex<MessageParser>>,
    write_buf: Arc<Mutex<BytesMut>>,
    read_buf: Arc<Mutex<BytesMut>>,
}

impl<T> Conn<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: T) -> Self {
        Self {
            io,
            state: Arc::new(RwLock::new(State::StartLine)),
            parser: Arc::new(Mutex::new(MessageParser::new())),
            write_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
            read_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
        }
    }

    pub async fn send_message(&mut self, message: IcapMessage) -> Result<()> {
        // Format message into write buffer
        let mut write_buf = self.write_buf.lock();
        write_buf.clear();

        self.build_message(&mut write_buf, &message)?;

        // Write buffer to socket
        self.io.write_all(&write_buf).await?;
        self.io.flush().await?;

        Ok(())
    }

    fn build_message(&self, write_buf: &mut BytesMut, message: &IcapMessage) -> Result<()> {
        match message {
            IcapMessage::Request { method, uri, version, headers, encapsulated } => {
                // Write request line
                write_buf.put_slice(method.as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(uri.as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(version.as_bytes());
                write_buf.put_slice(b"\r\n");

                // Write headers
                for (name, value) in headers.iter() {
                    write_buf.put_slice(name.as_str().as_bytes());
                    write_buf.put_slice(b": ");
                    write_buf.put_slice(value.as_bytes());
                    write_buf.put_slice(b"\r\n");
                }

                // Write encapsulated header
                write_buf.put_slice(b"Encapsulated: ");
                match encapsulated {
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        let mut offset = 0;
                        if let Some(data) = req_header {
                            write_buf.put_slice(b"req-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = req_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"req-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                            offset += data.len();
                        }
                        if let Some(data) = res_header {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-hdr=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                            offset += data.len();
                        }
                        if let Some(data) = res_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::RequestOnly { req_header, req_body } => {
                        let mut offset = 0;
                        if let Some(data) = req_header {
                            write_buf.put_slice(b"req-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = req_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"req-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::ResponseOnly { res_header, res_body } => {
                        let mut offset = 0;
                        if let Some(data) = res_header {
                            write_buf.put_slice(b"res-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = res_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::NullBody => {
                        write_buf.put_slice(b"null-body=0");
                    }
                    Encapsulated::Options { opt_body } => {
                        if let Some(data) = opt_body {
                            write_buf.put_slice(b"opt-body=0");
                        }
                    }
                }
                write_buf.put_slice(b"\r\n");
                write_buf.put_slice(b"\r\n");
            }
            IcapMessage::Response { status, reason, version, headers, encapsulated } => {
                // Write status line
                write_buf.put_slice(format!("ICAP/{:?} {} {}\r\n", version, status, reason).as_bytes());

                // Write headers
                for (name, value) in headers.iter() {
                    write_buf.put_slice(name.as_str().as_bytes());
                    write_buf.put_slice(b": ");
                    write_buf.put_slice(value.as_bytes());
                    write_buf.put_slice(b"\r\n");
                }

                // Write encapsulated header
                write_buf.put_slice(b"Encapsulated: ");
                match encapsulated {
                    Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                        let mut offset = 0;
                        if let Some(data) = req_header {
                            write_buf.put_slice(b"req-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = req_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"req-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                            offset += data.len();
                        }
                        if let Some(data) = res_header {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-hdr=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                            offset += data.len();
                        }
                        if let Some(data) = res_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::RequestOnly { req_header, req_body } => {
                        let mut offset = 0;
                        if let Some(data) = req_header {
                            write_buf.put_slice(b"req-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = req_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"req-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::ResponseOnly { res_header, res_body } => {
                        let mut offset = 0;
                        if let Some(data) = res_header {
                            write_buf.put_slice(b"res-hdr=0");
                            offset += data.len();
                        }
                        if let Some(data) = res_body {
                            if offset > 0 {
                                write_buf.put_slice(b", ");
                            }
                            write_buf.put_slice(b"res-body=");
                            write_buf.put_slice(offset.to_string().as_bytes());
                        }
                    }
                    Encapsulated::NullBody => {
                        write_buf.put_slice(b"null-body=0");
                    }
                    Encapsulated::Options { opt_body } => {
                        if let Some(data) = opt_body {
                            write_buf.put_slice(b"opt-body=0");
                        }
                    }
                }
                write_buf.put_slice(b"\r\n");
                write_buf.put_slice(b"\r\n");
            }
        }
        Ok(())
    }

    fn write_encapsulated(&self, encapsulated: &Encapsulated, write_buf: &mut BytesMut) -> Result<()> {
        write_buf.put_slice(b"Encapsulated: ");
        match encapsulated {
            Encapsulated::RequestOnly { req_header, req_body } => {
                if let Some(header_data) = req_header {
                    write_buf.put_slice(b"req-hdr=0");
                    self.write_request_header(header_data, write_buf)?;
                }
                if let Some(body_data) = req_body {
                    write_buf.put_slice(b", req-body=");
                    write_buf.put_slice(body_data.len().to_string().as_bytes());
                    write_buf.put_slice(body_data);
                }
            }
            Encapsulated::ResponseOnly { res_header, res_body } => {
                if let Some(header_data) = res_header {
                    write_buf.put_slice(b"res-hdr=0");
                    self.write_response_header(header_data, write_buf)?;
                }
                if let Some(body_data) = res_body {
                    write_buf.put_slice(b", res-body=");
                    write_buf.put_slice(body_data.len().to_string().as_bytes());
                    write_buf.put_slice(body_data);
                }
            }
            Encapsulated::RequestResponse { req_header, req_body, res_header, res_body } => {
                if let Some(header_data) = req_header {
                    write_buf.put_slice(b"req-hdr=0");
                    self.write_request_header(header_data, write_buf)?;
                }
                if let Some(body_data) = req_body {
                    write_buf.put_slice(b", req-body=");
                    write_buf.put_slice(body_data.len().to_string().as_bytes());
                    write_buf.put_slice(body_data);
                }
                if let Some(header_data) = res_header {
                    write_buf.put_slice(b", res-hdr=");
                    self.write_response_header(header_data, write_buf)?;
                }
                if let Some(body_data) = res_body {
                    write_buf.put_slice(b", res-body=");
                    write_buf.put_slice(body_data.len().to_string().as_bytes());
                    write_buf.put_slice(body_data);
                }
            }
            Encapsulated::NullBody => {
                write_buf.put_slice(b"null-body=0");
            }
            Encapsulated::Options { opt_body } => {
                if let Some(body_data) = opt_body {
                    write_buf.put_slice(b"opt-body=0");
                    write_buf.put_slice(body_data);
                }
            }
        }
        write_buf.put_slice(b"\r\n");
        Ok(())
    }

    fn write_request_header(&self, header: &Request, write_buf: &mut BytesMut) -> Result<()> {
        write_buf.put_slice(header.method.as_bytes());
        write_buf.put_u8(b' ');
        write_buf.put_slice(header.uri.as_bytes());
        write_buf.put_u8(b' ');
        write_buf.put_slice(header.version.as_bytes());
        write_buf.put_slice(b"\r\n");
        
        for (name, value) in header.headers.iter() {
            write_buf.put_slice(name.as_str().as_bytes());
            write_buf.put_slice(b": ");
            write_buf.put_slice(value.as_bytes());
            write_buf.put_slice(b"\r\n");
        }
        write_buf.put_slice(b"\r\n");
        Ok(())
    }

    fn write_response_header(&self, header: &Response, write_buf: &mut BytesMut) -> Result<()> {
        write_buf.put_slice(format!("HTTP/1.1 {} {}\r\n", header.status, header.reason).as_bytes());
        
        for (name, value) in header.headers.iter() {
            write_buf.put_slice(name.as_str().as_bytes());
            write_buf.put_slice(b": ");
            write_buf.put_slice(value.as_bytes());
            write_buf.put_slice(b"\r\n");
        }
        write_buf.put_slice(b"\r\n");
        Ok(())
    }

    pub async fn recv_message(&mut self) -> Result<Option<IcapMessage>> {
        let mut read_buf = self.read_buf.lock();
        
        // Read from socket into buffer
        let bytes_read = self.io.read(&mut *read_buf).await?;
        if bytes_read == 0 {
            return Ok(None);
        }

        // Parse message from buffer
        let mut parser = self.parser.lock();
        match parser.parse(&read_buf)? {
            Some(message) => Ok(Some(message)),
            None => Ok(None)
        }
    }

    pub fn wants(&self) -> Wants {
        let state = self.state.read();
        match *state {
            State::StartLine | State::Headers | State::Body | State::EncapsulatedHeader => Wants::Read,
            State::Complete => Wants::Write,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::duplex;
    use crate::{Method, Version, SectionType};
    use rama_http_types::{
        Request, Response, HeaderMap, Method as HttpMethod, Version as HttpVersion,
        Body, StatusCode, Uri,
    };

    #[tokio::test]
    async fn test_send_message() -> Result<()> {
        let (client, _server) = tokio::io::duplex(1024);
        let mut conn = Conn::new(client);

        let mut sections = HashMap::new();
        sections.insert(SectionType::RequestHeader, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
        sections.insert(SectionType::RequestBody, b"Hello World!".to_vec());
        
        let encapsulated = Encapsulated::from_sections(sections);
        let message = IcapMessage::Request {
            method: Method::Options,
            uri: "/".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated,
        };

        conn.send_message(message).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_send_receive_request() -> Result<()> {
        let (client, server) = tokio::io::duplex(1024);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        let mut sections = HashMap::new();
        sections.insert(SectionType::RequestHeader, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
        sections.insert(SectionType::RequestBody, b"Hello World!".to_vec());
        
        let encapsulated = Encapsulated::from_sections(sections);
        let request = IcapMessage::Request {
            method: Method::Options,
            uri: "/".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated,
        };

        client_conn.send_message(request).await?;
        
        let received = server_conn.recv_message().await?.unwrap();
        match received {
            IcapMessage::Request { encapsulated, .. } => {
                match encapsulated {
                    Encapsulated::RequestOnly { req_body, .. } => {
                        assert_eq!(req_body.unwrap(), b"Hello World!".to_vec());
                    }
                    _ => panic!("Expected RequestOnly variant"),
                }
            }
            _ => panic!("Expected Request message"),
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_send_receive_response() {
        let (client, server) = duplex(8192);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        // Create test response
        let mut response = IcapMessage::Response {
            version: Version::V1_0,
            status: 200 ,
            reason: "OK".to_string(),
            headers: {
                let mut headers = HeaderMap::new();
                headers.insert("Server", "test-server/1.0".parse().unwrap());
                headers
            },
            encapsulated: Encapsulated::ResponseOnly {
                res_header: Some(Response::default()),
                res_body: Some(b"Hello World!".to_vec().into()),
            },
        };

        // Send response
        server_conn.send_message(response).await.unwrap();

        // Receive response
        let received = client_conn.recv_message().await.unwrap().unwrap();

        // Verify received matches sent
        match received {
            IcapMessage::Response { version, status, reason, headers, encapsulated } => {
                assert_eq!(version, Version::V1_0);
                assert_eq!(status, 200);
                assert_eq!(reason, "OK");
                assert_eq!(headers.get("Server").unwrap(), "test-server/1.0");
                assert!(encapsulated.is_empty());
            }
            _ => panic!("Expected response"),
        }
    }

    #[tokio::test]
    async fn test_send_receive_with_encapsulated() {
        let (client, server) = duplex(8192);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        // Create test request with encapsulated sections
        let mut encapsulated = Vec::new();
        // Add sections in the order they should appear

        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "/modify".to_string(),
            version: Version::V1_0,
            headers: {
                let mut headers = HeaderMap::new();
                headers.insert("Host", "icap-server.net".parse().unwrap());
                headers
            },
            encapsulated: Encapsulated::RequestOnly {
                req_header: {
                    let mut req = Request::builder()
                        .method(HttpMethod::GET)
                        .uri(Uri::from_static("/"))
                        .header("Host", "example.com")
                        .body(Body::empty())
                        .unwrap();
                    Some(req)
                },
                req_body: Some(Body::from("Hello World")),
            },
        };

        // Send request
        client_conn.send_message(request).await.unwrap();

        // Receive request
        let received = server_conn.recv_message().await.unwrap().unwrap();

        // Verify received matches sent
        match received {
            IcapMessage::Request { method, uri, version, headers, encapsulated } => {
                assert_eq!(method, Method::ReqMod);
                assert_eq!(uri, "/modify");
                assert_eq!(version, Version::V1_0);
                assert_eq!(headers.get("Host").unwrap(), "icap-server.net");
                
                // Verify encapsulated sections in order
                assert_eq!(encapsulated.len(), 2);
                assert!(matches!(encapsulated[0].0, SectionType::RequestHeader));
                assert!(matches!(encapsulated[1].0, SectionType::RequestBody));
                assert_eq!(
                    encapsulated[0].1,
                    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                );
                assert_eq!(
                    encapsulated[1].1,
                    b"Hello World"
                );
            }
            _ => panic!("Expected request"),
        }
    }

    #[tokio::test]
    async fn test_connection_state() {
        let (client, _server) = duplex(8192);
        let mut conn = Conn::new(client);

        // Initial state should be StartLine
        assert_eq!(*conn.state.read(), State::StartLine);

        // Create and send a request
        let mut request = IcapMessage::Request {
            method: Method::Options,
            uri: "/echo".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated: HashMap::new(),
        };
        
        conn.send_message(request).await.unwrap();
        
        // After sending, should want to read
        assert!(matches!(conn.wants(), Wants::Read));
    }

    #[tokio::test]
    async fn test_large_message() {
        let (client, server) = duplex(32768);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        // Create a large request body
        let large_body = vec![b'x'; 8192];
        let mut encapsulated = HashMap::new();
        encapsulated.insert(SectionType::RequestBody, large_body.clone());
        
        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "/modify".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated,
        };
        
        // Send request
        client_conn.send_message(request).await.unwrap();

        // Receive request
        let received = server_conn.recv_message().await.unwrap().unwrap();

        // Verify large body was received correctly
        match received {
            IcapMessage::Request { encapsulated, .. } => {
                /* let length = encapsulated.get(&SectionType::RequestBody).unwrap().len();
                let expected_length = large_body.len(); */
                assert_eq!(
                    encapsulated.get(&SectionType::RequestBody).unwrap(),
                    &large_body
                );
            }
            _ => panic!("Expected request"),
        }
    }

    #[tokio::test]
    async fn test_partial_receive() {
        let (client, server) = duplex(8192);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        // Create test request
        let mut request = IcapMessage::Request {
            method: Method::Options,
            uri: "/echo".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated: HashMap::new(),
        };

        // Send request in parts
        client_conn.send_message(request).await.unwrap();

        // First read should return None as message is incomplete
        assert!(server_conn.recv_message().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_parse_request() -> Result<()> {
        let (client, _server) = tokio::io::duplex(1024);
        let mut conn = Conn::new(client);

        let mut sections = HashMap::new();
        sections.insert(SectionType::RequestHeader, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec());
        sections.insert(SectionType::RequestBody, b"Hello World!".to_vec());
        
        let encapsulated = Encapsulated::RequestResponse {
            req_header: Some(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
            req_body: Some(b"Hello World!".to_vec()),
            res_header: None,
            res_body: None,
        };

        let request = IcapMessage::Request {
            method: Method::Options,
            uri: "/".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated,
        };

        assert!(matches!(request, IcapMessage::Request { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_response() -> Result<()> {
        let (client, _server) = tokio::io::duplex(1024);
        let mut conn = Conn::new(client);

        let encapsulated = Encapsulated::RequestResponse {
            req_header: None,
            req_body: None,
            res_header: Some(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n".to_vec()),
            res_body: Some(b"Hello World!".to_vec()),
        };

        let response = IcapMessage::Response {
            status: 200,
            reason: "OK".to_string(),
            version: Version::V1_0,
            headers: HeaderMap::new(),
            encapsulated,
        };

        assert!(matches!(response, IcapMessage::Response { .. }));
        Ok(())
    }
}
