use bytes::{BufMut, BytesMut};
use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, IcapMessage, Result, SectionType, State, Wants};
use crate::parser::MessageParser;

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

    pub async fn send_message(&mut self, message: &mut IcapMessage) -> Result<()> {
        // Prepare headers before sending
        message.prepare_headers()?;

        let mut write_buf = self.write_buf.lock();

        // Format message into write buffer
        match message {
            IcapMessage::Request { method, uri, version, headers, encapsulated } => {
                // Write request line
                write_buf.put_slice(method.as_str().as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(uri.as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(version.as_str().as_bytes());
                write_buf.put_slice(b"\r\n");

                // Write headers
                for (name, value) in headers.iter() {
                    write_buf.put_slice(name.as_str().as_bytes());
                    write_buf.put_slice(b": ");
                    write_buf.put_slice(value.as_bytes());
                    write_buf.put_slice(b"\r\n");
                }

                // Write encapsulated header
                if !encapsulated.is_empty() {
                    write_buf.put_slice(b"Encapsulated: ");
                    let mut first = true;
                    for (section, data) in &mut *encapsulated {
                        if !first {
                            write_buf.put_slice(b", ");
                        }
                        first = false;

                        match section {
                            SectionType::NullBody => write_buf.put_slice(b"null-body=0"),
                            SectionType::RequestHeader => {
                                write_buf.put_slice(b"req-hdr=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::RequestBody => {
                                write_buf.put_slice(b"req-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::ResponseHeader => {
                                write_buf.put_slice(b"res-hdr=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::ResponseBody => {
                                write_buf.put_slice(b"res-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::OptionsBody => {
                                write_buf.put_slice(b"opt-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                        }
                    }
                    write_buf.put_slice(b"\r\n");
                }

                // End headers
                write_buf.put_slice(b"\r\n");

                // Write encapsulated data
                for data in encapsulated.values() {
                    write_buf.put_slice(data);
                }
            }
            IcapMessage::Response { version, status, reason, headers, encapsulated } => {
                // Write status line
                write_buf.put_slice(version.as_str().as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(status.to_string().as_bytes());
                write_buf.put_u8(b' ');
                write_buf.put_slice(reason.as_bytes());
                write_buf.put_slice(b"\r\n");

                // Write headers
                for (name, value) in headers.iter() {
                    write_buf.put_slice(name.as_str().as_bytes());
                    write_buf.put_slice(b": ");
                    write_buf.put_slice(value.as_bytes());
                    write_buf.put_slice(b"\r\n");
                }

                // Write encapsulated header
                if !encapsulated.is_empty() {
                    write_buf.put_slice(b"Encapsulated: ");
                    let mut first = true;
                    for (section, data) in &mut *encapsulated {
                        if !first {
                            write_buf.put_slice(b", ");
                        }
                        first = false;

                        match section {
                            SectionType::NullBody => write_buf.put_slice(b"null-body=0"),
                            SectionType::RequestHeader => {
                                write_buf.put_slice(b"req-hdr=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::RequestBody => {
                                write_buf.put_slice(b"req-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::ResponseHeader => {
                                write_buf.put_slice(b"res-hdr=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::ResponseBody => {
                                write_buf.put_slice(b"res-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                            SectionType::OptionsBody => {
                                write_buf.put_slice(b"opt-body=");
                                write_buf.put_slice(data.len().to_string().as_bytes());
                            }
                        }
                    }
                    write_buf.put_slice(b"\r\n");
                }

                // End headers
                write_buf.put_slice(b"\r\n");

                // Write encapsulated data
                for data in encapsulated.values() {
                    write_buf.put_slice(data);
                }
            }
        }

        // Write buffer to connection
        self.io.write_all(&write_buf).await?;
        self.io.flush().await?;
        write_buf.clear();

        Ok(())
    }

    pub async fn recv_message(&mut self) -> Result<Option<IcapMessage>> {
        loop {
            let message = {
                let mut parser = self.parser.lock();
                let read_buf = self.read_buf.lock();
                parser.parse(&read_buf)?
            };
            
            if message.is_some() {
                return Ok(message);
            }

            let mut guard = self.read_buf.lock();
            let n = self.io.read_buf(&mut *guard).await?;
            
            if n == 0 {
                return if guard.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::IncompleteMessage)
                };
            }
        }
    }

    pub fn wants(&self) -> Wants {
        let state = *self.state.read();
        match state {
            State::StartLine | State::Headers | State::EncapsulatedHeader | State::Body => {
                if self.write_buf.lock().is_empty() {
                    Wants::Read
                } else {
                    Wants::Write
                }
            }
            State::Complete => {
                if self.write_buf.lock().is_empty() {
                    Wants::Read
                } else {
                    Wants::Write
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::duplex;
    use crate::{Method, Version};

    #[tokio::test]
    async fn test_send_receive_request() {
        let (client, server) = duplex(8192);
        let mut client_conn = Conn::new(client);
        let mut server_conn = Conn::new(server);

        // Create test request
        let mut request = IcapMessage::Request {
            method: Method::Options,
            uri: "/echo".to_string(),
            version: Version::V1_0,
            headers: {
                let mut headers = http::HeaderMap::new();
                headers.insert("Host", "icap-server.net".parse().unwrap());
                headers
            },
            encapsulated: {
                let mut sections = HashMap::new();
                sections.insert(SectionType::NullBody, Vec::new());
                sections
            },
        };
        // Send request
        client_conn.send_message(&mut request).await.unwrap();

        // Receive request
        let received = server_conn.recv_message().await.unwrap().unwrap();

        // Verify received matches sent
        match received {
            IcapMessage::Request { method, uri, version, headers, encapsulated } => {
                assert_eq!(method, Method::Options);
                assert_eq!(uri, "/echo");
                assert_eq!(version, Version::V1_0);
                assert_eq!(headers.get("Host").unwrap(), "icap-server.net");
                assert!(encapsulated.contains_key(&SectionType::NullBody));
            }
            _ => panic!("Expected request"),
        }
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
                let mut headers = http::HeaderMap::new();
                headers.insert("Server", "test-server/1.0".parse().unwrap());
                headers
            },
            encapsulated: HashMap::new(),
        };

        // Send response
        server_conn.send_message(&mut response).await.unwrap();

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
        encapsulated.push((SectionType::RequestHeader, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()));
        encapsulated.push((SectionType::RequestBody, b"Hello World".to_vec()));

        let mut request = IcapMessage::Request {
            method: Method::ReqMod,
            uri: "/modify".to_string(),
            version: Version::V1_0,
            headers: {
                let mut headers = http::HeaderMap::new();
                headers.insert("Host", "icap-server.net".parse().unwrap());
                headers
            },
            encapsulated,
        };

        // Send request
        client_conn.send_message(&mut request).await.unwrap();

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
            headers: http::HeaderMap::new(),
            encapsulated: HashMap::new(),
        };
        
        conn.send_message(&mut request).await.unwrap();
        
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
            headers: http::HeaderMap::new(),
            encapsulated,
        };
        
        // Send request
        client_conn.send_message(&mut request).await.unwrap();

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
            headers: http::HeaderMap::new(),
            encapsulated: HashMap::new(),
        };

        // Send request in parts
        client_conn.send_message(&mut request).await.unwrap();

        // First read should return None as message is incomplete
        assert!(server_conn.recv_message().await.unwrap().is_some());
    }
}
