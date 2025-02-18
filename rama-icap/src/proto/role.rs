// clients, server

use bytes::BytesMut;
use rama_http_types::{HeaderMap, Method, StatusCode};
use crate::{Error, Result, IcapMessage};
use crate::Method as IcapMethod;

//------------------------------------------------------------------------------
// Protocol Role Trait
//------------------------------------------------------------------------------
/// ICAP 交易特徵
pub(crate) trait IcapTransaction {
    type Incoming;
    type Outgoing: Default;
    
    /// 解析 ICAP 消息
    fn parse(bytes: &mut BytesMut) -> Result<Self::Incoming>;
    
    /// 編碼 ICAP 消息
    fn encode(msg: &IcapMessage) -> Result<Vec<u8>>;
    
    /// 處理錯誤情況
    fn on_error(err: &Error) -> Option<Self::Outgoing>;

    /// 處理不同的傳輸編碼
    fn handle_transfer_encoding(headers: &HeaderMap, data: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(te) = headers.get("transfer-encoding") {
            if te.as_bytes().eq_ignore_ascii_case(b"chunked") {
                // Already chunked, pass through
                Ok(data)
            } else {
                // Unknown encoding, chunk the data
                Self::handle_unknown_encoding(data)
            }
        } else if let Some(cl) = headers.get("content-length") {
            // Convert Content-Length to chunked
            let len = cl.to_str()
                .map_err(|e| Error::new_encode(e))?
                .parse::<usize>()
                .map_err(|e| Error::new_encode(e))?;
            Self::handle_content_length(len, data)
        } else {
            // No encoding specified, assume TCP close
            Self::handle_unknown_encoding(data)
        }
    }

    /// 處理 Content-Length 編碼
    fn handle_content_length(len: usize, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        write!(buf.chunk_mut(), "{:x}\r\n", len).map_err(|e| Error::new_encode(e))?;
        buf.put_slice(&data);
        buf.put_slice(b"\r\n0\r\n\r\n");
        Ok(buf.freeze().to_vec())
    }

    /// 處理未知編碼（TCP close 情況）
    fn handle_unknown_encoding(data: Vec<u8>) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        let chunk_size = 8192; // Standard chunk size
        
        for chunk in data.chunks(chunk_size) {
            write!(buf.chunk_mut(), "{:x}\r\n", chunk.len()).map_err(|e| Error::new_encode(e))?;
            buf.put_slice(chunk);
            buf.put_slice(b"\r\n");
        }
        buf.put_slice(b"0\r\n\r\n");
        Ok(buf.freeze().to_vec())
    }
}

//------------------------------------------------------------------------------
// Client Implementation
//------------------------------------------------------------------------------

// 客戶端實現
impl IcapTransaction for Client {
    type Incoming = StatusCode;
    type Outgoing = Method;
    
    fn parse(bytes: &mut BytesMut) -> Result<Self::Incoming> {
        // 使用現有的 MessageParser 解析響應
        todo!()
    }
    
    fn encode(msg: &IcapMessage) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        let mut buf = BytesMut::new();
        
        encoder.encode(msg, &mut buf)?;
        
        // Handle body transfer encoding if present
        if let Some(body) = msg.body() {
            let encoded_body = Self::handle_transfer_encoding(msg.headers(), body.as_bytes().to_vec())?;
            buf.put_slice(&encoded_body);
        }
        
        Ok(buf.freeze().to_vec())
    }
    
    fn on_error(err: &Error) -> Option<Self::Outgoing> {
        None
    }
}

//------------------------------------------------------------------------------
// Server Implementation
//------------------------------------------------------------------------------

// 服務器實現
impl IcapTransaction for Server {
    type Incoming = Method;
    type Outgoing = StatusCode;
    
    fn parse(bytes: &mut BytesMut) -> Result<Self::Incoming> {
        // 使用現有的 MessageParser 解析請求
        todo!()
    }
    
    fn encode(msg: &IcapMessage) -> Result<Vec<u8>> {
        // 使用現有的 encode 邏輯編碼響應
        todo!()
    }
    
    fn on_error(err: &Error) -> Option<Self::Outgoing> {
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

//------------------------------------------------------------------------------
// Client Configuration
//------------------------------------------------------------------------------

use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum number of idle connections
    pub max_idle_conns: usize,
    /// Timeout for idle connections
    pub idle_timeout: Duration,
    /// Maximum number of connections per host
    pub max_conns_per_host: usize,
    /// Connection timeout
    pub dial_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_idle_conns: 100,
            idle_timeout: Duration::from_secs(90),
            max_conns_per_host: 10,
            dial_timeout: Duration::from_secs(30),
        }
    }
}

//------------------------------------------------------------------------------
// Client
//------------------------------------------------------------------------------

#[derive(Debug)]
pub struct Client {
    config: ClientConfig,
    transport: Transport,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            transport: Transport::new(&config),
            config,
        }
    }

    pub async fn request(&self, req: Request) -> Result<Response, Error> {
        self.transport.send_request(req).await
    }

    pub async fn options(&self, url: Url) -> Result<Response, Error> {
        let req = Request::new(IcapMethod::Options, url);
        self.request(req).await
    }

    pub async fn reqmod(&self, url: Url, http_req: Vec<u8>) -> Result<Response, Error> {
        let mut req = Request::new(IcapMethod::ReqMod, url);
        req.set_http_request(http_req);
        self.request(req).await
    }

    pub async fn respmod(&self, url: Url, http_resp: Vec<u8>) -> Result<Response, Error> {
        let mut req = Request::new(IcapMethod::RespMod, url);
        req.set_http_response(http_resp);
        self.request(req).await
    }
}

//------------------------------------------------------------------------------
// Test Server
//------------------------------------------------------------------------------

use std::net::TcpListener;
use std::sync::Once;

static START: Once = Once::new();
const TEST_SERVER_ADDR: &str = "127.0.0.1:1344";

pub(crate) async fn start_test_server() {
    START.call_once(|| {
        tokio::spawn(async {
            let listener = TcpListener::bind(TEST_SERVER_ADDR).unwrap();
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    tokio::spawn(async move {
                        let mut buf = [0; 1024];
                        if let Ok(n) = stream.read(&mut buf).await {
                            let request = String::from_utf8_lossy(&buf[..n]);
                            
                            // Handle OPTIONS request
                            if request.contains("OPTIONS") {
                                let response = "ICAP/1.0 200 OK\r\n\
                                    Methods: RESPMOD, REQMOD\r\n\
                                    Service: Rust ICAP Server\r\n\
                                    ISTag: RISV-01\r\n\
                                    Encapsulated: null-body=0\r\n\
                                    \r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                            
                            // Handle REQMOD request
                            else if request.contains("REQMOD") {
                                let response = "ICAP/1.0 200 OK\r\n\
                                    ISTag: RISV-01\r\n\
                                    Encapsulated: req-hdr=0, null-body=170\r\n\
                                    \r\n\
                                    GET / HTTP/1.1\r\n\
                                    Host: www.example.com\r\n\
                                    User-Agent: Mozilla/5.0\r\n\
                                    \r\n";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                            
                            // Handle RESPMOD request
                            else if request.contains("RESPMOD") {
                                let response = "ICAP/1.0 200 OK\r\n\
                                    ISTag: RISV-01\r\n\
                                    Encapsulated: res-hdr=0, res-body=145\r\n\
                                    \r\n\
                                    HTTP/1.1 200 OK\r\n\
                                    Content-Type: text/plain\r\n\
                                    Content-Length: 19\r\n\
                                    \r\n\
                                    This is a GOOD FILE";
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                        }
                    });
                }
            }
        });
    });
}

//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use url::Url;

    #[tokio::test]
    async fn test_client_options() {
        start_test_server().await;

        let config = ClientConfig::default();
        let client = Client::new(config);

        let url = Url::parse("icap://127.0.0.1:1344/options").unwrap();
        let response = client.options(url).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("Methods"));
        assert!(response.headers().contains_key("ISTag"));
        assert!(response.headers().contains_key("Service"));
    }

    #[tokio::test]
    async fn test_client_reqmod() {
        start_test_server().await;

        let config = ClientConfig::default();
        let client = Client::new(config);

        let url = Url::parse("icap://127.0.0.1:1344/reqmod").unwrap();
        let http_req = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".to_vec();
        let response = client.reqmod(url, http_req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("ISTag"));
        assert!(response.http_request().is_some());
    }

    #[tokio::test]
    async fn test_client_respmod() {
        start_test_server().await;

        let config = ClientConfig::default();
        let client = Client::new(config);

        let url = Url::parse("icap://127.0.0.1:1344/respmod").unwrap();
        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOriginal content".to_vec();
        let response = client.respmod(url, http_resp).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("ISTag"));
        assert!(response.http_response().is_some());
        
        if let Some(body) = response.body() {
            assert_eq!(body.content, "This is a GOOD FILE");
        }
    }

    #[tokio::test]
    async fn test_client_config() {
        let config = ClientConfig {
            max_idle_conns: 50,
            idle_timeout: Duration::from_secs(60),
            max_conns_per_host: 5,
            dial_timeout: Duration::from_secs(10),
        };

        let client = Client::new(config.clone());
        assert_eq!(client.config.max_idle_conns, 50);
        assert_eq!(client.config.idle_timeout.as_secs(), 60);
        assert_eq!(client.config.max_conns_per_host, 5);
        assert_eq!(client.config.dial_timeout.as_secs(), 10);
    }
}
