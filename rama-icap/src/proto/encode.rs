use bytes::{BufMut, BytesMut};
use crate::{Error, Result};
use crate::proto::IcapMessage;

#[derive(Debug, Clone, Copy)]
pub(crate) enum TransferEncoding {
    ContentLength(usize),
    Chunked,
    Unknown,
}

/// Utility functions for chunk writing
pub(crate) fn write_chunk(dst: &mut BytesMut, len: usize, data: &[u8]) -> Result<()> {
    // Write chunk size
    write!(dst.chunk_mut(), "{:x}\r\n", len).map_err(|e| Error::new_encode(e))?;
    dst.put_slice(data);
    dst.put_slice(b"\r\n");
    Ok(())
}

pub(crate) fn write_final_chunk(dst: &mut BytesMut) -> Result<()> {
    dst.put_slice(b"0\r\n\r\n");
    Ok(())
}

/// 編碼緩衝區
#[derive(Debug)]
pub(crate) struct EncodedBuf<B> {
    buf: BytesMut,
    body: Option<B>,
}

/// ICAP 消息編碼器
pub(crate) struct Encoder {
    state: EncodeState,
}

#[derive(Debug)]
enum EncodeState {
    Start,
    Headers,
    Body,
    Done,
}

impl Encoder {
    /// 創建新的編碼器
    pub(crate) fn new() -> Self {
        Self {
            state: EncodeState::Start,
        }
    }
    
    /// 編碼 ICAP 消息
    pub(crate) fn encode(&mut self, msg: &IcapMessage, dst: &mut BytesMut) -> Result<()> {
        match self.state {
            EncodeState::Start => {
                // 編碼起始行
                self.encode_start_line(msg, dst)?;
                self.state = EncodeState::Headers;
                Ok(())
            }
            EncodeState::Headers => {
                // 編碼頭部
                self.encode_headers(msg, dst)?;
                self.state = EncodeState::Body;
                Ok(())
            }
            EncodeState::Body => {
                // 編碼消息體
                self.encode_body(msg, dst)?;
                self.state = EncodeState::Done;
                Ok(())
            }
            EncodeState::Done => Ok(()),
        }
    }
    
    fn encode_start_line(&self, msg: &IcapMessage, dst: &mut BytesMut) -> Result<()> {
        // 使用現有的 to_bytes 方法編碼起始行
        todo!()
    }
    
    fn encode_headers(&self, msg: &IcapMessage, dst: &mut BytesMut) -> Result<()> {
        // 使用現有的 prepare_headers 方法編碼頭部
        todo!()
    }
    
    fn encode_body(&self, msg: &IcapMessage, dst: &mut BytesMut) -> Result<()> {
        let body = match msg.body() {
            Some(body) => body,
            None => return Ok(()),
        };

        // Determine transfer encoding from headers
        let encoding = if let Some(te) = msg.headers.get("transfer-encoding") {
            if te.as_bytes().eq_ignore_ascii_case(b"chunked") {
                TransferEncoding::Chunked
            } else {
                TransferEncoding::Unknown
            }
        } else if let Some(cl) = msg.headers.get("content-length") {
            let len = cl.to_str()
                .map_err(|e| Error::new_encode(e))?
                .parse::<usize>()
                .map_err(|e| Error::new_encode(e))?;
            TransferEncoding::ContentLength(len)
        } else {
            TransferEncoding::Unknown
        };

        match encoding {
            TransferEncoding::ContentLength(len) => {
                // Convert Content-Length body to a single chunk
                let data = body.as_bytes();
                write_chunk(dst, len, data)?;
                write_final_chunk(dst)?;
            }
            TransferEncoding::Chunked => {
                // Pass through existing chunks
                dst.put_slice(body.as_bytes());
            }
            TransferEncoding::Unknown => {
                // Handle TCP close case - convert each buffer into a chunk
                let data = body.as_bytes();
                let chunk_size = 8192; // Standard chunk size
                
                for chunk in data.chunks(chunk_size) {
                    write_chunk(dst, chunk.len(), chunk)?;
                }
                write_final_chunk(dst)?;
            }
        }
        
        Ok(())
    }
}

impl<B> EncodedBuf<B> {
    /// 創建新的編碼緩衝區
    pub(crate) fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            body: None,
        }
    }
    
    /// 設置消息體
    pub(crate) fn set_body(&mut self, body: B) {
        self.body = Some(body);
    }
    
    /// 獲取緩衝區內容
    pub(crate) fn get_ref(&self) -> &BytesMut {
        &self.buf
    }
    
    /// 獲取可變緩衝區內容
    pub(crate) fn get_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::{Method, Version, HeaderMap};

    #[test]
    fn test_encoded_buf_operations() {
        let mut buf = EncodedBuf::<Body>::new();
        assert!(buf.get_ref().is_empty());
        
        // 測試寫入數據
        buf.get_mut().put_slice(b"ICAP/1.0 200 OK\r\n");
        assert_eq!(buf.get_ref(), b"ICAP/1.0 200 OK\r\n");
        
        // 測試設置消息體
        let body = Body::empty();
        buf.set_body(body);
        assert!(buf.body.is_some());
    }

    #[test]
    fn test_encoder_state_machine() {
        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        
        let msg = IcapMessage::new(Method::OPTIONS, Version::default());
        
        // 測試狀態轉換
        assert!(matches!(encoder.state, EncodeState::Start));
        encoder.encode(&msg, &mut dst).unwrap();
        assert!(matches!(encoder.state, EncodeState::Headers));
        
        encoder.encode(&msg, &mut dst).unwrap();
        assert!(matches!(encoder.state, EncodeState::Body));
        
        encoder.encode(&msg, &mut dst).unwrap();
        assert!(matches!(encoder.state, EncodeState::Done));
    }

    #[test]
    fn test_encode_request_line() {
        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        
        let mut msg = IcapMessage::new(Method::REQMOD, Version::default());
        msg.set_uri("icap://example.org/reqmod".parse().unwrap());
        
        encoder.encode_start_line(&msg, &mut dst).unwrap();
        assert_eq!(dst, b"REQMOD icap://example.org/reqmod ICAP/1.0\r\n");
    }

    #[test]
    fn test_encode_response_line() {
        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        
        let mut msg = IcapMessage::new(Method::OPTIONS, Version::default());
        msg.set_status(200);
        msg.set_reason("OK");
        
        encoder.encode_start_line(&msg, &mut dst).unwrap();
        assert_eq!(dst, b"ICAP/1.0 200 OK\r\n");
    }

    #[test]
    fn test_encode_headers() {
        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        let mut msg = IcapMessage::new(Method::OPTIONS, Version::default());
        
        let mut headers = HeaderMap::new();
        headers.insert("Host", "example.org".parse().unwrap());
        headers.insert("User-Agent", "ICAP-Client/1.0".parse().unwrap());
        msg.headers = headers;
        
        encoder.encode_headers(&msg, &mut dst).unwrap();
        let expected = "Host: example.org\r\nUser-Agent: ICAP-Client/1.0\r\n\r\n";
        assert_eq!(dst, expected.as_bytes());
    }

    #[test]
    fn test_encode_body() {
        let mut encoder = Encoder::new();
        let mut dst = BytesMut::new();
        let mut msg = IcapMessage::new(Method::REQMOD, Version::default());
        
        let body = "Hello, World!";
        msg.set_body(Body::from(body));
        
        encoder.encode_body(&msg, &mut dst).unwrap();
        let expected = format!("{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body);
        assert_eq!(dst, expected.as_bytes());
    }
}