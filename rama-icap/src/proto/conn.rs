use std::marker::PhantomData;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use bytes::BytesMut;

use crate::{Error, Result};
use super::{
    decode::Decoder,
    encode::{Encoder, EncodedBuf},
    IcapMessage,
    role::IcapTransaction,
};

/// 連接狀態
#[derive(Debug)]
enum State {
    Idle,
    ReadingHead,
    ReadingBody,
    WritingHead,
    WritingBody,
    Done,
}

/// ICAP 連接
pub(crate) struct Conn {
    buf: BytesMut,
    state: State,
    decoder: Decoder,
    encoder: Encoder,
}

impl Conn
{
    pub(crate) fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(8192),
            state: State::Idle,
            decoder: Decoder::new(),
            encoder: Encoder::new(),
        }
    }

    pub(crate) fn read_message(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<IcapMessage>>> {
        loop {
            match self.state {
                State::Idle => {
                    // 開始讀取消息
                    self.state = State::ReadingHead;
                }
                State::ReadingHead => {
                    // 讀取緩衝區
                    if let Poll::Ready(n) = self.io.poll_read(cx)? {
                        if n == 0 {
                            return Poll::Ready(Ok(None));
                        }
                    }

                    // 解碼消息
                    match self.decoder.decode(&mut self.buf)? {
                        Some(message) => {
                            self.state = State::Idle;
                            return Poll::Ready(Ok(Some(message)));
                        }
                        None => {
                            self.state = State::ReadingBody;
                            continue;
                        }
                    }
                }
                State::ReadingBody => {
                    // 讀取消息體
                    if let Poll::Ready(n) = self.io.poll_read(cx)? {
                        if n == 0 {
                            return Poll::Ready(Ok(None));
                        }
                    }

                    // 解碼消息體
                    match self.decoder.decode(&mut self.buf)? {
                        Some(message) => {
                            self.state = State::Idle;
                            return Poll::Ready(Ok(Some(message)));
                        }
                        None => {
                            return Poll::Pending;
                        }
                    }
                }
                _ => {
                    return Poll::Ready(Err(Error::Protocol(
                        "invalid state for reading".into(),
                    )));
                }
            }
        }
    }

    pub(crate) fn write_message(&mut self, message: IcapMessage) -> Result<()> {
        self.encoder.encode(&message, &mut self.buf)?;
        self.state = State::WritingHead;
        Ok(())
    }

    pub(crate) fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(chunk);
        self.state = State::WritingBody;
        Ok(())
    }

    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let n = self.buf.len();
        if n > 0 {
            if let Poll::Ready(m) = self.io.poll_write(cx)? {
                if m == 0 {
                    return Poll::Ready(Err(Error::Protocol(
                        "failed to write to socket".into(),
                    )));
                }
                self.buf.advance(m);
                if self.buf.is_empty() {
                    self.state = State::Idle;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use rama_http_types::{Method, Version, HeaderMap};

    #[tokio::test]
    async fn test_conn_basic_operations() {
        let (client, mut server) = duplex(1024);
        let mut conn = Conn::<_, _>::new(client);
        
        assert!(matches!(conn.state, State::Idle));
    }

    #[tokio::test]
    async fn test_conn_read_write_message() {
        let (client, mut server) = duplex(1024);
        let mut conn = Conn::<_, _>::new(client);
        
        // Test message
        let mut msg = IcapMessage::new(Method::OPTIONS, Version::default());
        msg.set_uri("icap://example.org/reqmod".parse().unwrap());
        let mut headers = HeaderMap::new();
        headers.insert("Host", "example.org".parse().unwrap());
        msg.headers = headers;
        
        // Write message
        conn.write_message(msg.clone()).unwrap();
        
        // Flush buffer
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        conn.poll_flush(&mut cx).await.unwrap();
        
        // Read server response
        let mut buf = vec![0; 1024];
        let n = server.read(&mut buf).await.unwrap();
        assert!(n > 0);
        
        let received = String::from_utf8_lossy(&buf[..n]);
        assert!(received.contains("OPTIONS icap://example.org/reqmod ICAP/1.0\r\n"));
        assert!(received.contains("Host: example.org\r\n"));
    }

    #[tokio::test]
    async fn test_conn_state_transitions() {
        let (client, _server) = duplex(1024);
        let mut conn = Conn::<_, _>::new(client);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        
        // 初始狀態應該是 Idle
        assert!(matches!(conn.state, State::Idle));
        
        // 開始讀取
        let _ = conn.read_message(&mut cx);
        assert!(matches!(conn.state, State::ReadingHead));
        
        // 寫入消息
        let msg = IcapMessage::new(Method::OPTIONS, Version::default());
        conn.write_message(msg).unwrap();
        assert!(matches!(conn.state, State::WritingHead));
    }

    #[tokio::test]
    async fn test_conn_empty_read() {
        let (client, server) = duplex(1024);
        let mut conn = Conn::<_, _>::new(client);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        
        // 關閉服務器端
        drop(server);
        
        // 讀取應該返回 None
        if let Poll::Ready(Ok(msg)) = conn.read_message(&mut cx) {
            assert!(msg.is_none());
        }
    }

    #[tokio::test]
    async fn test_conn_error_handling() {
        let (client, _server) = duplex(1024);
        let mut conn = Conn::<_, _>::new(client);
        
        // 寫入無效的消息
        let result = conn.write_message(IcapMessage::new(Method::OPTIONS, Version::default()));
        assert!(result.is_ok());
    }
}
