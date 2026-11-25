use std::{
    io,
    pin::Pin,
    str,
    task::{Context, Poll},
};

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::tls::ServerName;
use rama_tls::client::{
    ClientHello, ClientHelloHandshakePrefix, DEFAULT_CLIENT_HELLO_MAX_SIZE,
    client_hello_message_size, extract_sni_from_client_hello_record,
    parse_client_hello_message_prefix,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct ObserveHello<IO> {
    pub(super) io: IO,
    bytes: Vec<u8>,
    header: [u8; 5],
    header_length: usize,
    payload_remaining: usize,
    handshake_record: bool,
    message_size: Option<usize>,
    finished: bool,
}

impl<IO> ObserveHello<IO> {
    pub(super) fn new(io: IO) -> Self {
        Self {
            io,
            bytes: Vec::new(),
            header: [0; 5],
            header_length: 0,
            payload_remaining: 0,
            handshake_record: false,
            message_size: None,
            finished: false,
        }
    }

    pub(super) fn client_hello(&self) -> Option<ClientHello> {
        match parse_client_hello_message_prefix(&self.bytes) {
            ClientHelloHandshakePrefix::Complete(client_hello) => Some(client_hello),
            _ => None,
        }
    }

    pub(super) fn server_name(&self) -> Result<Option<ServerName>, BoxError> {
        let body = self
            .finished
            .then(|| self.bytes.get(4..))
            .flatten()
            .ok_or_else(|| BoxError::from_static_str("incomplete client hello capture"))?;
        extract_sni_from_client_hello_record(body)
            .or_else(|error| accepted_host_name(body).map(Some).ok_or(error))
    }

    fn observe(&mut self, mut input: &[u8]) {
        while !self.finished && !input.is_empty() {
            if self.payload_remaining == 0 {
                let count = (self.header.len() - self.header_length).min(input.len());
                self.header[self.header_length..self.header_length + count]
                    .copy_from_slice(&input[..count]);
                self.header_length += count;
                input = &input[count..];
                if self.header_length == self.header.len() {
                    self.payload_remaining =
                        usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                    self.handshake_record = self.header[0] == 22;
                    self.header_length = 0;
                }
                continue;
            }
            let mut count = self.payload_remaining.min(input.len());
            if self.handshake_record {
                let remaining = self
                    .message_size
                    .unwrap_or(4)
                    .saturating_sub(self.bytes.len());
                count = count.min(remaining);
                self.bytes.extend_from_slice(&input[..count]);
                if let Ok(size) =
                    client_hello_message_size(&self.bytes, DEFAULT_CLIENT_HELLO_MAX_SIZE)
                {
                    self.message_size = size;
                } else {
                    self.bytes.clear();
                    self.finished = true;
                }
                self.finished |= self
                    .message_size
                    .is_some_and(|size| self.bytes.len() == size);
            }
            self.payload_remaining -= count;
            input = &input[count..];
        }
    }
}

fn vector<'a>(input: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
    let (length, rest) = input.split_at_checked(width)?;
    let length = length
        .iter()
        .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
    let (value, rest) = rest.split_at_checked(length)?;
    *input = rest;
    Some(value)
}

// The native acceptor has already accepted the host_name prefix of this list.
fn accepted_host_name(body: &[u8]) -> Option<ServerName> {
    let mut input = body.get(34..)?;
    vector(&mut input, 1)?;
    vector(&mut input, 2)?;
    vector(&mut input, 1)?;
    let mut extensions = vector(&mut input, 2)?;
    while !extensions.is_empty() {
        let (kind, rest) = extensions.split_at_checked(2)?;
        extensions = rest;
        let data = vector(&mut extensions, 2)?;
        if kind == [0, 0] {
            let mut data = data;
            let names = vector(&mut data, 2)?;
            let (&kind, mut name) = names.split_first()?;
            if kind != 0 {
                return None;
            }
            return ServerName::parse(str::from_utf8(vector(&mut name, 2)?).ok()?);
        }
    }
    None
}

impl<IO: AsyncRead + Unpin> AsyncRead for ObserveHello<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(()))) {
            this.observe(&buf.filled()[filled..]);
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ObserveHello<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod reassembly_tests {
    use rama_utils::octets::kib;
    use tokio::io::AsyncReadExt as _;

    use super::*;

    struct Chunked<'a> {
        bytes: &'a [u8],
        limit: usize,
    }

    impl AsyncRead for Chunked<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let count = this.limit.min(this.bytes.len()).min(buf.remaining());
            buf.put_slice(&this.bytes[..count]);
            this.bytes = &this.bytes[count..];
            Poll::Ready(Ok(()))
        }
    }

    fn hello() -> Vec<u8> {
        let name = b"2001:db8::1";
        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&u16::try_from(name.len() + 5).unwrap().to_be_bytes());
        extensions.extend_from_slice(&u16::try_from(name.len() + 3).unwrap().to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        extensions.extend_from_slice(name);
        extensions.extend_from_slice(&[0, 21]);
        extensions.extend_from_slice(&u16::try_from(kib(1)).unwrap().to_be_bytes());
        extensions.resize(extensions.len() + kib(1), 0);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0xc0, 0x2f, 1, 0]);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut message = vec![1];
        message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    #[tokio::test]
    async fn record_fragmentation_preserves_observed_ip_and_forwarded_bytes() {
        let message = hello();
        for fragmented in [false, true] {
            let mut records = Vec::new();
            let chunks = if fragmented { 1 } else { message.len() };
            for bytes in message.chunks(chunks) {
                records.extend_from_slice(&[22, 3, 3]);
                records.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
                records.extend_from_slice(bytes);
            }
            for limit in [1, 2, 5, 17, records.len()] {
                let mut reader = ObserveHello::new(Chunked {
                    bytes: &records,
                    limit,
                });
                let mut forwarded = Vec::new();
                reader.read_to_end(&mut forwarded).await.unwrap();
                assert_eq!(forwarded, records);
                let hello = reader.client_hello().unwrap();
                assert_eq!(
                    hello.ext_server_name(),
                    Some(&"2001:db8::1".parse::<ServerName>().unwrap())
                );
                assert!(hello.ext_server_domain().is_none());
            }
        }
    }

    #[test]
    fn sni_scanning_does_not_require_a_complete_observation() {
        let mut message = hello();
        let mut body = message[4..].to_vec();
        let extra = [0, 10, 0, 1, 0];
        let extensions =
            u16::from_be_bytes([body[41], body[42]]) + u16::try_from(extra.len()).unwrap();
        body[41..43].copy_from_slice(&extensions.to_be_bytes());
        body.extend_from_slice(&extra);
        message.truncate(1);
        message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        let mut records = vec![22, 3, 3];
        records.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
        records.extend_from_slice(&message);
        let mut observer = ObserveHello::new(());
        observer.observe(&records);
        assert!(observer.client_hello().is_none());
        assert_eq!(
            observer.server_name().unwrap(),
            ServerName::parse("2001:db8::1")
        );
    }
}
