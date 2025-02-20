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

#[derive(Debug)]
enum State {
    Idle,
    ReadingHead,
    ReadingBody,
    WritingHead,
    WritingBody,
    Done,
}

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
                    self.state = State::ReadingHead;
                }
                State::ReadingHead => {
                    if let Poll::Ready(n) = self.io.poll_read(cx)? {
                        if n == 0 {
                            return Poll::Ready(Ok(None));
                        }
                    }

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
                    if let Poll::Ready(n) = self.io.poll_read(cx)? {
                        if n == 0 {
                            return Poll::Ready(Ok(None));
                        }
                    }
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
