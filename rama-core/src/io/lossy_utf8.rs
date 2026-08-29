use core::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

/// Incremental lossy UTF-8 adapter for asynchronous buffered byte streams.
///
/// Invalid sequences become U+FFFD, including an incomplete sequence at EOF.
/// Valid input is exposed directly from the inner reader without copying.
/// Scratch capacity is retained when invalid or split sequences require a
/// transformed buffer.
#[derive(Debug)]
pub struct LossyUtf8Reader<R> {
    inner: R,
    output: Vec<u8>,
    output_offset: usize,
    pending: Vec<u8>,
    combined: Vec<u8>,
    direct_remaining: usize,
    eof: bool,
}

impl<R> LossyUtf8Reader<R> {
    /// Wrap an asynchronous buffered byte reader.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            output: Vec::new(),
            output_offset: 0,
            pending: Vec::with_capacity(4),
            combined: Vec::new(),
            direct_remaining: 0,
            eof: false,
        }
    }

    /// Borrow the wrapped reader.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutably borrow the wrapped reader.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Consume the adapter and return the wrapped reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

fn fill_output(bytes: &[u8], output: &mut Vec<u8>, pending: &mut Vec<u8>, combined: &mut Vec<u8>) {
    output.clear();
    if pending.is_empty() {
        decode_lossy(bytes, output, pending);
        return;
    }

    combined.clear();
    combined.extend_from_slice(pending);
    pending.clear();
    combined.extend_from_slice(bytes);
    decode_lossy(combined, output, pending);
}

enum BufferSource {
    Output,
    Inner,
    Eof,
}

impl<R> LossyUtf8Reader<R>
where
    R: AsyncBufRead + Unpin,
{
    fn poll_prepare(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<BufferSource>> {
        loop {
            if self.output_offset < self.output.len() {
                return Poll::Ready(Ok(BufferSource::Output));
            }
            if self.direct_remaining != 0 {
                return Poll::Ready(Ok(BufferSource::Inner));
            }
            if self.eof {
                if self.pending.is_empty() {
                    return Poll::Ready(Ok(BufferSource::Eof));
                }
                self.pending.clear();
                self.output.clear();
                self.output.extend_from_slice("\u{fffd}".as_bytes());
                return Poll::Ready(Ok(BufferSource::Output));
            }

            let Self {
                inner,
                output,
                pending,
                combined,
                direct_remaining,
                eof,
                ..
            } = self;
            let bytes = match Pin::new(&mut *inner).poll_fill_buf(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(bytes)) => bytes,
            };
            if bytes.is_empty() {
                *eof = true;
                continue;
            }
            if pending.is_empty() && core::str::from_utf8(bytes).is_ok() {
                *direct_remaining = bytes.len();
                return Poll::Ready(Ok(BufferSource::Inner));
            }

            let consumed = bytes.len();
            fill_output(bytes, output, pending, combined);
            Pin::new(inner).consume(consumed);
        }
    }
}

fn decode_lossy(input: &[u8], output: &mut Vec<u8>, pending: &mut Vec<u8>) {
    let mut remaining = input;
    loop {
        match core::str::from_utf8(remaining) {
            Ok(_) => {
                output.extend_from_slice(remaining);
                return;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                output.extend_from_slice(&remaining[..valid]);
                if let Some(invalid) = error.error_len() {
                    output.extend_from_slice("\u{fffd}".as_bytes());
                    remaining = &remaining[valid + invalid..];
                } else {
                    pending.extend_from_slice(&remaining[valid..]);
                    return;
                }
            }
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<R> AsyncBufRead for LossyUtf8Reader<R>
where
    R: AsyncBufRead + Unpin,
{
    fn poll_fill_buf(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        match self.as_mut().get_mut().poll_prepare(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(BufferSource::Output)) => {
                let this = self.get_mut();
                Poll::Ready(Ok(&this.output[this.output_offset..]))
            }
            Poll::Ready(Ok(BufferSource::Inner)) => {
                let this = self.get_mut();
                match Pin::new(&mut this.inner).poll_fill_buf(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(bytes)) => {
                        Poll::Ready(Ok(&bytes[..this.direct_remaining.min(bytes.len())]))
                    }
                }
            }
            Poll::Ready(Ok(BufferSource::Eof)) => Poll::Ready(Ok(&[])),
        }
    }

    fn consume(mut self: Pin<&mut Self>, amount: usize) {
        let this = self.as_mut().get_mut();
        if this.output_offset < this.output.len() {
            this.output_offset = (this.output_offset + amount).min(this.output.len());
            if this.output_offset == this.output.len() {
                this.output.clear();
                this.output_offset = 0;
            }
        } else {
            let consumed = amount.min(this.direct_remaining);
            this.direct_remaining -= consumed;
            Pin::new(&mut this.inner).consume(consumed);
        }
    }
}

impl<R> AsyncRead for LossyUtf8Reader<R>
where
    R: AsyncBufRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let count = match self.as_mut().poll_fill_buf(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(bytes)) => {
                let count = output.remaining().min(bytes.len());
                output.put_slice(&bytes[..count]);
                count
            }
        };
        self.consume(count);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);

    struct GrowingBuffer {
        bytes: [u8; 3],
        consumed: usize,
        fills: usize,
    }

    impl AsyncRead for GrowingBuffer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let count = output.remaining().min(self.bytes.len() - self.consumed);
            output.put_slice(&self.bytes[self.consumed..self.consumed + count]);
            self.consumed += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncBufRead for GrowingBuffer {
        fn poll_fill_buf(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<&[u8]>> {
            self.fills += 1;
            let exposed = if self.fills == 1 { 1 } else { self.bytes.len() };
            let this = self.get_mut();
            Poll::Ready(Ok(&this.bytes[this.consumed..exposed]))
        }

        fn consume(mut self: Pin<&mut Self>, amount: usize) {
            self.consumed += amount;
        }
    }

    #[tokio::test]
    async fn exposes_valid_input_without_copying() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let bytes = b"already valid".as_slice();
            let source_pointer = bytes.as_ptr();
            let mut reader = LossyUtf8Reader::new(bytes);

            let decoded = reader.fill_buf().await.unwrap();

            assert_eq!(decoded, b"already valid");
            assert_eq!(decoded.as_ptr(), source_pointer);
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn partial_consume_keeps_the_validated_inner_buffer() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let bytes = "\u{1f4a9}".as_bytes();
            let mut reader = LossyUtf8Reader::new(bytes);
            assert_eq!(reader.fill_buf().await.unwrap(), bytes);

            Pin::new(&mut reader).consume(1);

            assert_eq!(reader.fill_buf().await.unwrap(), &bytes[1..]);
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn direct_path_does_not_expose_a_grown_unvalidated_suffix() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let inner = GrowingBuffer {
                bytes: [b'A', 0xff, b'B'],
                consumed: 0,
                fills: 0,
            };
            let mut reader = LossyUtf8Reader::new(inner);
            let mut decoded = String::new();

            reader.read_to_string(&mut decoded).await.unwrap();

            assert_eq!(decoded, "A\u{fffd}B");
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn replaces_invalid_and_truncated_sequences() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let bytes = b"valid\xf0\x9f\x92\xa9\xfftail\xe2\x82".as_slice();
            let mut reader = LossyUtf8Reader::new(bytes);
            let mut decoded = String::new();
            reader.read_to_string(&mut decoded).await.unwrap();
            assert_eq!(decoded, "valid\u{1f4a9}\u{fffd}tail\u{fffd}");
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn joins_valid_sequences_split_across_inner_buffers() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let bytes = "a\u{1f4a9}b".as_bytes();
            let inner = BufReader::with_capacity(1, bytes);
            let mut reader = LossyUtf8Reader::new(inner);
            let mut decoded = String::new();

            reader.read_to_string(&mut decoded).await.unwrap();

            assert_eq!(decoded, "a\u{1f4a9}b");
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn handles_output_buffers_smaller_than_a_replacement() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let mut reader = LossyUtf8Reader::new(b"\xff".as_slice());
            let mut decoded = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                let count = reader.read(&mut byte).await.unwrap();
                if count == 0 {
                    break;
                }
                decoded.push(byte[0]);
            }
            assert_eq!(decoded, "\u{fffd}".as_bytes());
        })
        .await
        .expect("lossy UTF-8 reader made no progress");
    }

    #[tokio::test]
    async fn matches_the_standard_lossy_decoder_across_buffer_boundaries() {
        let inputs: &[&[u8]] = &[
            b"plain ascii",
            b"a\xf0\x9f\x92\xa9b",
            b"a\xf0\x9f\xffb",
            b"a\xe2\x82b\xffc",
            b"\xf0\x9f\x92",
            b"\x80\xbfvalid\xc0\xaf",
        ];
        for input in inputs {
            for capacity in 1..=8 {
                let inner = BufReader::with_capacity(capacity, *input);
                let mut reader = LossyUtf8Reader::new(inner);
                let mut actual = String::new();
                reader.read_to_string(&mut actual).await.unwrap();
                assert_eq!(
                    actual,
                    String::from_utf8_lossy(input),
                    "input: {input:?}, capacity: {capacity}",
                );
            }
        }
    }
}
