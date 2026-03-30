use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::Instant,
};

/// Result of a [`peek_input_until`] call.
///
/// `peek_size` reports how many bytes were copied into the caller-provided
/// buffer before peeking stopped. `data` is only populated when the predicate
/// matched those bytes.
#[derive(Debug)]
pub struct PeekOutput<D> {
    pub data: Option<D>,
    pub peek_size: usize,
}

#[inline(always)]
/// Read into `buffer` until `predicate` matches, peeking stops, or the optional
/// `timeout` expires.
///
/// This helper is intended for protocol sniffing and similar cases where a
/// caller needs to inspect a small prefix without committing to a full parser.
///
/// Peeking stops when one of the following happens:
/// - `predicate` returns `Some(_)`;
/// - the reader returns EOF;
/// - the reader returns an error;
/// - the optional timeout elapses;
/// - the internal read-attempt budget is exhausted.
///
/// The attempt budget is capped at `max(buffer.len() / 4, 1) + 1` reads. This keeps
/// peeking bounded even for slow or fragmented inputs, but it also means this
/// function can return partial data before the buffer is full.
pub fn peek_input_until<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    timeout: Option<Duration>,
    predicate: P,
) -> impl Future<Output = PeekOutput<O>>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> Option<O>,
{
    peek_input_until_with_offset(reader, buffer, 0, timeout, predicate)
}

/// Same as [`peek_input_until`] but with a starting offset as peek-size.
///
/// It is assumed that the offst is within the buffer boundaries,
/// but it will be clamped to the `buffer.len()` regardless.
pub async fn peek_input_until_with_offset<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    offset: usize,
    timeout: Option<Duration>,
    predicate: P,
) -> PeekOutput<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> Option<O>,
{
    let mut output = PeekOutput {
        data: None,
        peek_size: offset.min(buffer.len()),
    };

    if buffer[output.peek_size..].is_empty() {
        return output;
    }

    let peek_deadline = timeout.map(|d| Instant::now() + d);

    let max_attempts = buffer.len().saturating_div(4).max(1) + 1;
    for _ in 0..max_attempts {
        let read_fut = reader.read(&mut buffer[output.peek_size..]);

        let n = match peek_deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    tracing::debug!("I/O peek: abort: deadline reached");
                    return output;
                }

                let remaining = deadline - now;
                match tokio::time::timeout(remaining, read_fut).await {
                    Err(err) => {
                        tracing::debug!("I/O peek: time-fenced peek read timeout error: {err}");
                        return output;
                    }
                    Ok(Err(err)) => {
                        tracing::debug!("I/O peek: time-fenced peek read error: {err}");
                        return output;
                    }
                    Ok(Ok(n)) => n,
                }
            }
            None => match read_fut.await {
                Err(err) => {
                    tracing::debug!("I/O peek: peek read error: {err}");
                    return output;
                }
                Ok(n) => n,
            },
        };

        if n == 0 {
            tracing::trace!("I/O peek: break loop: no new data read...");
            return output;
        }

        output.peek_size = (output.peek_size + n).min(buffer.len());

        if let Some(data) = predicate(&buffer[..output.peek_size]) {
            output.data = Some(data);
            tracing::trace!("I/O peek: data found using predicate: return it...");
            return output;
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::ReadBuf;

    #[tokio::test]
    async fn returns_immediately_for_empty_buffer() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = [];

        let output =
            peek_input_until::<_, (), _>(&mut reader, &mut buffer, None, |_| unreachable!()).await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
    }

    #[tokio::test]
    async fn returns_data_when_predicate_matches_on_first_read() {
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some("hello")
        })
        .await;

        assert_eq!(output.data, Some("hello"));
        assert_eq!(output.peek_size, 5);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn accumulates_across_multiple_reads_until_predicate_matches() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(buf.len())
        })
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_hits_eof_before_match() {
        let mut reader = tokio_test::io::Builder::new().read(b"he").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_errors_after_progress() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_no_data_when_first_read_errors() {
        let mut reader = tokio_test::io::Builder::new()
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (!buf.is_empty()).then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
    }

    #[tokio::test]
    async fn timeout_returns_partial_bytes_already_peeked() {
        let mut reader = TwoPhaseReader {
            first_chunk: Some(b"he".to_vec()),
            sleep: Some(Box::pin(tokio::time::sleep(Duration::from_millis(50)))),
        };
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(
            &mut reader,
            &mut buffer,
            Some(Duration::from_millis(10)),
            |buf| (buf == b"hello").then_some(()),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn stops_when_attempt_budget_is_exhausted() {
        let mut reader = tokio_test::io::Builder::new().read(b"h").read(b"e").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hel").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    struct TwoPhaseReader {
        first_chunk: Option<Vec<u8>>,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncRead for TwoPhaseReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.first_chunk.take() {
                buf.put_slice(&chunk[..chunk.len().min(buf.remaining())]);
                return Poll::Ready(Ok(()));
            }

            match self.sleep.as_mut() {
                Some(sleep) => sleep.as_mut().poll(cx).map(|_| Ok(())),
                None => Poll::Ready(Ok(())),
            }
        }
    }
}
