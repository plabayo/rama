//! Line-based WebSocket client for non-interactive use (scripts, pipes and tests).

use parking_lot::Mutex;
use rama::{
    error::{BoxError, BoxErrorExt as _},
    futures::{SinkExt as _, StreamExt as _},
    http::ws::{
        Message, ProtocolError, WebSocketIo,
        handshake::client::ClientWebSocket,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use std::{
    io::{self, BufRead as _},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt as _,
    sync::mpsc,
    time::{Instant, sleep},
};

/// Lines buffered between stdin and the socket.
const PENDING_LINES: usize = 16;

/// How long a peer has to complete the close handshake once our Close went out.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Send each stdin line as a text message and print every received message.
///
/// Both directions run concurrently, so a send waiting on flow control never stops
/// receiving. End of input starts the close handshake; the command ends once the peer's
/// close completed and the stream ended, whatever state stdin is in, or fails when the
/// peer leaves it unanswered. Unreadable input closes with an error status and fails the
/// command.
pub(super) async fn run<S: WebSocketIo>(socket: ClientWebSocket<S>) -> Result<(), BoxError> {
    // A blocking stdin read cannot be cancelled: keep it off the runtime, so a pending
    // read never delays the exit.
    let (lines_tx, lines) = mpsc::channel(PENDING_LINES);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let failed = line.is_err();
            if lines_tx.blocking_send(line).is_err() || failed {
                break;
            }
        }
    });
    pump(socket, lines).await
}

/// Exchange `lines` and received messages over `socket` until it closed.
async fn pump<S: WebSocketIo>(
    socket: ClientWebSocket<S>,
    mut lines: mpsc::Receiver<io::Result<String>>,
) -> Result<(), BoxError> {
    let (mut sink, mut stream) = socket.split();
    // Kept where either branch sees it: the peer may finish the close before our Close is
    // flushed, and an input error must still fail the command then.
    let input_error = Mutex::new(None);

    let send = async {
        while let Some(line) = lines.recv().await {
            match line {
                Ok(line) => sink.send(Message::text(line)).await?,
                Err(error) => {
                    *input_error.lock() = Some(error);
                    let close = CloseFrame {
                        code: CloseCode::Error,
                        reason: "unreadable input".into(),
                    };
                    return sink.send(Message::Close(Some(close))).await;
                }
            }
        }
        sink.send(Message::Close(None)).await
    };
    let receive = async {
        let mut stdout = tokio::io::stdout();
        // Keep reading after a close: that sends our reply and ends the transport.
        while let Some(message) = stream.next().await.transpose()? {
            match message {
                Message::Text(text) => {
                    stdout.write_all(text.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
                Message::Binary(data) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                _ => (),
            }
        }
        Ok::<_, BoxError>(())
    };

    let closing = sleep(CLOSE_TIMEOUT);
    tokio::pin!(send, receive, closing);
    let mut sending = true;
    loop {
        tokio::select! {
            result = &mut send, if sending => {
                sending = false;
                closing.as_mut().reset(Instant::now() + CLOSE_TIMEOUT);
                match result {
                    // The peer started closing first: nothing more may be sent.
                    Ok(()) | Err(ProtocolError::SendAfterClosing) => (),
                    Err(error) if error.is_connection_error() => (),
                    Err(error) => return Err(error.into()),
                }
            }
            result = &mut receive => {
                result?;
                return input_error.lock().take().map_or(Ok(()), |error| Err(error.into()));
            }
            () = &mut closing, if !sending => {
                return Err(BoxError::from_static_str(
                    "the peer did not complete the WebSocket close handshake",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        ServiceInput,
        http::{
            Body, Response,
            ws::{AsyncWebSocket, protocol::Role},
        },
    };
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Default)]
    struct Wire {
        written: Vec<u8>,
        peer_closed: bool,
        pending_flushes: usize,
        shutdowns: usize,
        reader: Option<Waker>,
    }

    /// Written bytes reach the peer at once, but flushing waits until the peer's Close and
    /// EOF are readable: the peer finishes the close before our flush does.
    struct CloseBeforeFlush(Arc<Mutex<Wire>>);

    impl AsyncRead for CloseBeforeFlush {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut wire = self.0.lock();
            if wire.written.is_empty() {
                wire.reader = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if !wire.peer_closed {
                buf.put_slice(&[0x88, 2, 0x03, 0xe8]);
                wire.peer_closed = true;
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CloseBeforeFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut wire = self.0.lock();
            wire.written.extend_from_slice(bytes);
            if let Some(reader) = wire.reader.take() {
                reader.wake();
            }
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut wire = self.0.lock();
            if wire.peer_closed {
                return Poll::Ready(Ok(()));
            }
            wire.pending_flushes += 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut wire = self.0.lock();
            if !wire.peer_closed {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            wire.shutdowns += 1;
            Poll::Ready(Ok(()))
        }
    }

    /// A peer that never answers our Close cannot hold the command forever.
    #[tokio::test(start_paused = true)]
    async fn an_unanswered_close_ends_the_command_with_an_error() {
        let (client, _silent_peer) = tokio::io::duplex(1024);
        let socket =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(client), Role::Client, None).await;
        let (response, _) = Response::new(Body::empty()).into_parts();
        let socket = ClientWebSocket {
            socket,
            response,
            accepted_protocol: None,
        };
        let (lines_tx, lines) = mpsc::channel(1);
        drop(lines_tx);
        let started = Instant::now();
        let result = tokio::time::timeout(CLOSE_TIMEOUT * 2, pump(socket, lines))
            .await
            .expect("bounded by the close timeout");
        assert!(result.is_err());
        assert!(started.elapsed() >= CLOSE_TIMEOUT);
    }

    #[tokio::test]
    async fn an_input_error_survives_a_peer_close_that_beats_our_flush() {
        let wire = Arc::new(Mutex::new(Wire::default()));
        let socket = AsyncWebSocket::from_raw_socket(
            ServiceInput::new(CloseBeforeFlush(wire.clone())),
            Role::Client,
            None,
        )
        .await;
        let (response, _) = Response::new(Body::empty()).into_parts();
        let socket = ClientWebSocket {
            socket,
            response,
            accepted_protocol: None,
        };
        let (lines_tx, lines) = mpsc::channel(1);
        lines_tx
            .send(Err(io::Error::new(io::ErrorKind::InvalidData, "not UTF-8")))
            .await
            .unwrap();
        drop(lines_tx);

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), pump(socket, lines))
            .await
            .unwrap();
        let wire = wire.lock();
        assert!(wire.pending_flushes > 0, "our close waited in flush");
        assert!(wire.peer_closed);
        assert_eq!(wire.shutdowns, 1);
        // One masked close frame with status 1011: the error was read before the peer closed.
        let written = &wire.written;
        assert_eq!(written[0], 0x88);
        assert_ne!(written[1] & 0x80, 0);
        assert_eq!(written.len(), 6 + usize::from(written[1] & 0x7f));
        let payload: Vec<u8> = written[6..]
            .iter()
            .zip(written[2..6].iter().cycle())
            .map(|(byte, mask)| byte ^ mask)
            .collect();
        assert_eq!(payload[..2], 1011u16.to_be_bytes());
        assert_eq!(&payload[2..], b"unreadable input");
        assert!(result.is_err(), "the input error was lost: {result:?}");
    }
}
