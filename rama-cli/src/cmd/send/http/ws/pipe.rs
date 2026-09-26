//! Line-based WebSocket client for non-interactive use (scripts, pipes and tests).

use rama::{
    error::BoxError,
    futures::{SinkExt as _, StreamExt as _},
    http::ws::{
        Message, ProtocolError, WebSocketIo,
        handshake::client::ClientWebSocket,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use std::io::BufRead as _;
use tokio::{io::AsyncWriteExt as _, sync::mpsc};

/// Lines buffered between stdin and the socket.
const PENDING_LINES: usize = 16;

/// Send each stdin line as a text message and print every received message.
///
/// Both directions run concurrently, so a send waiting on flow control never stops
/// receiving. End of input starts the close handshake; the command ends once the peer's
/// close completed and the stream ended, whatever state stdin is in. Unreadable input
/// closes with an error status and fails the command.
pub(super) async fn run<S: WebSocketIo>(socket: ClientWebSocket<S>) -> Result<(), BoxError> {
    let (mut sink, mut stream) = socket.split();

    // A blocking stdin read cannot be cancelled: keep it off the runtime, so a pending
    // read never delays the exit.
    let (lines_tx, mut lines) = mpsc::channel(PENDING_LINES);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let failed = line.is_err();
            if lines_tx.blocking_send(line).is_err() || failed {
                break;
            }
        }
    });

    let send = async {
        while let Some(line) = lines.recv().await {
            match line {
                Ok(line) => sink.send(Message::text(line)).await?,
                Err(error) => {
                    let close = CloseFrame {
                        code: CloseCode::Error,
                        reason: "unreadable input".into(),
                    };
                    sink.send(Message::Close(Some(close))).await?;
                    return Ok(Some(error));
                }
            }
        }
        sink.send(Message::Close(None)).await.map(|()| None)
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

    tokio::pin!(send, receive);
    let mut sending = true;
    let mut input_error = None;
    loop {
        tokio::select! {
            result = &mut send, if sending => {
                sending = false;
                match result {
                    Ok(error) => input_error = error,
                    // The peer started closing first: nothing more may be sent.
                    Err(ProtocolError::SendAfterClosing) => (),
                    Err(error) if error.is_connection_error() => (),
                    Err(error) => return Err(error.into()),
                }
            }
            result = &mut receive => {
                result?;
                return input_error.map_or(Ok(()), |error| Err(error.into()));
            }
        }
    }
}
