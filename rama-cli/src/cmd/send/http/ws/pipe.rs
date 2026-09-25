//! Line-based WebSocket client for non-interactive use (scripts, pipes and tests).

use rama::{
    error::BoxError,
    futures::{SinkExt as _, StreamExt as _},
    http::ws::{Message, WebSocketIo, handshake::client::ClientWebSocket},
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

/// Send each stdin line as a text message and print every received message.
/// End of input closes the socket; the command ends once the peer closed too.
pub(super) async fn run<S: WebSocketIo>(mut socket: ClientWebSocket<S>) -> Result<(), BoxError> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    let mut input_open = true;
    loop {
        tokio::select! {
            line = lines.next_line(), if input_open => {
                if let Some(line) = line? {
                    socket.send(Message::text(line)).await?;
                } else {
                    input_open = false;
                    socket.send(Message::Close(None)).await?;
                }
            }
            message = socket.next() => match message.transpose()? {
                Some(Message::Text(text)) => {
                    stdout.write_all(text.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
                Some(Message::Binary(data)) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Some(Message::Close(_)) | None => return Ok(()),
                Some(_) => (),
            },
        }
    }
}
