//! Connect to a secure WebSocket endpoint with Rama's blocking HTTP client.
//!
//! ```sh
//! cargo run -p rama-examples --bin ws_blocking_wss_client \
//!   --features=http-full,boring
//! ```
//!
//! Pass the WSS URL and message as arguments to replace the defaults. The HTTP
//! client owns its runtime thread and remains reusable after the upgrade.
//!
//! # Expected output
//!
//! `Echo: Hello, Rama!`

#![expect(
    clippy::print_stdout,
    reason = "printing the echo is the purpose of this client example"
)]

use rama::{
    error::BoxError,
    http::{client::EasyHttpWebClient, ws::handshake::client::BlockingHttpClientWebSocketExt as _},
};

fn main() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "wss://echo.ramaproxy.org/".to_owned());
    let message = args.next().unwrap_or_else(|| "Hello, Rama!".to_owned());

    let client = EasyHttpWebClient::try_blocking()?;
    let mut socket = client.websocket(url).try_handshake()?;

    socket.send_message(message.into())?;
    let echo = socket.recv_message()?.into_text()?;
    println!("Echo: {echo}");

    Ok(())
}
