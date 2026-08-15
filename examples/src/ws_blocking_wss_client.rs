//! Connect to a secure WebSocket endpoint with Rama's blocking HTTP client.
//!
//! ```sh
//! cargo run -p rama-examples --bin ws_blocking_wss_client \
//!   --features=http-full,boring
//! ```
//!
//! Pass the WSS URL, message, and optional TLS server name as arguments. The
//! HTTP client owns its runtime thread and remains reusable after the upgrade.
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
    extensions::Extensions,
    http::{client::EasyHttpWebClient, ws::handshake::client::BlockingHttpClientWebSocketExt as _},
    tls::client::TlsServerName,
};

fn main() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "wss://echo.ramaproxy.org/".to_owned());
    let message = args.next().unwrap_or_else(|| "Hello, Rama!".to_owned());
    let server_name = args.next();

    let client = EasyHttpWebClient::try_blocking()?;
    let extensions = Extensions::new();
    if let Some(server_name) = server_name {
        extensions.insert(TlsServerName(server_name.parse()?));
    }
    let mut socket = client
        .websocket(url)
        .try_handshake_with_extensions(extensions)?;

    socket.send_message(message.into())?;
    let echo = socket.recv_message()?.into_text()?;
    println!("Echo: {echo}");

    Ok(())
}
