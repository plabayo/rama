//! Send an HTTPS request with Rama's blocking HTTP client.
//!
//! ```sh
//! cargo run -p rama-examples --bin http_blocking_https_client \
//!   --features=http-full,boring
//! ```
//!
//! Pass a URL and optional TLS server name to replace `https://example.com/`.
//! The client owns its runtime thread, so callers do not need to create one.
//!
//! # Expected output
//!
//! The response status and body are printed before the process exits.

#![expect(
    clippy::print_stdout,
    reason = "printing the response is the purpose of this client example"
)]

use rama::{error::BoxError, http::client::EasyHttpWebClient, tls::client::TlsServerName};

fn main() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "https://example.com/".to_owned());
    let server_name = args.next();
    let client = EasyHttpWebClient::try_blocking()?;

    let mut request = client.get(url);
    if let Some(server_name) = server_name {
        request = request.extension(TlsServerName(server_name.parse()?));
    }
    let response = request.send()?;
    println!("Status: {}", response.status());
    println!("Body: {}", response.try_into_string()?);

    Ok(())
}
