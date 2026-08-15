//! Send an HTTPS request with Rama's blocking HTTP client.
//!
//! ```sh
//! cargo run -p rama-examples --bin http_blocking_https_client \
//!   --features=http-full,boring
//! ```
//!
//! Pass a URL as the first argument to replace `https://example.com/`.
//! The client owns its runtime thread, so callers do not need to create one.
//!
//! # Expected output
//!
//! The response status and body are printed before the process exits.

#![expect(
    clippy::print_stdout,
    reason = "printing the response is the purpose of this client example"
)]

use rama::{error::BoxError, http::client::EasyHttpWebClient};

fn main() -> Result<(), BoxError> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".to_owned());
    let client = EasyHttpWebClient::try_blocking()?;

    let response = client.get(url).send()?;
    println!("Status: {}", response.status());
    println!("Body: {}", response.try_into_string()?);

    Ok(())
}
