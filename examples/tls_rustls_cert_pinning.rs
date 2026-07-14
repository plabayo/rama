//! Make an HTTPS request only when the server leaf matches a pin, with normal verification by default.
//!
//! In one terminal:
//! ```sh
//! RAMA_TLS_RUSTLS_DYNAMIC_CERTS_ADDR=127.0.0.1:64806 \
//!     cargo run --example tls_rustls_dynamic_certs --features=http-full,rustls,aws-lc
//! ```
//!
//! In another terminal:
//! ```sh
//! cargo run --example tls_rustls_cert_pinning --features=http-full,rustls,aws-lc -- \
//!     --insecure https://127.0.0.1:64806 examples/assets/example.com.crt
//! ```
//!
//! The pin argument is either a standard `sha256/<base64>` key pin (as printed
//! by `rama probe tls`), a `der/<base64>` exact certificate pin, or a path to a
//! PEM certificate whose key pin is derived.
//!
//! Another way that you can play with this example is by getting the public key hash
//! for a domain that you want to test using the Rama CLI tool and use that hash to make
//! a request to the server reachable by that domain:
//!
//! ```sh
//! rama probe tls example.com
//!
//! # copy the hash, e.g. 'sha256/tdjz7o5j27MAN6uFM2/pKGMGSbSyBMSiSU1r5qw4JDM='
//! # and use it as for example below:
//!
//! cargo run --example tls_rustls_cert_pinning --features=http-full,rustls,aws-lc -- \
//!     https://example.com \
//!     'sha256/tdjz7o5j27MAN6uFM2/pKGMGSbSyBMSiSU1r5qw4JDM='
//! ```
//!
//! The local server uses a self-signed certificate, so this invocation opts out
//! of normal verification. The pin is still required. Omit `--insecure` for
//! servers whose certificate is normally trusted. Private trust anchors can
//! instead be configured with `TlsClientConfig::try_with_server_trust_anchors`.

#![expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use clap::Parser;
use rama::{
    http::{BodyExtractExt as _, client::EasyHttpWebClient, service::client::HttpClientExt as _},
    net::uri::Uri,
    rt::Executor,
    tls::client::{ServerVerifyMode, TlsClientConfig, TlsServerCertPin, TlsServerCertPins},
};

#[derive(Debug, Parser)]
struct Args {
    /// Disable certificate verification beyond the pin check.
    #[arg(short = 'k', long)]
    insecure: bool,

    /// HTTPS URL to request.
    url: Uri,

    /// `sha256/<base64>` key pin, `der/<base64>` certificate pin,
    /// or a PEM certificate path to derive the key pin from.
    pin: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let pin = match args.pin.parse::<TlsServerCertPin>() {
        Ok(pin) => pin,
        Err(_) => std::fs::read_to_string(&args.pin)
            .expect("read pinned certificate")
            .parse()
            .expect("parse pinned certificate"),
    };
    let mut tls_config =
        TlsClientConfig::default_http().with_server_cert_pins(TlsServerCertPins::new(pin));
    if args.insecure {
        tls_config.set_server_verify(ServerVerifyMode::Disable);
    }

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_rustls(tls_config)
        .with_default_http_connector(Executor::default())
        .build_client();

    let response = client.get(args.url).send().await.expect("HTTPS request");
    println!(
        "{}",
        response.try_into_string().await.expect("response body")
    );
}
