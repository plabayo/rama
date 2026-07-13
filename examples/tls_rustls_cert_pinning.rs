//! Make an HTTPS request only when the server leaf matches a pin, with normal verification by default.
//!
//! In one terminal:
//! ```sh
//! cargo run --example tls_rustls_dynamic_certs --features=http-full,rustls,aws-lc
//! ```
//!
//! In another terminal:
//! ```sh
//! cargo run --example tls_rustls_cert_pinning --features=http-full,rustls,aws-lc -- \
//!     --insecure https://127.0.0.1:64802 examples/assets/example.com.crt
//! ```
//!
//! The local server uses a self-signed certificate, so this invocation opts out
//! of normal verification. The certificate pin is still required. Omit
//! `--insecure` for servers whose certificate is normally trusted. Private
//! trust anchors can instead be configured with
//! `TlsClientConfig::try_with_server_trust_anchors`.

#![expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use clap::Parser;
use rama::{
    crypto::pki_types::{CertificateDer, pem::PemObject as _},
    http::{BodyExtractExt as _, client::EasyHttpWebClient, service::client::HttpClientExt as _},
    rt::Executor,
    tls::client::{ServerVerifyMode, TlsClientConfig, TlsServerCertPins},
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
struct Args {
    /// Disable certificate verification beyond the pin check.
    #[arg(short = 'k', long)]
    insecure: bool,

    /// HTTPS URL to request.
    url: String,

    /// PEM-encoded server leaf certificate to pin.
    server_cert: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_verification_is_opt_in() {
        let args = Args::try_parse_from(["example", "https://example.com", "server.crt"]).unwrap();
        assert!(!args.insecure);

        let args =
            Args::try_parse_from(["example", "--insecure", "https://example.com", "server.crt"])
                .unwrap();
        assert!(args.insecure);
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let pin = CertificateDer::from_pem_file(args.server_cert).expect("read pinned certificate");
    let mut tls_config = TlsClientConfig::default_http().with_server_cert_pins(
        TlsServerCertPins::try_new([pin]).expect("non-empty certificate pins"),
    );
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
