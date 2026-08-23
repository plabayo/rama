//! Minimal HTTP proxy with ICAP response adaptation.
//!
//! By default this process serves both:
//!
//! - an HTTP proxy on `127.0.0.1:62059`;
//! - an ICAP server on `127.0.0.1:62060`.
//!
//! The embedded ICAP service only adapts responses for `example.com`. It
//! adds an `x-rama-icap: adapted` response header while leaving the
//! streaming response body untouched. Other origins receive an ICAP 204.
//!
//! # Run with the embedded ICAP server
//!
//! ```sh
//! cargo run -p rama-examples --bin http_icap_proxy \
//!   --features=http-full,icap
//! curl -v -x http://127.0.0.1:62059 http://example.com/
//! curl -v -x http://127.0.0.1:62059 http://example.net/
//! ```
//!
//! # Run against an external ICAP server
//!
//! Pass one ICAP service URI to skip the embedded server:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_icap_proxy \
//!   --features=http-full,icap -- \
//!   icap://127.0.0.1:1344/echo
//! ```
//!
//! The external service must support RESPMOD. This makes it easy to replace
//! the embedded Rama implementation with c-icap or another implementation.

#![expect(
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{sync::Arc, time::Duration};

use clap::Parser;
use rama::{
    Layer as _,
    error::{BoxError, ErrorContext as _},
    http::{
        HeaderValue, client::EasyHttpWebClient, layer::error_handling::ErrorHandlerLayer,
        server::HttpServer,
    },
    icap::{
        client::Client as IcapClient,
        codec::{HeadParserConfig, InterimServiceTag},
        http::{
            HttpService, IncomingRequest,
            layer::{AdaptationLayer, ServiceEndpoint},
        },
        io::ConnectionOptions,
        proto::{MethodKind, Preview},
        server::{OptionsResponse, OutgoingResponse, Server as IcapServer},
    },
    net::{AuthorityInputExt as _, address::Host},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};

const PROXY_ADDRESS: &str = "127.0.0.1:62059";
const ICAP_ADDRESS: &str = "127.0.0.1:62060";
const DEFAULT_ICAP_URI: &str = "icap://127.0.0.1:62060/adapt";
const TARGET_HOST: &str = "example.com";
const SERVICE_TAG: &str = "\"rama-icap-example\"";

#[derive(Debug, Parser)]
#[command(about = "Run an HTTP proxy through a selective ICAP service")]
struct Args {
    /// External RESPMOD service URI; omit to run the embedded Rama service.
    icap_uri: Option<String>,

    /// HTTP host adapted by the embedded ICAP service.
    #[arg(long, default_value = TARGET_HOST)]
    target_host: String,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let Args {
        icap_uri,
        target_host,
    } = Args::parse();
    let embedded = icap_uri.is_none();
    let icap_uri = icap_uri.unwrap_or_else(|| DEFAULT_ICAP_URI.to_owned());
    let target_host = Arc::new(target_host.parse::<Host>()?);

    let graceful = rama::graceful::Shutdown::default();
    let executor = Executor::graceful(graceful.guard());

    if embedded {
        let listener = TcpListener::bind_address(ICAP_ADDRESS, executor.clone()).await?;
        let service_target = Arc::clone(&target_host);
        let service = HttpService::new(service_fn(move |request| {
            adapt_response(request, Arc::clone(&service_target))
        }));
        let server = IcapServer::new(service, SERVICE_TAG)?;
        graceful.spawn_task(listener.serve(server));
    }

    let connector =
        rama::dns::client::DnsConnector::new(rama::tcp::client::service::TcpConnector::new());
    let icap_client = IcapClient::new(connector).with_options(icap_connection_options(embedded));
    let endpoint = ServiceEndpoint::new(icap_uri)?
        .with_preview(Preview::new(1024))
        .with_allow_204(true)
        .with_allow_206(true);
    let proxy = AdaptationLayer::new(icap_client)
        .with_response_service(endpoint.clone())
        .into_layer(EasyHttpWebClient::default_with_executor(executor.clone()));
    let proxy = ErrorHandlerLayer::new().into_layer(proxy);
    let listener = TcpListener::bind_address(PROXY_ADDRESS, executor.clone()).await?;
    let server = HttpServer::auto(executor).service(proxy);
    graceful.spawn_task(listener.serve(server));

    println!("HTTP proxy listening on http://{PROXY_ADDRESS}");
    if embedded {
        println!("embedded ICAP service listening at {DEFAULT_ICAP_URI}");
        println!("only responses for {target_host} are adapted");
    } else {
        println!("using external ICAP service: {endpoint:?}");
    }
    println!("try: curl -v -x http://{PROXY_ADDRESS} http://{TARGET_HOST}/");

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;
    Ok(())
}

fn icap_connection_options(embedded: bool) -> ConnectionOptions {
    if embedded {
        ConnectionOptions::new()
    } else {
        // c-icap omits the mandatory ISTag on interim 100 responses.
        // Final responses remain strictly validated.
        let head =
            HeadParserConfig::new().with_interim_service_tag(InterimServiceTag::AllowMissing);
        ConnectionOptions::new().with_head_parser(head)
    }
}

async fn adapt_response(
    mut request: IncomingRequest,
    target_host: Arc<Host>,
) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    match method {
        MethodKind::Options => options_response(),
        MethodKind::Respmod => {
            if !targets_host(&request, &target_host) {
                return Ok(request.respond_no_modification(SERVICE_TAG)?);
            }

            request
                .encapsulated_mut()
                .and_then(|encapsulated| encapsulated.response_mut())
                .context("RESPMOD request has no HTTP response")?
                .headers_mut()
                .insert("x-rama-icap", HeaderValue::from_static("adapted"));
            Ok(request.adapt_response_head(SERVICE_TAG).await?)
        }
        MethodKind::Reqmod | MethodKind::Extension => {
            Ok(request.respond_method_not_allowed(SERVICE_TAG)?)
        }
    }
}

fn targets_host(request: &IncomingRequest, target_host: &Host) -> bool {
    let Some(request) = request
        .encapsulated()
        .and_then(|encapsulated| encapsulated.request())
    else {
        return false;
    };
    request
        .authority()
        .is_some_and(|authority| authority.host == *target_host)
}

fn options_response() -> Result<OutgoingResponse, BoxError> {
    Ok(OptionsResponse::new(SERVICE_TAG, "RESPMOD")
        .with_service("Rama selective response adapter")
        .with_preview(Preview::new(1024))
        .with_allow_204(true)
        .with_allow_206(true)
        .with_transfer_preview_all(true)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_mode_accepts_c_icap_interim_responses() {
        assert_eq!(
            icap_connection_options(false)
                .head_parser()
                .interim_service_tag(),
            InterimServiceTag::AllowMissing,
        );
        assert_eq!(
            icap_connection_options(true)
                .head_parser()
                .interim_service_tag(),
            InterimServiceTag::Required,
        );
    }
}
