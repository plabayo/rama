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

use std::{convert::Infallible, sync::Arc, time::Duration};

use clap::Parser;
use rama::{
    Layer as _,
    error::{BoxError, BoxErrorExt as _},
    http::{
        Body, HeaderMap, HeaderValue,
        body::{Frame, util::BodyExt as _},
        client::EasyHttpWebClient,
        layer::error_handling::ErrorHandlerLayer,
        server::HttpServer,
    },
    icap::{
        client::Client as IcapClient,
        codec::{HeadParserConfig, Header, InterimServiceTag, ResponseLine},
        http::{
            Encapsulated, HttpService, IncomingRequest,
            layer::{AdaptationLayer, ServiceEndpoint},
        },
        io::ConnectionOptions,
        message::{EncapsulatedParts, Response as IcapResponse},
        proto::{EncapsulatedKind, MethodKind, Preview, StatusCode as IcapStatusCode, header},
        server::{OutgoingResponse, Server as IcapServer},
    },
    net::address::HostWithOptPort,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};

const PROXY_ADDRESS: &str = "127.0.0.1:62059";
const ICAP_ADDRESS: &str = "127.0.0.1:62060";
const DEFAULT_ICAP_URI: &str = "icap://127.0.0.1:62060/adapt";
const TARGET_HOST: &str = "example.com";
const SERVICE_TAG: &[u8] = b"\"rama-icap-example\"";

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
    let target_host: Arc<str> = target_host.into();

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
    request: IncomingRequest,
    target_host: Arc<str>,
) -> Result<OutgoingResponse, BoxError> {
    let method = request.icap().method();
    match method {
        MethodKind::Options => options_response(),
        MethodKind::Respmod => {
            if !targets_host(&request, &target_host) {
                return no_modification(MethodKind::Respmod);
            }

            let (_icap, encapsulated, mut body, _extensions) = request.into_parts();
            let (_request, response, body_kind) = encapsulated
                .ok_or_else(|| BoxError::from_static_str("RESPMOD request has no HTTP metadata"))?
                .into_parts();
            let mut response = response
                .ok_or_else(|| BoxError::from_static_str("RESPMOD request has no HTTP response"))?;
            response
                .headers_mut()
                .insert("x-rama-icap", HeaderValue::from_static("adapted"));

            let original_body = match body_kind {
                EncapsulatedKind::ResponseBody => classify_original_body(&mut body).await?,
                EncapsulatedKind::NullBody => OriginalBody::Empty,
                _ => {
                    return Err(BoxError::from_static_str(
                        "RESPMOD request has an invalid body kind",
                    ));
                }
            };
            let fields = [Header::new(header::ISTAG, SERVICE_TAG)?];
            match original_body {
                OriginalBody::HasOctet => {
                    let parts =
                        Encapsulated::from_response(&response, EncapsulatedKind::ResponseBody)?;
                    let line =
                        ResponseLine::new(IcapStatusCode::PARTIAL_CONTENT, b"Partial Content")?;
                    let response =
                        IcapResponse::new(MethodKind::Respmod, line, &fields, Some(parts))?;
                    Ok(OutgoingResponse::without_body(response).with_use_original_body(0))
                }
                OriginalBody::Trailers(trailers) => {
                    declare_trailers(&mut response, &trailers)?;
                    let body =
                        Body::from_frame_stream(rama::futures::stream::iter([
                            Ok::<_, Infallible>(Frame::trailers(trailers)),
                        ]));
                    OutgoingResponse::from_http_response(
                        MethodKind::Respmod,
                        ResponseLine::new(IcapStatusCode::OK, b"OK")?,
                        &fields,
                        response.map(|_| body),
                    )
                    .map_err(Into::into)
                }
                OriginalBody::Empty => {
                    let parts = Encapsulated::from_response(&response, EncapsulatedKind::NullBody)?;
                    let response = IcapResponse::new(
                        MethodKind::Respmod,
                        ResponseLine::new(IcapStatusCode::OK, b"OK")?,
                        &fields,
                        Some(parts),
                    )?;
                    Ok(OutgoingResponse::without_body(response))
                }
            }
        }
        MethodKind::Reqmod | MethodKind::Extension => method_not_allowed(method),
    }
}

enum OriginalBody {
    HasOctet,
    Trailers(HeaderMap),
    Empty,
}

async fn classify_original_body(body: &mut Body) -> Result<OriginalBody, BoxError> {
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) if !data.is_empty() => return Ok(OriginalBody::HasOctet),
            Ok(_empty) => {}
            Err(frame) => {
                let trailers = frame
                    .into_trailers()
                    .map_err(|_frame| BoxError::from_static_str("unsupported HTTP body frame"))?;
                return Ok(OriginalBody::Trailers(trailers));
            }
        }
    }
    Ok(OriginalBody::Empty)
}

fn declare_trailers<B>(
    response: &mut rama::http::Response<B>,
    trailers: &HeaderMap,
) -> Result<(), BoxError> {
    let mut names = String::new();
    for name in trailers.keys() {
        if !names.is_empty() {
            names.push_str(", ");
        }
        names.push_str(name.as_str());
    }
    response
        .headers_mut()
        .insert(rama::http::header::TRAILER, HeaderValue::from_str(&names)?);
    Ok(())
}

fn targets_host(request: &IncomingRequest, target_host: &str) -> bool {
    let Some(request) = request
        .encapsulated()
        .and_then(|encapsulated| encapsulated.request())
    else {
        return false;
    };
    request
        .uri()
        .host()
        .is_some_and(|host| host.to_str().eq_ignore_ascii_case(target_host))
        || request
            .headers()
            .get(rama::http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|authority| authority.parse::<HostWithOptPort>().ok())
            .is_some_and(|authority| authority.host.to_str().eq_ignore_ascii_case(target_host))
}

fn options_response() -> Result<OutgoingResponse, BoxError> {
    let fields = [
        Header::new(header::METHODS, b"RESPMOD")?,
        Header::new("Service", b"Rama selective response adapter")?,
        Header::new(header::ISTAG, SERVICE_TAG)?,
        Header::new(header::PREVIEW, b"1024")?,
        Header::new(header::ALLOW, b"204, 206")?,
        Header::new(header::TRANSFER_PREVIEW, b"*")?,
    ];
    let response = IcapResponse::new(
        MethodKind::Options,
        ResponseLine::new(IcapStatusCode::OK, b"OK")?,
        &fields,
        Some(EncapsulatedParts::null()),
    )?;
    Ok(OutgoingResponse::without_body(response))
}

fn no_modification(method: MethodKind) -> Result<OutgoingResponse, BoxError> {
    let response = IcapResponse::new(
        method,
        ResponseLine::new(
            IcapStatusCode::NO_MODIFICATION_NEEDED,
            b"No Modification Needed",
        )?,
        &[Header::new(header::ISTAG, SERVICE_TAG)?],
        None,
    )?;
    Ok(OutgoingResponse::without_body(response))
}

fn method_not_allowed(method: MethodKind) -> Result<OutgoingResponse, BoxError> {
    let response = IcapResponse::new(
        method,
        ResponseLine::new(IcapStatusCode::METHOD_NOT_ALLOWED, b"Method Not Allowed")?,
        &[Header::new(header::ISTAG, SERVICE_TAG)?],
        None,
    )?;
    Ok(OutgoingResponse::without_body(response))
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
