#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "benchmark fixtures fail fast"
)]
#![deny(warnings)]

use divan::{AllocProfiler, Bencher, black_box};
use rama_icap::{
    client::options::{OptionsValidation, ServiceCapabilities},
    codec::{
        HeadParserConfig, HeadScanner, Header, HeaderSlot, RequestLine, ResponseLine,
        encode_chunk_line as encode_chunk_line_into, encode_encapsulated,
        encode_parsed_request_head, parse_chunk_line as parse_chunk_line_bytes, parse_encapsulated,
        parse_request_head, parse_response_head,
    },
    http::layer::ServiceEndpoint,
    message::{EncapsulatedParts, Request, Response},
    proto::{EncapsulatedKind, EncapsulatedSection, Method, MethodKind, StatusCode, header},
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const OPTIONS_REQUEST: &[u8] = b"OPTIONS icap://icap.test/scan ICAP/1.0\r\n\
Host: icap.test\r\n\
Allow: 204, 206\r\n\
Encapsulated: null-body=0\r\n\r\n";

const OPTIONS_RESPONSE: &[u8] = b"ICAP/1.0 200 OK\r\n\
Methods: REQMOD, RESPMOD\r\n\
ISTag: \"rama-bench\"\r\n\
Preview: 1024\r\n\
Allow: 204, 206\r\n\
Transfer-Preview: *\r\n\
Options-TTL: 3600\r\n\
Encapsulated: null-body=0\r\n\r\n";

fn main() {
    divan::main();
}

#[divan::bench]
fn scan_options_head() {
    let scanner = HeadScanner::new();
    black_box(scanner.scan(
        black_box(OPTIONS_RESPONSE),
        HeadParserConfig::new().with_max_bytes(64 * 1024),
    ))
    .unwrap();
}

#[divan::bench]
fn parse_options_request() {
    let mut slots = [HeaderSlot::EMPTY; 8];
    black_box(parse_request_head(black_box(OPTIONS_REQUEST), &mut slots)).unwrap();
}

#[divan::bench]
fn parse_options_response() {
    let mut slots = [HeaderSlot::EMPTY; 16];
    black_box(parse_response_head(
        MethodKind::Options,
        black_box(OPTIONS_RESPONSE),
        &mut slots,
    ))
    .unwrap();
}

#[divan::bench]
fn encode_options_request() {
    let mut slots = [HeaderSlot::EMPTY; 8];
    let rama_icap::codec::ParseStatus::Complete(head, _) =
        parse_request_head(OPTIONS_REQUEST, &mut slots).unwrap()
    else {
        panic!("complete benchmark request");
    };
    let mut output = [0; 256];
    black_box(encode_parsed_request_head(&head, &mut output)).unwrap();
}

#[divan::bench]
fn parse_chunk_line() {
    black_box(parse_chunk_line_bytes(black_box(
        b"0; use-original-body=1024\r\n",
    )))
    .unwrap();
}

#[divan::bench]
fn encode_chunk_line() {
    let mut output = [0; 64];
    black_box(encode_chunk_line_into(4096, &[], &mut output)).unwrap();
}

#[divan::bench]
fn parse_encapsulated_sections() {
    black_box(parse_encapsulated(black_box(
        b"req-hdr=0, res-hdr=64, res-body=128",
    )))
    .unwrap();
}

#[divan::bench]
fn encode_encapsulated_sections() {
    let sections = [
        EncapsulatedSection::new(EncapsulatedKind::RequestHeader, 0),
        EncapsulatedSection::new(EncapsulatedKind::ResponseHeader, 64),
        EncapsulatedSection::new(EncapsulatedKind::ResponseBody, 128),
    ];
    let mut output = [0; 64];
    black_box(encode_encapsulated(&sections, &mut output)).unwrap();
}

#[divan::bench]
fn build_options_request() {
    let line = RequestLine::new(Method::Options, "icap://icap.test/scan").unwrap();
    let fields = [Header::new(header::HOST, b"icap.test").unwrap()];
    black_box(Request::new(line, &fields, Some(EncapsulatedParts::null()))).unwrap();
}

#[divan::bench]
fn parse_service_capabilities(bencher: Bencher) {
    let response = options_response();
    bencher.bench(|| {
        black_box(ServiceCapabilities::from_options_response(
            black_box(response.clone()),
            None,
            16,
            true,
            OptionsValidation::Compatible,
        ))
        .unwrap()
    });
}

#[divan::bench]
fn clone_warmed_endpoint_options_request(bencher: Bencher) {
    let endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    endpoint.options_request().unwrap();
    bencher.bench(|| black_box(endpoint.options_request()).unwrap());
}

fn options_response() -> Response {
    let fields = [
        Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
        Header::new(header::ISTAG, b"\"rama-bench\"").unwrap(),
        Header::new(header::PREVIEW, b"1024").unwrap(),
        Header::new(header::ALLOW, b"204, 206").unwrap(),
        Header::new(header::TRANSFER_PREVIEW, b"*").unwrap(),
        Header::new(header::OPTIONS_TTL, b"3600").unwrap(),
    ];
    Response::new(
        MethodKind::Options,
        ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
        &fields,
        Some(EncapsulatedParts::null()),
    )
    .unwrap()
}
