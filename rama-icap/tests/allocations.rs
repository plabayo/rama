#![cfg(feature = "http")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "allocation contracts use fixed valid fixtures"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use rama_icap::{
    client::options::{OptionsRequest, OptionsValidation, ServiceCapabilities},
    codec::{
        HeadParserConfig, HeadScanner, Header, HeaderSlot, ParseStatus, RequestLine, ResponseLine,
        encode_parsed_request_head, parse_request_head, parse_response_head,
    },
    http::layer::ServiceEndpoint,
    message::{EncapsulatedParts, Request, Response},
    proto::{Method, MethodKind, StatusCode, header},
};
use rama_net::{address::HostWithPort, client::ConnectRequest};

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get().saturating_add(layout.size()));
            }
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get().saturating_add(new_size));
            }
        });
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const OPTIONS_REQUEST: &[u8] = b"OPTIONS icap://icap.test/scan ICAP/1.0\r\n\
Host: icap.test\r\n\
Allow: 204, 206\r\n\
Encapsulated: null-body=0\r\n\r\n";

const OPTIONS_RESPONSE: &[u8] = b"ICAP/1.0 200 OK\r\n\
Methods: REQMOD, RESPMOD\r\n\
ISTag: \"rama-allocation\"\r\n\
Preview: 1024\r\n\
Allow: 204, 206\r\n\
Transfer-Preview: *\r\n\
Options-TTL: 3600\r\n\
Encapsulated: null-body=0\r\n\r\n";

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    ALLOCATED_BYTES.set(0);
    COUNTING.set(true);
    let output = operation();
    COUNTING.set(false);
    (output, ALLOCATIONS.get(), ALLOCATED_BYTES.get())
}

#[test]
fn release_allocation_contracts() {
    let (_, allocations, bytes) = measured(|| {
        HeadScanner::new()
            .scan(
                OPTIONS_REQUEST,
                HeadParserConfig::new().with_max_bytes(64 * 1024),
            )
            .unwrap();

        let mut request_slots = [HeaderSlot::EMPTY; 8];
        let ParseStatus::Complete(request, _) =
            parse_request_head(OPTIONS_REQUEST, &mut request_slots).unwrap()
        else {
            panic!("complete request fixture");
        };
        let mut encoded = [0; 256];
        encode_parsed_request_head(&request, &mut encoded).unwrap();

        let mut response_slots = [HeaderSlot::EMPTY; 16];
        parse_response_head(MethodKind::Options, OPTIONS_RESPONSE, &mut response_slots).unwrap();
    });
    assert_eq!((allocations, bytes), (0, 0));

    let (request, allocations, _bytes) = measured(|| {
        Request::new(
            RequestLine::new(Method::Options, "icap://icap.test/scan").unwrap(),
            &[Header::new(header::HOST, b"icap.test").unwrap()],
            Some(EncapsulatedParts::null()),
        )
        .unwrap()
    });
    assert_eq!(allocations, 1);
    let connect = ConnectRequest::new("icap.test:1344".parse::<HostWithPort>().unwrap());
    let (request, _allocations, bytes) =
        measured(|| OptionsRequest::new(connect, request).unwrap());
    assert!(
        bytes <= 1024,
        "OPTIONS request construction allocated {bytes} bytes",
    );
    drop(request);

    drop(
        ServiceCapabilities::from_options_response(
            options_response(),
            None,
            16,
            true,
            OptionsValidation::Compatible,
        )
        .unwrap(),
    );
    let response = options_response();
    let (capabilities, allocations, bytes) = measured(|| {
        ServiceCapabilities::from_options_response(
            response,
            None,
            16,
            true,
            OptionsValidation::Compatible,
        )
        .unwrap()
    });
    assert!(
        allocations <= 1,
        "capability parse allocated {allocations} times ({bytes} bytes)",
    );
    drop(capabilities);

    let endpoint = ServiceEndpoint::new("icap://icap.test/scan").unwrap();
    endpoint.options_request().unwrap();
    let (request, allocations, bytes) = measured(|| endpoint.options_request().unwrap());
    assert_eq!((allocations, bytes), (0, 0));
    drop(request);
}

fn options_response() -> Response {
    let fields = [
        Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
        Header::new(header::ISTAG, b"\"rama-allocation\"").unwrap(),
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
