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
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rama_core::{ServiceInput, bytes::Bytes, error::BoxError, service::service_fn};
use rama_icap::{
    client::options::{OptionsRequest, OptionsValidation, ServiceCapabilities},
    client::{ClientConnection, WriteOutcome},
    codec::{
        HeadParserConfig, HeadScanner, Header, HeaderSlot, ParseStatus, RequestLine, ResponseLine,
        encode_parsed_request_head, parse_request_head, parse_response_head,
    },
    http::layer::ServiceEndpoint,
    message::{EncapsulatedParts, Request, Response},
    proto::{EncapsulatedKind, Method, MethodKind, StatusCode, header},
    server::{IncomingRequest, OutgoingResponse, Server},
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

async fn measured_async<T>(future: impl Future<Output = T>) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    ALLOCATED_BYTES.set(0);
    COUNTING.set(true);
    let output = future.await;
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

    let body = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
    let mut slots = [HeaderSlot::EMPTY; 8];
    let (response, allocations, bytes) = measured(|| {
        Response::from_head_bytes(
            MethodKind::Respmod,
            Bytes::from_static(
                b"ICAP/1.0 200 OK\r\nISTag: \"allocation\"\r\nEncapsulated: res-body=0\r\n\r\n",
            ),
            &mut slots,
            HeadParserConfig::new(),
            Some(body.clone()),
        )
        .unwrap()
    });
    assert_eq!(
        (allocations, bytes),
        (0, 0),
        "a response without an outer trailer promise allocated"
    );
    drop(response);

    let (response, allocations, _bytes) = measured(|| {
        Response::from_head_bytes(
            MethodKind::Respmod,
            Bytes::from_static(
                b"ICAP/1.0 200 OK\r\nISTag: \"allocation\"\r\nAllow: trailers\r\nTrailer: X-Scan\r\nEncapsulated: res-body=0\r\n\r\n",
            ),
            &mut slots,
            HeadParserConfig::new(),
            Some(body),
        )
        .unwrap()
    });
    assert_eq!(
        allocations, 1,
        "a response promise did not use exactly one bounded metadata allocation"
    );
    drop(response);

    let folded_body = EncapsulatedParts::new(None, None, EncapsulatedKind::ResponseBody).unwrap();
    let (response, allocations, _bytes) = measured(|| {
        Response::from_head_bytes(
            MethodKind::Respmod,
            Bytes::from_static(
                b"ICAP/1.0 200 OK\r\nISTag: \"allocation\"\r\nAllow: trailers\r\nTrailer: X-Scan,\r\n X-Score\r\nEncapsulated: res-body=0\r\n\r\n",
            ),
            &mut slots,
            HeadParserConfig::compatible(),
            Some(folded_body),
        )
        .unwrap()
    });
    assert_eq!(
        allocations, 2,
        "a folded response promise exceeded its fixed allocation ceiling"
    );
    drop(response);

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

#[tokio::test]
async fn inbound_server_frames_have_constant_allocation_cost() {
    // Warm lazy runtime and protocol initialization before measuring.
    Box::pin(measure_inbound_server_frames(4)).await;

    let one = Box::pin(measure_inbound_server_frames(1)).await;
    let four = Box::pin(measure_inbound_server_frames(4)).await;
    let eight = Box::pin(measure_inbound_server_frames(8)).await;
    // These totals include fixed connection, bridge, and request setup. Equal
    // totals prove that additional inbound frames add no allocation slope.
    assert_eq!(one, four, "four inbound frames changed allocation cost");
    assert_eq!(one, eight, "eight inbound frames changed allocation cost");
}

async fn measure_inbound_server_frames(frame_count: usize) -> (usize, usize) {
    const BODY_BYTES: usize = 32;

    let (client_io, server_io) = tokio::io::duplex(4096);
    let frames_seen = Arc::new(AtomicUsize::new(0));
    let service_frames_seen = Arc::clone(&frames_seen);
    let service = service_fn(move |mut request: IncomingRequest| {
        let service_frames_seen = Arc::clone(&service_frames_seen);
        async move {
            while request.body_mut().next_data().await?.is_some() {
                service_frames_seen.fetch_add(1, Ordering::Relaxed);
            }
            let response = Response::new(
                MethodKind::Reqmod,
                ResponseLine::new(
                    StatusCode::NO_MODIFICATION_NEEDED,
                    b"No Modification Needed",
                )?,
                &[Header::new(header::ISTAG, b"\"rama-allocation\"")?],
                None,
            )?;
            Ok::<_, BoxError>(OutgoingResponse::without_body(response))
        }
    });
    let server = Server::new(
        service,
        rama_icap::proto::ServiceTag::from_static("rama-allocation"),
    )
    .unwrap();
    let mut client = ClientConnection::new(ServiceInput::new(client_io));
    let request = Request::new(
        RequestLine::new(Method::Reqmod, "icap://icap.test/scan").unwrap(),
        &[
            Header::new(header::HOST, b"icap.test").unwrap(),
            Header::new(header::ALLOW, b"204").unwrap(),
            Header::new(header::CONNECTION, b"close").unwrap(),
        ],
        Some(
            EncapsulatedParts::new(
                Some(rama_core::bytes::Bytes::from_static(
                    b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )),
                None,
                EncapsulatedKind::RequestBody,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let chunk = [b'x'; BODY_BYTES];
    let chunk_len = BODY_BYTES / frame_count;

    let (_, allocations, bytes) = Box::pin(measured_async(async {
        let server = server.serve_connection(ServiceInput::new(server_io));
        let client = async {
            let mut transaction = client.start(request).await.unwrap();
            for _ in 0..frame_count {
                assert_eq!(
                    transaction.write_data(&chunk[..chunk_len]).await.unwrap(),
                    WriteOutcome::Written,
                );
            }
            transaction.finish().await.unwrap().into_response().unwrap();
        };
        let (server, ()) = tokio::join!(server, client);
        server.unwrap();
    }))
    .await;
    assert_eq!(frames_seen.load(Ordering::Relaxed), frame_count);
    (allocations, bytes)
}
