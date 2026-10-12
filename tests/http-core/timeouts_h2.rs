//! HTTP/2 deadline behavior at the frame boundary, including fragmented header blocks.

use std::{convert::Infallible, future::pending, time::Duration};

use rama::{
    ServiceInput,
    http::{
        Body, Request, Response,
        core::{
            server::conn::{HeaderReadTimeout, IdleTimeout, http2},
            service::RamaHttpService,
        },
    },
    rt::Executor,
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex, split},
    spawn,
    task::{JoinHandle, yield_now},
    time::{Instant, advance, sleep},
};

const SECOND: Duration = Duration::from_secs(1);

async fn server(builder: http2::Builder, hold: bool) -> (DuplexStream, JoinHandle<()>) {
    let (mut peer, io) = duplex(65536);
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(move |_: Request| async move {
            if hold {
                pending::<()>().await;
            }
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        _ = builder.serve_connection(ServiceInput::new(io), svc).await;
    });
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut peer, 4, 0, 0, &[]).await;
    // Consume SETTINGS and its ACK before starting the scenario.
    loop {
        let (kind, flags, _) = read_frame(&mut peer).await;
        if kind == 4 && flags == 1 {
            break;
        }
    }
    frame(&mut peer, 4, 1, 0, &[]).await;
    (peer, task)
}

async fn frame(peer: &mut DuplexStream, kind: u8, flags: u8, stream: u32, body: &[u8]) {
    let length = (body.len() as u32).to_be_bytes();
    peer.write_all(&length[1..]).await.unwrap();
    peer.write_all(&[kind, flags]).await.unwrap();
    peer.write_all(&stream.to_be_bytes()).await.unwrap();
    peer.write_all(body).await.unwrap();
}

async fn read_frame(peer: &mut DuplexStream) -> (u8, u8, Vec<u8>) {
    let mut head = [0; 9];
    peer.read_exact(&mut head).await.unwrap();
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut body = vec![0; len];
    peer.read_exact(&mut body).await.unwrap();
    (head[3], head[4], body)
}

async fn goaway(peer: &mut DuplexStream) -> u32 {
    loop {
        let (kind, _, body) = read_frame(peer).await;
        if kind == 7 {
            return u32::from_be_bytes(body[4..8].try_into().unwrap());
        }
    }
}

async fn request(peer: &mut DuplexStream, end_stream: bool) {
    // Indexed GET, https, /, then a literal :authority = localhost.
    frame(
        peer,
        1,
        if end_stream { 5 } else { 4 },
        1,
        b"\x82\x87\x84\x01\x09localhost",
    )
    .await;
}

fn head(grace: u64, rate: u32, ceiling: u64) -> HeaderReadTimeout {
    HeaderReadTimeout {
        grace: SECOND * grace as u32,
        min_rate: rate,
        ceiling: SECOND * ceiling as u32,
    }
}

fn elapsed_at_deadline(start: Instant, expected: Duration) {
    let elapsed = start.elapsed();
    assert!(
        elapsed >= expected && elapsed <= expected + Duration::from_millis(2),
        "expected {expected:?}, observed {elapsed:?}"
    );
}

/// The next GOAWAY's last stream ID and error code, with the PING that may precede it.
async fn goaway_and_ping(peer: &mut DuplexStream) -> (u32, u32, Option<Vec<u8>>) {
    let mut ping = None;
    loop {
        let (kind, flags, body) = read_frame(peer).await;
        match kind {
            6 if flags & 1 == 0 => ping = Some(body),
            7 => {
                let last = u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7fff_ffff;
                let code = u32::from_be_bytes(body[4..8].try_into().unwrap());
                return (last, code, ping);
            }
            _ => {}
        }
    }
}

async fn expect_eof(peer: &mut DuplexStream) {
    let mut rest = Vec::new();
    peer.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "{} bytes after the final GOAWAY",
        rest.len()
    );
}

#[tokio::test(start_paused = true)]
async fn first_request_idle_sends_goaway_then_bounds_unacknowledged_drain() {
    let (mut peer, task) = server(http2::Builder::new(Executor::new()), false).await;
    let start = Instant::now();
    let (last, code, ping) = goaway_and_ping(&mut peer).await;
    assert_eq!((last, code), (0x7fff_ffff, 0), "a graceful GOAWAY first");
    elapsed_at_deadline(start, SECOND * 10);
    // Never acknowledging the shutdown PING: the drain ends with the final GOAWAY.
    let (kind, _, _) = read_frame(&mut peer).await;
    assert_eq!(kind, 6, "the shutdown PING follows the GOAWAY: {ping:?}");
    assert_eq!(goaway_and_ping(&mut peer).await, (0, 0, None));
    elapsed_at_deadline(start, SECOND * 11);
    expect_eof(&mut peer).await;
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn acknowledged_shutdown_ping_closes_before_the_drain() {
    let (mut peer, task) = server(http2::Builder::new(Executor::new()), false).await;
    let start = Instant::now();
    let (last, code, _) = goaway_and_ping(&mut peer).await;
    assert_eq!((last, code), (0x7fff_ffff, 0));
    let ping = loop {
        let (kind, flags, body) = read_frame(&mut peer).await;
        if kind == 6 && flags == 0 {
            break body;
        }
    };
    frame(&mut peer, 6, 1, 0, &ping).await;
    assert_eq!(goaway_and_ping(&mut peer).await, (0, 0, None));
    expect_eof(&mut peer).await;
    task.await.unwrap();
    elapsed_at_deadline(start, SECOND * 10);
}

#[tokio::test(start_paused = true)]
async fn settings_round_trip_extends_the_first_window_and_the_drain() {
    let (mut peer, io) = duplex(65536);
    let start = Instant::now();
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        http2::Builder::new(Executor::new())
            .serve_connection(ServiceInput::new(io), svc)
            .await
    });
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut peer, 4, 0, 0, &[]).await;
    loop {
        let (kind, flags, _) = read_frame(&mut peer).await;
        if kind == 4 && flags == 0 {
            break;
        }
    }
    advance(Duration::from_millis(500)).await;
    frame(&mut peer, 4, 1, 0, &[]).await;
    let (last, _, _) = goaway_and_ping(&mut peer).await;
    assert_eq!(last, 0x7fff_ffff);
    // Ten seconds plus four round trips of 500 ms.
    elapsed_at_deadline(start, SECOND * 12);
    assert_eq!(goaway_and_ping(&mut peer).await.0, 0);
    // The drain is four round trips too.
    elapsed_at_deadline(start, SECOND * 14);
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn stalled_preface_is_cut_by_the_head_deadline_alone() {
    let (mut peer, io) = duplex(65536);
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        http2::Builder::new(Executor::new())
            .without_idle_timeout()
            .with_header_read_timeout(head(2, 256, 5))
            .serve_connection(ServiceInput::new(io), svc)
            .await
    });
    peer.write_all(b"PRI * HTTP/2.0").await.unwrap();
    let start = Instant::now();
    assert!(task.await.unwrap().unwrap_err().is_timeout());
    elapsed_at_deadline(start, SECOND * 2);
}

#[tokio::test(start_paused = true)]
async fn bytes_before_a_frame_type_are_head_progress_on_an_idle_connection() {
    let builder = http2::Builder::new(Executor::new())
        .without_idle_timeout()
        .with_header_read_timeout(head(2, 256, 5));
    let (mut peer, task) = server(builder, false).await;
    peer.write_all(&[0, 0, 3]).await.unwrap();
    let start = Instant::now();
    assert_eq!(goaway(&mut peer).await, 11);
    elapsed_at_deadline(start, SECOND * 2);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn completed_request_earns_longer_idle_window() {
    let (mut peer, task) = server(http2::Builder::new(Executor::new()), false).await;
    request(&mut peer, true).await;
    let start = Instant::now();
    assert_eq!(goaway(&mut peer).await, 0);
    elapsed_at_deadline(start, SECOND * 30);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn incomplete_headers_payload_times_out_before_whole_frame_arrives() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(2, 256, 5));
    let (mut peer, task) = server(builder, false).await;
    peer.write_all(&[0, 0, 3, 1, 1, 0, 0, 0, 1, 0x82])
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(goaway(&mut peer).await, 11, "ENHANCE_YOUR_CALM");
    elapsed_at_deadline(start, SECOND * 2);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn continuation_progress_extends_grace_but_not_absolute_ceiling() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(1, 10, 5));
    let (mut peer, task) = server(builder, false).await;
    let mut block = vec![0x82, 0x87, 0x84, 0x01, 100];
    block.extend_from_slice(&[b'a'; 20]);
    frame(&mut peer, 1, 1, 1, &block).await;
    yield_now().await;
    let start = Instant::now();
    advance(SECOND * 2).await;
    frame(&mut peer, 9, 0, 1, &[b'a'; 20]).await;
    yield_now().await;
    assert!(!task.is_finished());
    assert_eq!(goaway(&mut peer).await, 11, "ENHANCE_YOUR_CALM");
    elapsed_at_deadline(start, SECOND * 5);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn active_request_is_exempt_from_idle_deadline() {
    let (mut peer, task) = server(http2::Builder::new(Executor::new()), true).await;
    request(&mut peer, false).await;
    yield_now().await;
    advance(SECOND * 120).await;
    yield_now().await;
    advance(SECOND * 2).await;
    yield_now().await;
    assert!(!task.is_finished());
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn incomplete_second_head_times_out_even_with_an_active_request() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(2, 256, 5));
    let (mut peer, task) = server(builder, true).await;
    request(&mut peer, false).await;
    peer.write_all(&[0, 0, 3, 1, 1, 0, 0, 0, 3, 0x82])
        .await
        .unwrap();
    let start = Instant::now();
    assert_eq!(goaway(&mut peer).await, 11, "ENHANCE_YOUR_CALM");
    elapsed_at_deadline(start, SECOND * 2);
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn disabled_deadlines_leave_idle_and_partial_headers_open() {
    let builder = http2::Builder::new(Executor::new())
        .maybe_with_idle_timeout(None)
        .maybe_with_header_read_timeout(None);
    let (mut peer, task) = server(builder, false).await;
    advance(SECOND * 120).await;
    yield_now().await;
    assert!(!task.is_finished());
    peer.write_all(&[0, 0, 3, 1, 1, 0, 0, 0, 1, 0x82])
        .await
        .unwrap();
    yield_now().await;
    advance(SECOND * 120).await;
    yield_now().await;
    advance(SECOND * 2).await;
    yield_now().await;
    assert!(!task.is_finished());
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn configured_idle_budget_applies_while_waiting_for_preface() {
    let (mut peer, io) = duplex(65536);
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        http2::Builder::new(Executor::new())
            .with_idle_timeout(IdleTimeout {
                first_request: SECOND * 2,
                idle: SECOND * 3,
            })
            .serve_connection(ServiceInput::new(io), svc)
            .await
            .unwrap();
    });
    let start = Instant::now();
    task.await.unwrap();
    elapsed_at_deadline(start, SECOND * 2);
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn pending_response_body_is_exempt_after_request_end_stream() {
    let (mut peer, io) = duplex(65536);
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::from_stream(
                rama::futures::stream::pending::<Result<rama::bytes::Bytes, Infallible>>(),
            )))
        }));
        _ = http2::Builder::new(Executor::new())
            .serve_connection(ServiceInput::new(io), svc)
            .await;
    });
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut peer, 4, 0, 0, &[]).await;
    request(&mut peer, true).await;
    loop {
        if read_frame(&mut peer).await.0 == 1 {
            break;
        }
    }
    advance(SECOND * 120).await;
    yield_now().await;
    advance(SECOND * 2).await;
    yield_now().await;
    assert!(!task.is_finished());
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn continuously_ready_extension_frames_cannot_starve_idle_deadline() {
    let (mut peer, task) = server(http2::Builder::new(Executor::new()), false).await;
    let writer = spawn(async move {
        let frames = [0, 0, 0, 0xff, 0, 0, 0, 0, 0].repeat(4096);
        while peer.write_all(&frames).await.is_ok() {}
    });
    for _ in 0..20 {
        yield_now().await;
    }
    advance(SECOND * 10).await;
    for _ in 0..100 {
        yield_now().await;
    }
    advance(SECOND * 2).await;
    for _ in 0..100 {
        yield_now().await;
    }
    assert!(task.is_finished(), "ready frames must not starve the timer");
    task.await.unwrap();
    writer.await.unwrap();
}

// ===== heads sharing a read, responses racing the idle GOAWAY, rejected heads =====

async fn settle() {
    for _ in 0..50 {
        yield_now().await;
    }
}

fn frame_bytes(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(body);
    out
}

async fn try_read_frame(peer: &mut DuplexStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0; 9];
    peer.read_exact(&mut head).await.ok()?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    let mut body = vec![0; len];
    peer.read_exact(&mut body).await.ok()?;
    Some((head[3], head[4], stream, body))
}

/// A server whose responses carry `body_len` bytes after `delay`, over a pipe of `capacity` bytes.
async fn responding_server(
    builder: http2::Builder,
    capacity: usize,
    body_len: usize,
    delay: Duration,
) -> (DuplexStream, JoinHandle<rama::http::core::Result<()>>) {
    let (mut peer, io) = duplex(capacity);
    let task = spawn(async move {
        let svc = RamaHttpService::new(service_fn(move |_: Request| async move {
            sleep(delay).await;
            Ok::<_, Infallible>(Response::new(Body::from(vec![b'x'; body_len])))
        }));
        builder.serve_connection(ServiceInput::new(io), svc).await
    });
    peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    frame(&mut peer, 4, 0, 0, &[]).await;
    loop {
        let (kind, flags, _, _) = try_read_frame(&mut peer).await.unwrap();
        if kind == 4 && flags == 1 {
            break;
        }
    }
    frame(&mut peer, 4, 1, 0, &[]).await;
    settle().await;
    (peer, task)
}

/// A literal header field without indexing: `x-pad` with a 20 byte value.
fn pad() -> Vec<u8> {
    let mut out = vec![0x00, 0x05];
    out.extend_from_slice(b"x-pad");
    out.push(20);
    out.extend_from_slice(&[b'a'; 20]);
    out
}

/// Reads `stream`'s response until END_STREAM, returning the DATA bytes, or `None` on a GOAWAY first.
async fn read_response(peer: &mut DuplexStream, stream: u32) -> Option<usize> {
    let mut data = 0;
    while let Some((kind, flags, id, body)) = try_read_frame(peer).await {
        match kind {
            0 if id == stream => {
                data += body.len();
                if flags & 1 == 1 {
                    return Some(data);
                }
            }
            1 if id == stream && flags & 1 == 1 => return Some(data),
            _ => {}
        }
    }
    None
}

#[tokio::test(start_paused = true)]
async fn second_head_in_the_same_read_gets_its_own_grace() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(2, 20, 60));
    let (mut peer, task) = responding_server(builder, 65536, 2, Duration::ZERO).await;
    let start = Instant::now();
    // HEADERS for stream 1 with END_STREAM but without END_HEADERS.
    frame(&mut peer, 1, 0x1, 1, b"\x82\x87\x84\x01\x09localhost").await;
    settle().await;
    for _ in 0..4 {
        advance(SECOND).await;
        frame(&mut peer, 9, 0, 1, &pad()).await;
        settle().await;
        assert!(!task.is_finished());
    }
    advance(SECOND).await;
    // The last CONTINUATION and the first five bytes of stream 3's HEADERS arrive together.
    let mut wire = frame_bytes(9, 0x4, 1, &pad());
    wire.extend_from_slice(&[0, 0, 14, 1, 5]);
    peer.write_all(&wire).await.unwrap();
    assert_eq!(read_response(&mut peer, 1).await, Some(2));
    assert_eq!(goaway(&mut peer).await, 11);
    elapsed_at_deadline(start, SECOND * 7);
    assert!(task.await.unwrap().unwrap_err().is_timeout());
}

#[tokio::test(start_paused = true)]
async fn head_after_a_refused_one_in_the_same_read_gets_its_own_grace() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(2, 20, 60));
    let (mut peer, task) = responding_server(builder, 65536, 2, Duration::ZERO).await;
    let start = Instant::now();
    // A head for stream 1 without :scheme or :path, which is reset rather than served.
    frame(&mut peer, 1, 0x1, 1, b"\x82").await;
    settle().await;
    for _ in 0..4 {
        advance(SECOND).await;
        frame(&mut peer, 9, 0, 1, &pad()).await;
        settle().await;
        assert!(!task.is_finished());
    }
    advance(SECOND).await;
    let mut wire = frame_bytes(9, 0x4, 1, &pad());
    wire.extend_from_slice(&[0, 0, 14, 1, 5]);
    peer.write_all(&wire).await.unwrap();
    assert_eq!(goaway(&mut peer).await, 11);
    elapsed_at_deadline(start, SECOND * 7);
    assert!(task.await.unwrap().unwrap_err().is_timeout());
}

#[tokio::test(start_paused = true)]
async fn slow_head_alone_is_served() {
    let builder = http2::Builder::new(Executor::new()).with_header_read_timeout(head(2, 20, 60));
    let (mut peer, task) = responding_server(builder, 65536, 2, Duration::ZERO).await;
    frame(&mut peer, 1, 0x1, 1, b"\x82\x87\x84\x01\x09localhost").await;
    settle().await;
    for _ in 0..4 {
        advance(SECOND).await;
        frame(&mut peer, 9, 0, 1, &pad()).await;
        settle().await;
    }
    advance(SECOND).await;
    frame(&mut peer, 9, 0x4, 1, &pad()).await;
    assert_eq!(read_response(&mut peer, 1).await, Some(2));
    task.abort();
}

#[tokio::test(start_paused = true)]
async fn response_racing_the_idle_goaway_is_not_truncated() {
    for capacity in [8192, 1 << 20] {
        let body_len = 60_000;
        let (mut peer, task) = responding_server(
            http2::Builder::new(Executor::new()),
            capacity,
            body_len,
            SECOND * 3,
        )
        .await;
        advance(SECOND * 10).await;
        settle().await;
        // Sent before this client read the GOAWAY.
        frame(&mut peer, 1, 0x5, 1, b"\x82\x87\x84\x01\x09localhost").await;
        settle().await;
        advance(SECOND * 3).await;
        settle().await;
        assert_eq!(
            read_response(&mut peer, 1).await,
            Some(body_len),
            "capacity {capacity}"
        );
        task.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn final_close_flushes_a_response_the_peer_reads_late() {
    let body_len = 60_000;
    let (mut peer, task) = responding_server(
        http2::Builder::new(Executor::new()),
        8192,
        body_len,
        SECOND * 3,
    )
    .await;
    advance(SECOND * 10).await;
    settle().await;
    frame(&mut peer, 1, 0x5, 1, b"\x82\x87\x84\x01\x09localhost").await;
    settle().await;
    advance(SECOND * 3).await;
    settle().await;
    // Once the last DATA frame left the stream for the connection's write buffer,
    // the client pauses for longer than the drain.
    let mut data = 0;
    while data < 45_000 {
        let (kind, _, stream, body) = try_read_frame(&mut peer).await.unwrap();
        if kind == 0 && stream == 1 {
            data += body.len();
        }
    }
    advance(Duration::from_millis(1_500)).await;
    settle().await;
    let rest = read_response(&mut peer, 1).await;
    assert_eq!(rest.map(|rest| data + rest), Some(body_len));
    assert_eq!(goaway_and_ping(&mut peer).await.0, 1, "the final GOAWAY");
    expect_eof(&mut peer).await;
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn rejected_heads_do_not_restart_the_first_request_window() {
    let (peer, task) = responding_server(
        http2::Builder::new(Executor::new()),
        65536,
        2,
        Duration::ZERO,
    )
    .await;
    let (mut reader, mut writer) = split(peer);
    let start = Instant::now();
    let goaway_at = spawn(async move {
        loop {
            let mut head = [0; 9];
            reader.read_exact(&mut head).await.ok()?;
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut body = vec![0; len];
            reader.read_exact(&mut body).await.ok()?;
            if head[3] == 7 {
                return Some(start.elapsed());
            }
        }
    });
    // Time moves in small steps so that the GOAWAY is seen when it is due.
    async fn elapse(total: Duration) {
        let step = Duration::from_millis(250);
        for _ in 0..total.as_millis() / step.as_millis() {
            advance(step).await;
            settle().await;
        }
    }
    let mut stream = 1u32;
    for _ in 0..5 {
        elapse(SECOND * 9).await;
        // A malformed head, split so that each one is in progress for half a second.
        let wire = frame_bytes(1, 0x5, stream, b"\x82");
        if writer.write_all(&wire[..9]).await.is_err() {
            break;
        }
        settle().await;
        elapse(Duration::from_millis(500)).await;
        if writer.write_all(&wire[9..]).await.is_err() {
            break;
        }
        settle().await;
        stream += 2;
    }
    let at = goaway_at.await.unwrap().expect("GOAWAY");
    assert!(at <= SECOND * 11, "GOAWAY only at {at:?}");
    task.abort();
}
