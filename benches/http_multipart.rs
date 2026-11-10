#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the server-side `multipart/form-data` parser,
//! decoupled from HTTP transport: one large field per payload shape (binary,
//! CRLF text, LF-only text) and a form of many small fields, each fed at
//! several body-chunk sizes and read to the end chunk by chunk.

use divan::black_box;
use divan::counter::BytesCount;
use rama::bytes::Bytes;
use rama::futures::stream;
use rama::http::service::web::extract::multipart::{Multipart, MultipartConfig};
use rama::utils::octets::{kib, mib};
use std::convert::Infallible;
use std::sync::OnceLock;

mod bench_alloc;

const BOUNDARY: &str = "----RamaFormBoundary7MA4YWxkTrZu0gW";
const LARGE_FIELD_SIZE: usize = mib(16);
const SMALL_FIELDS: usize = 1000;
const LINE_LEN: usize = 78;

const CHUNK_SIZES: &[usize] = &[kib(1), kib(16), kib(64)];

#[derive(Debug, Clone, Copy)]
enum Payload {
    Binary,
    CrlfText,
    LfText,
}

/// Deterministic bytes covering every value, CR and LF included.
fn binary_content() -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut out = Vec::with_capacity(LARGE_FIELD_SIZE);
    while out.len() < LARGE_FIELD_SIZE {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(LARGE_FIELD_SIZE);
    out
}

fn text_content(line_end: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LARGE_FIELD_SIZE + LINE_LEN);
    let mut n = 0usize;
    while out.len() < LARGE_FIELD_SIZE {
        for i in 0..LINE_LEN {
            out.push(b'a' + ((n + i * 7) % 26) as u8);
        }
        out.extend_from_slice(line_end);
        n += 1;
    }
    out.truncate(LARGE_FIELD_SIZE);
    out
}

fn push_part(out: &mut Vec<u8>, name: &str, file: Option<(&str, &str)>, data: &[u8]) {
    out.extend_from_slice(b"--");
    out.extend_from_slice(BOUNDARY.as_bytes());
    out.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
    out.extend_from_slice(name.as_bytes());
    out.push(b'"');
    if let Some((file_name, content_type)) = file {
        out.extend_from_slice(b"; filename=\"");
        out.extend_from_slice(file_name.as_bytes());
        out.extend_from_slice(b"\"\r\nContent-Type: ");
        out.extend_from_slice(content_type.as_bytes());
    }
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

fn close(out: &mut Vec<u8>) {
    out.extend_from_slice(b"--");
    out.extend_from_slice(BOUNDARY.as_bytes());
    out.extend_from_slice(b"--\r\n");
}

fn large_field_body(payload: Payload) -> &'static [u8] {
    static BINARY: OnceLock<Vec<u8>> = OnceLock::new();
    static CRLF_TEXT: OnceLock<Vec<u8>> = OnceLock::new();
    static LF_TEXT: OnceLock<Vec<u8>> = OnceLock::new();
    let (cell, content_type): (_, &str) = match payload {
        Payload::Binary => (&BINARY, "application/octet-stream"),
        Payload::CrlfText => (&CRLF_TEXT, "text/plain"),
        Payload::LfText => (&LF_TEXT, "application/sql"),
    };
    cell.get_or_init(|| {
        let content = match payload {
            Payload::Binary => binary_content(),
            Payload::CrlfText => text_content(b"\r\n"),
            Payload::LfText => text_content(b"\n"),
        };
        let mut out = Vec::with_capacity(content.len() + 512);
        push_part(&mut out, "comment", None, b"a large upload");
        push_part(
            &mut out,
            "upload",
            Some(("upload.bin", content_type)),
            &content,
        );
        close(&mut out);
        out
    })
}

fn small_fields_body() -> &'static [u8] {
    static BODY: OnceLock<Vec<u8>> = OnceLock::new();
    BODY.get_or_init(|| {
        let mut out = Vec::new();
        for i in 0..SMALL_FIELDS {
            let name = format!("field-{i}");
            let value = format!("value of field number {i}");
            push_part(&mut out, &name, None, value.as_bytes());
        }
        close(&mut out);
        out
    })
}

fn chunks_for(encoded: &[u8], chunk_size: usize) -> Vec<Bytes> {
    encoded
        .chunks(chunk_size)
        .map(Bytes::copy_from_slice)
        .collect()
}

fn multipart(chunks: &[Bytes]) -> Multipart {
    let config = MultipartConfig::new().without_max_parts();
    Multipart::from_stream_with_config(
        stream::iter(Vec::from(chunks).into_iter().map(Ok::<_, Infallible>)),
        BOUNDARY,
        Some(&config),
    )
}

/// Reads every field chunk by chunk; returns the field count and data bytes.
async fn read_chunks(chunks: &[Bytes]) -> (usize, usize) {
    let mut multipart = multipart(chunks);
    let (mut fields, mut total) = (0, 0);
    while let Some(mut field) = multipart.next_field().await.expect("valid part") {
        black_box(field.name());
        while let Some(chunk) = field.chunk().await.expect("valid field data") {
            total += black_box(chunk.len());
        }
        fields += 1;
    }
    (fields, total)
}

/// Collects every field as one buffer; returns the field count and data bytes.
async fn read_collected(chunks: &[Bytes]) -> (usize, usize) {
    let mut multipart = multipart(chunks);
    let (mut fields, mut total) = (0, 0);
    while let Some(field) = multipart.next_field().await.expect("valid part") {
        total += black_box(field.bytes().await.expect("valid field data")).len();
        fields += 1;
    }
    (fields, total)
}

fn main() {
    // correctness preflight, outside any timing
    for payload in [Payload::Binary, Payload::CrlfText, Payload::LfText] {
        for &chunk_size in CHUNK_SIZES {
            let chunks = chunks_for(large_field_body(payload), chunk_size);
            let expected = (2, LARGE_FIELD_SIZE + "a large upload".len());
            assert_eq!(expected, block_on(read_chunks(&chunks)), "{payload:?}");
            assert_eq!(expected, block_on(read_collected(&chunks)), "{payload:?}");
        }
    }
    let chunks = chunks_for(small_fields_body(), kib(16));
    assert_eq!(SMALL_FIELDS, block_on(read_chunks(&chunks)).0);

    divan::main();
}

/// Minimal single-future block-on: the in-memory stream never waits on I/O.
fn block_on<F: Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::hint::spin_loop();
    }
}

fn bench_large(bencher: divan::Bencher, payload: Payload, chunk_size: usize) {
    let encoded = large_field_body(payload);
    let chunks = chunks_for(encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| block_on(read_chunks(black_box(&chunks))));
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn large_binary_field(bencher: divan::Bencher, chunk_size: usize) {
    bench_large(bencher, Payload::Binary, chunk_size);
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn large_crlf_text_field(bencher: divan::Bencher, chunk_size: usize) {
    bench_large(bencher, Payload::CrlfText, chunk_size);
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn large_lf_text_field(bencher: divan::Bencher, chunk_size: usize) {
    bench_large(bencher, Payload::LfText, chunk_size);
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn large_binary_field_collected(bencher: divan::Bencher, chunk_size: usize) {
    let encoded = large_field_body(Payload::Binary);
    let chunks = chunks_for(encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| block_on(read_collected(black_box(&chunks))));
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn many_small_fields(bencher: divan::Bencher, chunk_size: usize) {
    let encoded = small_fields_body();
    let chunks = chunks_for(encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| block_on(read_chunks(black_box(&chunks))));
}

#[divan::bench(args = CHUNK_SIZES, sample_count = 30)]
fn many_small_fields_collected(bencher: divan::Bencher, chunk_size: usize) {
    let encoded = small_fields_body();
    let chunks = chunks_for(encoded, chunk_size);
    bencher
        .counter(BytesCount::new(encoded.len()))
        .bench_local(|| block_on(read_collected(black_box(&chunks))));
}
