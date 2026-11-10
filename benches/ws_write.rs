#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for harnesses"
)]

//! In-memory benchmark for the WebSocket write path, decoupled from any
//! transport: a socket sends binary messages of various sizes, unmasked (server role)
//! and masked (client role), into a sink that discards them, so framing and buffering dominate.

use divan::black_box;
use divan::counter::BytesCount;
use rama::bytes::Bytes;
use rama::http::ws::Message;
use rama::http::ws::protocol::{Role, WebSocket};
use rama::utils::octets::{kib, mib};
use std::io::{self, Read, Write};

mod bench_alloc;

const TOTAL_BYTES: usize = mib(16);
const MESSAGE_LENS: &[usize] = &[kib(1), kib(64), mib(1), mib(4)];

/// Counts and discards what is written; never has anything to read.
#[derive(Default)]
struct Sink {
    written: usize,
}

impl Read for Sink {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += black_box(buf).len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn payload(len: usize) -> Bytes {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn send_all(socket: &mut WebSocket<Sink>, payload: &Bytes, messages: usize) {
    for _ in 0..messages {
        socket
            .send(Message::Binary(payload.clone()))
            .expect("send message");
    }
}

fn main() {
    // correctness preflight, outside any timing
    for len in MESSAGE_LENS {
        let mut socket = WebSocket::from_raw_socket(Sink::default(), Role::Server, None);
        send_all(&mut socket, &payload(*len), 3);
        assert!(socket.get_ref().written > 3 * len);
    }

    divan::main();
}

fn send_binary(bencher: divan::Bencher, role: Role, len: usize) {
    let payload = payload(len);
    let messages = TOTAL_BYTES / len;
    let mut socket = WebSocket::from_raw_socket(Sink::default(), role, None);
    bencher
        .counter(BytesCount::new(messages * len))
        .bench_local(|| send_all(&mut socket, black_box(&payload), messages));
}

#[divan::bench(args = MESSAGE_LENS, sample_count = 50)]
fn send_binary_unmasked(bencher: divan::Bencher, len: usize) {
    send_binary(bencher, Role::Server, len);
}

#[divan::bench(args = MESSAGE_LENS, sample_count = 50)]
fn send_binary_masked(bencher: divan::Bencher, len: usize) {
    send_binary(bencher, Role::Client, len);
}

/// Payloads the socket owns exclusively, as an application that builds each message does.
fn send_owned(bencher: divan::Bencher, role: Role, len: usize) {
    let messages = TOTAL_BYTES / len;
    let mut socket = WebSocket::from_raw_socket(Sink::default(), role, None);
    bencher
        .counter(BytesCount::new(messages * len))
        .with_inputs(|| (0..messages).map(|_| payload(len)).collect::<Vec<_>>())
        .bench_local_values(|payloads| {
            for payload in payloads {
                socket
                    .send(Message::Binary(black_box(payload)))
                    .expect("send message");
            }
        });
}

#[divan::bench(args = MESSAGE_LENS, sample_count = 50)]
fn send_owned_unmasked(bencher: divan::Bencher, len: usize) {
    send_owned(bencher, Role::Server, len);
}

#[divan::bench(args = MESSAGE_LENS, sample_count = 50)]
fn send_owned_masked(bencher: divan::Bencher, len: usize) {
    send_owned(bencher, Role::Client, len);
}
