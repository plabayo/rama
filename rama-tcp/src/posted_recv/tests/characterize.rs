//! Characterization of how a plain tokio `TcpStream` sees data that arrives
//! right before a reset. These only print what the OS does, since asserting
//! it would be brittle; run them with `--run-ignored=only`.

use std::time::Duration;

use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::harness::{
    Close, FORCED_DELAY, Origin, SIZES, Tally, exchange, read_until_end, spawn_origin, tally,
};

async fn plain_tally(origin: &Origin, len: usize, runs: usize, delay: Duration) -> Tally {
    let addr = origin.addr;
    tally(runs, 32, len, move || async move {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        exchange(&mut stream, delay).await
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints OS behaviour"]
async fn forced_delay_reply_then_reset() {
    if !super::harness::characterizing() {
        return;
    }
    for len in SIZES {
        let origin = spawn_origin(len, Close::Reset).await;
        let tally = plain_tally(&origin, len, 200, FORCED_DELAY).await;
        eprintln!("ws0/1 forced delay, plain tokio, N={len}: {tally}");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints OS behaviour"]
async fn natural_race_reply_then_reset() {
    if !super::harness::characterizing() {
        return;
    }
    for len in SIZES {
        let origin = spawn_origin(len, Close::Reset).await;
        let tally = plain_tally(&origin, len, 1000, Duration::ZERO).await;
        eprintln!("ws0/2 natural race, idle runtime, plain tokio, N={len}: {tally}");
    }
}

/// A current-thread runtime whose only worker is kept busy by filler tasks,
/// which widens the window between readiness and the actual `recv`.
#[test]
#[ignore = "characterization: prints OS behaviour"]
fn natural_race_busy_runtime() {
    if !super::harness::characterizing() {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let busy = super::harness::spawn_filler(8);
        for len in SIZES {
            let origin = spawn_origin(len, Close::Reset).await;
            let tally = plain_tally(&origin, len, 1000, Duration::ZERO).await;
            eprintln!("ws0/2 natural race, busy runtime, plain tokio, N={len}: {tally}");
        }
        busy.stop().await;
    });
}

/// The origin replies and closes gracefully; the client writes once more
/// before reading, which makes the origin answer with a reset.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints OS behaviour"]
async fn send_after_peer_close() {
    if !super::harness::characterizing() {
        return;
    }
    for len in SIZES {
        let origin = spawn_origin(len, Close::Fin).await;
        let addr = origin.addr;
        let tally = tally(200, 32, len, move || async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(super::harness::REQUEST).await.unwrap();
            tokio::time::sleep(FORCED_DELAY).await;
            _ = stream.write_all(b"late").await;
            tokio::time::sleep(FORCED_DELAY).await;
            read_until_end(&mut stream).await
        })
        .await;
        eprintln!("ws0/3 send after peer close, plain tokio, N={len}: {tally}");
    }
}

/// rama#1156: the origin closes with the request still unread, so its close
/// goes out as a reset.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints OS behaviour"]
async fn close_with_unread_input() {
    if !super::harness::characterizing() {
        return;
    }
    for len in SIZES {
        let origin = spawn_origin(len, Close::UnreadInput).await;
        let tally = plain_tally(&origin, len, 200, FORCED_DELAY).await;
        eprintln!("ws0/4 close with unread input, plain tokio, N={len}: {tally}");
    }
}
