//! Characterization of how a plain tokio `TcpStream` sees data that arrives
//! right before a reset. These only print what the OS does, since asserting
//! it would be brittle; run them with `--run-ignored=only`.

use std::{future::Future, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpStream, task::JoinSet};

use super::harness::{Close, Origin, Tally, exchange, read_until_end, spawn_origin};

pub(super) const SIZES: [usize; 3] = [234, 1843, 6554];
pub(super) const FORCED_DELAY: Duration = Duration::from_millis(30);
pub(super) const RESET_GAP: Duration = Duration::from_millis(5);

/// Run `runs` exchanges, `concurrency` at a time, and tally the outcomes.
pub(super) async fn tally<F, Fut>(runs: usize, concurrency: usize, len: usize, run: F) -> Tally
where
    F: Fn() -> Fut,
    Fut: Future<Output = super::harness::Received> + Send + 'static,
{
    let mut tally = Tally::default();
    let mut set = JoinSet::new();
    for _ in 0..runs {
        if set.len() >= concurrency
            && let Some(received) = set.join_next().await
        {
            tally.add(&received.unwrap(), len);
        }
        set.spawn(run());
    }
    while let Some(received) = set.join_next().await {
        tally.add(&received.unwrap(), len);
    }
    tally
}

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
    for len in SIZES {
        let origin = spawn_origin(len, Close::Reset, RESET_GAP).await;
        let tally = plain_tally(&origin, len, 200, FORCED_DELAY).await;
        eprintln!("ws0/1 forced delay, plain tokio, N={len}: {tally}");
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "characterization: prints OS behaviour"]
async fn natural_race_reply_then_reset() {
    for len in SIZES {
        let origin = spawn_origin(len, Close::Reset, Duration::ZERO).await;
        let tally = plain_tally(&origin, len, 1000, Duration::ZERO).await;
        eprintln!("ws0/2 natural race, idle runtime, plain tokio, N={len}: {tally}");
    }
}

/// A current-thread runtime whose only worker is kept busy by filler tasks,
/// which widens the window between readiness and the actual `recv`.
#[test]
#[ignore = "characterization: prints OS behaviour"]
fn natural_race_busy_runtime() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let busy = super::harness::spawn_filler(8);
        for len in SIZES {
            let origin = spawn_origin(len, Close::Reset, Duration::ZERO).await;
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
    for len in SIZES {
        let origin = spawn_origin(len, Close::Fin, Duration::ZERO).await;
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
    for len in SIZES {
        let origin = spawn_origin(len, Close::UnreadInput, RESET_GAP).await;
        let tally = plain_tally(&origin, len, 200, FORCED_DELAY).await;
        eprintln!("ws0/4 close with unread input, plain tokio, N={len}: {tally}");
    }
}
