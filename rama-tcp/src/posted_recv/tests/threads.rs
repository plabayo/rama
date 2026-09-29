//! The completion threads: their configuration, how they scale with the
//! load, and that several of them completing receives of the same stream
//! keep every stream intact.
//!
//! The threads are process-wide, so the tests that count them only assert
//! when this test has the process to itself, as under nextest.

use std::time::Duration;

use crate::posted_recv::{
    CompletionThreads, completion_threads, running_completion_threads, set_completion_threads,
};

#[cfg(target_os = "windows")]
use {
    super::harness::{Close, FORCED_DELAY, REQUEST, exchange, reply, spawn_origin, tally},
    crate::{
        TcpStream, TokioTcpStream,
        posted_recv::{PostedRecv, PostedRecvConfig},
    },
    rama_utils::octets::{kib, mib},
    std::time::Instant,
    tokio::io::AsyncReadExt,
};

fn isolated() -> bool {
    std::env::var_os("NEXTEST").is_some()
}

#[test]
fn config_keeps_its_bounds_consistent() {
    let default = CompletionThreads::new();
    assert_eq!(default.min_threads(), 1);
    assert!((1..=8).contains(&default.max_threads()));
    assert_eq!(default.idle_timeout(), Duration::from_secs(30));

    let raised = CompletionThreads::new()
        .with_max_threads(2)
        .with_min_threads(4);
    assert_eq!((raised.min_threads(), raised.max_threads()), (4, 4));

    let clamped = CompletionThreads::new()
        .with_min_threads(3)
        .with_max_threads(1);
    assert_eq!((clamped.min_threads(), clamped.max_threads()), (3, 3));

    let floor = CompletionThreads::new()
        .with_min_threads(0)
        .with_idle_timeout(Duration::ZERO);
    assert_eq!(floor.min_threads(), 1);
    assert_eq!(floor.idle_timeout(), Duration::from_millis(1));

    let single = CompletionThreads::single();
    assert_eq!((single.min_threads(), single.max_threads()), (1, 1));
}

#[test]
fn config_is_process_wide() {
    if !isolated() {
        return;
    }
    assert_eq!(completion_threads(), CompletionThreads::new());
    let config = CompletionThreads::new()
        .with_max_threads(3)
        .with_idle_timeout(Duration::from_secs(5));
    set_completion_threads(config);
    assert_eq!(completion_threads(), config);
    #[cfg(not(target_os = "windows"))]
    assert_eq!(running_completion_threads(), 0);
}

#[cfg(target_os = "windows")]
async fn connect(addr: std::net::SocketAddr, config: &PostedRecvConfig) -> PostedRecv<TcpStream> {
    let stream = TokioTcpStream::connect(addr).await.unwrap();
    let stream = PostedRecv::with_config(TcpStream::new(stream), config);
    assert!(stream.is_posted());
    stream
}

#[cfg(target_os = "windows")]
async fn wait_for_threads(expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while running_completion_threads() != expected {
        assert!(
            Instant::now() < deadline,
            "expected {expected} completion threads, {} run",
            running_completion_threads()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A raised minimum starts threads right away; a lowered maximum stops the
/// extra ones once they are idle.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn threads_follow_the_configured_bounds() {
    if !isolated() {
        return;
    }
    let idle = Duration::from_millis(50);
    set_completion_threads(
        CompletionThreads::new()
            .with_max_threads(4)
            .with_idle_timeout(idle),
    );
    assert_eq!(
        running_completion_threads(),
        0,
        "threads start on first use"
    );

    let len = SIZES_SMALL;
    let origin = spawn_origin(len, Close::Fin).await;
    let mut stream = connect(origin.addr, &PostedRecvConfig::default()).await;
    assert!(exchange(&mut stream, Duration::ZERO).await.is_complete(len));
    assert_eq!(running_completion_threads(), 1);

    set_completion_threads(
        CompletionThreads::new()
            .with_min_threads(3)
            .with_max_threads(4)
            .with_idle_timeout(idle),
    );
    assert_eq!(running_completion_threads(), 3);

    // Above the minimum again, idle threads exit.
    set_completion_threads(
        CompletionThreads::new()
            .with_max_threads(4)
            .with_idle_timeout(idle),
    );
    wait_for_threads(1).await;

    // A maximum lowered below the running threads stops the extra ones.
    set_completion_threads(
        CompletionThreads::new()
            .with_min_threads(3)
            .with_idle_timeout(idle),
    );
    wait_for_threads(3).await;
    set_completion_threads(CompletionThreads::single().with_idle_timeout(idle));
    wait_for_threads(1).await;

    // The remaining thread still completes receives.
    let mut stream = connect(origin.addr, &PostedRecvConfig::default()).await;
    assert!(exchange(&mut stream, Duration::ZERO).await.is_complete(len));
}

#[cfg(target_os = "windows")]
const SIZES_SMALL: usize = 6554;

/// Under a bulk load the threads grow past one, never past the maximum,
/// and go back to the minimum once the load is gone.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn threads_scale_with_the_load() {
    if !isolated() {
        return;
    }
    let max = 4;
    set_completion_threads(
        CompletionThreads::new()
            .with_max_threads(max)
            .with_idle_timeout(Duration::from_millis(200)),
    );
    let len = mib(8);
    let origin = spawn_origin(len, Close::Fin).await;
    let addr = origin.addr;

    let sampling = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sampler = {
        let sampling = sampling.clone();
        tokio::spawn(async move {
            let mut peak = 0;
            while sampling.load(std::sync::atomic::Ordering::Relaxed) {
                peak = peak.max(running_completion_threads());
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            peak
        })
    };
    let seen = tally(64, 64, len, move || async move {
        let mut stream = connect(addr, &PostedRecvConfig::default()).await;
        exchange(&mut stream, Duration::ZERO).await
    })
    .await;
    sampling.store(false, std::sync::atomic::Ordering::Relaxed);
    let peak = sampler.await.unwrap();
    assert_eq!(seen.complete, 64, "{seen}");
    eprintln!("peak completion threads under load: {peak}");
    assert!(peak >= 2, "the threads never grew under load");
    assert!(peak <= max, "{peak} threads is over the maximum of {max}");

    wait_for_threads(1).await;
}

/// With several threads completing receives of the same stream at once,
/// every stream still comes out whole and in order, ends right, and closes.
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread")]
async fn many_threads_keep_every_stream_intact() {
    set_completion_threads(
        CompletionThreads::new()
            .with_min_threads(4)
            .with_max_threads(4),
    );

    // Tiny slots make many completions per stream, completed concurrently.
    let tiny = PostedRecvConfig::new()
        .with_slots(8)
        .with_slot_size(7)
        .with_max_buffered(kib(1));
    let len = kib(256);
    let origin = spawn_origin(len, Close::Fin).await;
    let addr = origin.addr;
    let config = tiny.clone();
    let seen = tally(20, 20, len, move || {
        let tiny = config.clone();
        async move {
            let mut stream = connect(addr, &tiny).await;
            exchange(&mut stream, Duration::ZERO).await
        }
    })
    .await;
    assert_eq!(seen.complete, 20, "tiny slots: {seen}");
    assert_eq!(seen.ends, [(None, None)], "tiny slots: {seen}");

    // A slow reader: completions race the reader for the flow lock.
    let origin = spawn_origin(len, Close::Fin).await;
    let mut stream = connect(origin.addr, &tiny).await;
    tokio::io::AsyncWriteExt::write_all(&mut stream, REQUEST)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    let mut buf = [0; 97];
    loop {
        match stream.read(&mut buf).await.unwrap() {
            0 => break,
            n => bytes.extend_from_slice(&buf[..n]),
        }
        if bytes.len() % 7 == 0 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(bytes, reply(len));

    // Bulk flows and resets, many at once.
    let len = kib(256);
    let origin = spawn_origin(len, Close::Fin).await;
    let addr = origin.addr;
    let seen = tally(200, 100, len, move || async move {
        let mut stream = connect(addr, &PostedRecvConfig::default()).await;
        exchange(&mut stream, Duration::ZERO).await
    })
    .await;
    assert_eq!(seen.complete, 200, "bulk: {seen}");

    let len = SIZES_SMALL;
    let origin = spawn_origin(len, Close::Reset).await;
    let addr = origin.addr;
    let seen = tally(500, 100, len, move || async move {
        let mut stream = connect(addr, &PostedRecvConfig::default()).await;
        exchange(&mut stream, FORCED_DELAY).await
    })
    .await;
    assert_eq!(seen.complete, 500, "resets: {seen}");
    assert!(
        seen.ends
            .iter()
            .all(|(_, kind)| *kind == Some(std::io::ErrorKind::ConnectionReset)),
        "resets: {seen}"
    );
}

/// The threads record their lifecycle on the dial9 recorder of the thread
/// that started them.
#[cfg(all(target_os = "windows", feature = "dial9"))]
#[test]
fn threads_record_dial9_events() {
    if !isolated() {
        return;
    }
    let dir = rama_utils::fs::tempdir().unwrap();
    let writer = ::dial9::DiskBuffer::builder()
        .base_path(dir.path())
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = ::dial9::recorder_or_disabled(writer).build();
    assert!(recorder.handle().is_enabled());
    ::dial9::core::set_tl_handle(recorder.handle().clone());

    let idle = Duration::from_millis(50);
    set_completion_threads(
        CompletionThreads::new()
            .with_max_threads(2)
            .with_idle_timeout(idle),
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let origin = spawn_origin(SIZES_SMALL, Close::Fin).await;
        let mut stream = connect(origin.addr, &PostedRecvConfig::default()).await;
        assert!(
            exchange(&mut stream, Duration::ZERO)
                .await
                .is_complete(SIZES_SMALL)
        );
        set_completion_threads(
            CompletionThreads::new()
                .with_min_threads(2)
                .with_idle_timeout(idle),
        );
        set_completion_threads(
            CompletionThreads::new()
                .with_max_threads(2)
                .with_idle_timeout(idle),
        );
        wait_for_threads(1).await;
    });
    drop(rt);
    ::dial9::core::clear_tl_handle();
    drop(recorder);

    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let data = std::fs::read(entry.unwrap().path()).unwrap();
        if let Some(mut decoder) = ::dial9::format::Decoder::new(&data) {
            decoder
                .for_each_event(|event| names.push(event.name.to_owned()))
                .unwrap();
        }
    }
    for expected in ["PostedRecvThreadStarted", "PostedRecvThreadStopped"] {
        assert!(
            names.iter().any(|name| name == expected),
            "no {expected} in {names:?}"
        );
    }
}
