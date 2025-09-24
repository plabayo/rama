use super::utils;
use rama::Context;
use rama::futures::StreamExt;
use rama::graceful::Shutdown;
use rama::net::address::Authority;
use rama::stream::codec::FramedRead;
use rama::stream::json::JsonDecoder;
use rama::tcp::client::default_tcp_connect;
use rama::telemetry::tracing;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::oneshot;

#[tokio::test]
#[ignore]
async fn test_tcp_nd_json() {
    utils::init_tracing();

    let (exit_tx, exit_rx) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(exit_rx);

    shutdown.spawn_task_fn(async move |guard| {
        let runner = utils::ExampleRunner::interactive("tcp_nd_json", None);
        guard.cancelled().await;
        tracing::info!("exit runner");
        drop(runner);
        tracing::info!("runner dropped");
    });

    let mut try_count = 0;
    let stream = loop {
        tokio::time::sleep(Duration::from_secs(try_count * 2)).await;
        match default_tcp_connect(&Context::default(), Authority::local_ipv4(62042)).await {
            Ok((stream, _)) => break stream,
            Err(err) => tracing::error!(
                "#{}: failed to connect to example listener: {err}",
                try_count + 1
            ),
        }
        try_count += 1;
        if try_count >= 12 {
            panic!("failed to connect to example listener: try loop exhausted");
        }
    };

    tracing::info!("Connection Established");

    #[derive(Debug, Clone, Deserialize)]
    #[allow(dead_code)]
    struct OrderEvent {
        item: String,
        quantity: u32,
        prepaid: bool,
    }

    let mut reader = FramedRead::new(stream, JsonDecoder::<OrderEvent>::new());
    let mut unique_events = HashSet::new();

    let mut event_count = 0;
    while let Some(order_event) = tokio::time::timeout(Duration::from_secs(3), reader.next())
        .await
        .unwrap()
    {
        let order_event = order_event.unwrap();
        event_count += 1;
        tracing::info!("received event #{event_count}: {order_event:?}");
        assert!(!order_event.item.is_empty());
        unique_events.insert(order_event.item);
    }
    assert_eq!(28, event_count);
    assert_eq!(22, unique_events.len());

    tracing::info!("trigger shutdown...");
    exit_tx.send(()).unwrap();
    tracing::info!("...wait for shutdown...");
    shutdown
        .shutdown_with_limit(Duration::from_secs(5))
        .await
        .unwrap();
    tracing::info!("bye");
}
