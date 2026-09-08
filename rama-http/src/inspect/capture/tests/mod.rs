use super::*;
use crate::HeaderValue;
use rama_core::extensions::ExtensionsRef as _;
use rama_core::futures::StreamExt as _;
use std::{convert::Infallible, time::Duration};
use tokio::task::JoinSet;

fn test_store() -> CaptureStore {
    test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1))
}

fn test_store_with_limits(
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
) -> CaptureStore {
    CaptureStore::with_storage(
        rama_inspect::storage::Storage::new(rama_inspect::storage::MemoryStore::new(
            Default::default(),
        )),
        CaptureConfig {
            max_connections,
            max_exchanges,
            body_limit,
            total_limit: 0,
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    )
}
fn test_store_with_total_limit(
    max_exchanges: usize,
    body_limit: u64,
    total_limit: u64,
) -> CaptureStore {
    CaptureStore::with_storage(
        rama_inspect::storage::Storage::new(rama_inspect::storage::MemoryStore::new(
            Default::default(),
        )),
        CaptureConfig {
            max_connections: 8,
            max_exchanges,
            body_limit,
            total_limit,
            ..CaptureConfig::default()
        },
        InspectionState::default(),
    )
}
fn decoded_body(records: &[StoredRecord], request: bool) -> Vec<u8> {
    records
        .iter()
        .filter_map(|record| match (request, record) {
            (true, StoredRecord::RequestBody { data })
            | (false, StoredRecord::ResponseBody { data }) => Some(data.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

// These tests assert forwarding boundaries, rather than the controller's implementation.
#[derive(Debug)]
struct ApprovalBody {
    polls: Arc<AtomicUsize>,
    bytes: Option<Bytes>,
}
impl StreamingBody for ApprovalBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<crate::body::Frame<Bytes>, Infallible>>> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Ready(
            self.bytes
                .take()
                .map(|bytes| Ok(crate::body::Frame::data(bytes))),
        )
    }
}
async fn approval_id(store: &CaptureStore, direction: &str) -> u64 {
    let control = store.control();
    let mut changes = control.subscribe_changes();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = serde_json::to_value(control.snapshot()).unwrap();
            if let Some(message) = snapshot["pending"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["direction"] == direction)
            {
                return message["id"].as_u64().unwrap();
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("approval did not arrive")
}

mod connections;

mod records;

mod storage;

mod interception;

mod query;
