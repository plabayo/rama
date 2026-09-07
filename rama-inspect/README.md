# rama-inspect

Reusable inspection building blocks for Rama services. Share controller handles with
an HTTP API, native GUI, TUI, or another service; there is no required interface trait.

| Module / feature | Responsibility |
| --- | --- |
| `lifecycle` | Shared pause boundary, writer permits, cancellable sessions |
| `intercept` | Typed `Interception<Message, Decision>`, bounded admission, cancellation, deadlines, atomic decisions |
| `subscription` | Initial query content followed by refreshed views; coalesces slow consumers |
| `storage` | Streaming record services, logical IDs, retained readers; memory backend included |
| `fs` | Temporary file backend using `rama-utils::fs`, one append lock per collection |
| `encryption` | `EncryptLayer` over any storage service; authenticated bounded chunks using BoringSSL |
| `http` | HTTP capture, retention, filtering, replay reconstruction, HAR conversion and traffic controls |
| `tls` | Optional TLS capture metadata and fingerprints |
| `profiles` | Optional observed user-agent profiles and recognition; includes TLS metadata |
| `websocket` | WebSocket capture, interception and injection adapters; includes HTTP handshake support |

Default features contain no HTTP, WebSocket, TLS or user-agent dependency.
Through the `rama` facade, enable `inspect` with the protocol features you use;
`inspect-fs`, `inspect-encryption`, and `inspect-profiles` select optional storage
and profile support. Protocol
modules live here rather than in their protocol crates, avoiding dependency cycles.
The existing HTTP/WebSocket control JSON vocabulary is retained for CLI compatibility;
custom protocols use their own message and decision types with the generic queue.

## Storage composition

```rust
use rama_core::{Layer, Service};
use rama_inspect::storage::{CreateCollection, FileStore, StorageLimits, encrypt::EncryptLayer};
use tokio::io::AsyncReadExt;

# async fn example() -> Result<(), rama_core::error::BoxError> {
let storage = EncryptLayer::random()?.layer(FileStore::temporary(StorageLimits {
    total_bytes: 512 * 1024 * 1024,
    record_bytes: 16 * 1024 * 1024,
})?);
let collection = storage.serve(CreateCollection { id: 1 }).await?;
let id = collection.append(std::io::Cursor::new(b"captured record")).await?;
let mut reader = collection.read(id).await?;
let mut output = tokio::io::sink();
tokio::io::copy(&mut reader, &mut output).await?;
# Ok(()) }
```

Inputs and outputs are `AsyncRead`; pipe readers into an HTTP body, another file,
or a native UI. `ReadRecord` optionally selects a byte range. A custom factory is a
Rama `Service<CreateCollection, Output = Collection>`. Its collection implements
three small services: `AppendRecord`, `ReadRecord`, and `ListRecords`. None exposes
paths, file handles, encryption keys, or physical offsets. `Collection::new` erases
only this composition boundary.

An append is one logical record. Success publishes it; cancellation publishes
nothing. There is no user-facing commit operation. A filesystem append remembers
its last committed boundary before starting writes. On the next append it settles
pending filesystem work, truncates an interrupted tail and seeks to that boundary.
Earlier records remain readable. An unfinished file tail keeps its storage allowance
until recovery removes it or the collection is released. This is cancellation safety, not crash durability;
the supplied filesystem backend is temporary session storage.

Use bounded records for incremental publication. A live collection can contain many
records; readers can pin existing records while capture continues. Dropping all
collections and readers releases their storage. Clearing or evicting a capture does
not invalidate an export that already owns it. Different collections append in
parallel; one collection serializes appends. The HTTP adapter uses one collection
per exchange (including each HTTP/2 stream); WebSocket messages share their handshake
collection. Neither stores an entire HTTP/1 keepalive connection in one file.

Encryption authenticates each chunk before yielding plaintext and binds chunks to
the collection, record identity, position, and final marker. It buffers at most a
bounded chunk in each direction. Range reads currently authenticate and skip the
preceding chunks; a partial read does not verify unread later content. Storage limits
apply to the bytes seen by that backend, hence ciphertext when below encryption.

## A custom protocol

```rust
use rama_inspect::intercept::{Interception, QueueLimits};
use std::time::Duration;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
#[derive(Debug)]
struct Message { channel: u32, payload: Vec<u8> }
#[derive(Debug)]
enum Decision { Continue, Discard }
let controller = Interception::<Message, Decision>::default();
let message = Message { channel: 7, payload: vec![1, 2, 3] };
let retained = message.payload.len() + std::mem::size_of::<Message>();
let ticket = controller.enqueue(message, retained, QueueLimits::default())?;
// A GUI/API can observe controller.subscribe() and resolve by ticket ID.
controller.resolve(ticket.id(), Decision::Continue);
let decision = ticket.wait(Duration::from_secs(30)).await;
// The protocol adapter decides how to handle timeout, cancellation and each decision.
# Ok(()) }
```

Adapters supply admission costs because they know their message representation.
Those costs are not required UI data. The queue owns only the editable message and
reply channel; the protocol adapter continues to own its transport and body stream.
Dropping a ticket releases its admission. Validation and resolution can run atomically
with `resolve_with`, and `release_where` resolves related waits together.

## HTTP and native interfaces

```rust
use rama_core::{Service, futures::StreamExt};
use rama_inspect::{InspectionState, http::capture::{CaptureConfig, CaptureHttpLayer, CaptureQuery, CaptureStore}, storage::{MemoryStore, Storage, StorageLimits}};

# async fn example() -> Result<(), rama_core::error::BoxError> {
let captures = CaptureStore::with_storage(
    Storage::new(MemoryStore::new(StorageLimits::default())),
    CaptureConfig::default(),
    InspectionState::default(),
);
let layer = CaptureHttpLayer::new(Some(captures.clone()));
// Apply `layer` to your HTTP service. Share these handles with your UI:
let controls = captures.control();
let mut views = Box::pin(captures.subscribe(CaptureQuery::default()));
let initial = views.next().await;
// Subsequent views contain refreshed typed summaries. Body bytes stream separately.
# Ok(()) }
```

`rama-cli serve proxy` selects encrypted file storage, assembles protocol layers,
and exposes its existing GUI plus a documented token-authenticated HTTP API. Use
`--mitm --inspect-json` for machine-readable readiness and fetch `/api` or `/api/help`
with the startup bearer token. An agent may attach to a human-started proxy or launch
one itself; MCP is not required for clients with ordinary HTTP access.
