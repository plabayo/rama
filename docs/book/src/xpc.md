# 🍎 Apple XPC

> XPC is Apple's inter-process communication (IPC) framework. It provides structured,
> asynchronous message passing between processes on the same machine, backed by
> the kernel's Mach IPC layer. It is the standard way for macOS and iOS system software
> to decompose an application into isolated, cooperating processes.
>
> Source: [Apple Developer Documentation — XPC](https://developer.apple.com/documentation/xpc)

Rama supports Apple XPC through the `rama-net-apple-xpc` crate, or via
the `rama` mono crate when enabled with the `net-apple-xpc` feature flag.
It is only compiled on Apple (vendor) targets.

## What XPC Is

XPC is a local-only IPC mechanism. There is no network socket, no TCP, no TLS. Instead,
XPC messages travel through Mach ports — kernel-mediated channels that can carry typed
data, file descriptors, and even connection endpoints between processes.

Because the kernel mediates every message, XPC has properties that socket-based IPC
cannot match:

- **No eavesdropping.** Only the two connected processes see the data.
- **Unforgeable peer identity.** The kernel authenticates the peer. You can query its PID,
  effective UID, effective GID, and audit session ID directly from the connection handle.
- **Signed-binary verification.** Apple's peer requirement APIs let you require the connecting
  process to carry a specific code signature, team identity, or entitlement — all enforced by
  the kernel before a single message is delivered.

## Core Terminology

**Mach port** — The kernel primitive underlying XPC. A Mach port is a unidirectional channel
capable of carrying messages and kernel resources (file descriptors, memory, other ports).
XPC manages Mach ports on your behalf; you never touch them directly.

**Service name** — The name used to locate a listener through launchd, the macOS service
manager. A service name looks like a reverse-DNS string: `com.example.myservice`. launchd
maps names to processes; the kernel does the rest.

**Listener** — A process that registers under a service name and accepts incoming peer
connections. In Rama this is `XpcListener`. Each accepted connection is delivered as an
`XpcConnection`.

**Connection** — A bidirectional channel between two processes. Each side can send messages
and receive events. In Rama this is `XpcConnection`, which integrates with Tokio and
implements the `Service` trait.

**Endpoint** — A serializable reference to a listener. An endpoint can be embedded inside
an XPC message and sent to a third process, which can then call `into_connection()` to
establish a peer connection without knowing any service name. Endpoints are the key to
bootstrapping connections without launchd registration.

**Message** — A typed value sent over a connection. XPC messages are always rooted in
either a dictionary or another primitive type. In Rama, messages are represented by
`XpcMessage`, an enum covering all native XPC types: booleans, integers, floats, strings,
binary data, file descriptors, UUIDs, dates, endpoints, arrays, and dictionaries.

**Event handler** — XPC connections are event-driven. In Rama, the event handler is bridged
into a Tokio channel; you receive events by calling `conn.recv().await`.

**Peer requirement** — A security constraint set on a connection before it is activated.
If the remote process does not satisfy the requirement, the connection is invalidated before
any message is delivered. In Rama this is `PeerSecurityRequirement`.

## The Two Roles

Every XPC conversation has a listener side and a client side.

**Listener (server)**

The listener creates an `XpcListener` bound to a service name. The name must be registered
with launchd via a plist file before the process starts — XPC does not support ad-hoc
binding the way TCP does. Once bound, `listener.accept().await` delivers each incoming peer
as an `XpcConnection`.

**Client**

The client creates an `XpcConnection` via `XpcConnection::connect(XpcClientConfig::new("com.example.myservice"))`,
or constructs an `XpcConnector` for use inside a Rama service stack. The connection is
lazy — no handshake happens until the first message is sent or a peer requirement is applied.

## Message Passing Patterns

XPC supports two patterns, both available on `XpcConnection`:

**Fire-and-forget** — `conn.send(message)` delivers the message with no expectation of a
reply. The call returns as soon as the message is queued.

**Request-reply** — `conn.send_request(message).await` delivers the message and awaits a
reply. The server calls `received.reply(response)` to satisfy the pending future. The reply
must be a `Dictionary`.

The server receives all incoming messages (and connection lifecycle events) via
`conn.recv().await`, which returns an `XpcEvent`.

For peer connections this is usually either:

- `Message`
- `Error`

For listener-style connections, including anonymous listeners created via
`XpcEndpoint::anonymous_channel`, the first meaningful event is:

- `Connection(XpcConnection)`

That accepted peer connection then yields the usual message/error stream.

## Security Model

XPC's security is built in, not bolted on.

By default, any process on the same machine that knows the service name can connect.
To restrict access, set a `PeerSecurityRequirement` on the connection before first use:

- `CodeSigning(requirement)` — validates the peer against a code signing requirement string
- `TeamIdentity(id)` — requires a specific Apple Developer team identity
- `PlatformIdentity(id)` — requires a platform-signed binary (Apple internal)
- `EntitlementExists(key)` / `EntitlementMatchesValue { key, value }` — requires the peer
  binary to carry specific entitlements
- `LightweightCodeRequirement(lcr)` — modern constraint format introduced in macOS 13;
  preferred over legacy code signing strings for new code

Peer requirements are applied before the connection is activated. If the peer fails the
check, you receive an `XpcConnectionError::PeerRequirementFailed` — no messages are
exchanged.

## Typical Use Cases

**System service decomposition** — macOS apps are often split into a privileged helper
daemon (running as root) and an unprivileged UI process. XPC is the standard channel
between them. The helper registers under a launchd service name; the app connects by name.
Peer requirements ensure only the signed app binary can reach the daemon.

**Network Extension control plane** — When building a `NETransparentProxyProvider` or
other Network Extension, the extension process and the host application communicate via XPC.
This is how configuration, start/stop commands, and telemetry flow between the sandboxed
extension and the UI.

See [Operating Transparent Proxies on macOS](./proxies/operate/transparent/macos.md).

**Endpoint hand-off** — A server can accept a connection, create an `XpcEndpoint` from it,
and embed that endpoint in a message to a third process. The third process calls
`endpoint.into_connection()` to establish a direct channel — no service name required.
This pattern avoids launchd registration for dynamically created services.

**Privilege separation** — A Rust daemon can offload sensitive operations (keychain access,
network configuration, certificate management) to a privileged XPC service, keeping the
main application unprivileged and sandboxed.

## Gotchas and Constraints

**launchd registration is required for named services.** `XpcListener` binds to a Mach
service name through launchd. The plist file must be installed and loaded before the
process starts. There is no equivalent of `bind()` on a TCP socket for ad-hoc services
without launchd. Use `XpcEndpoint` to pass connection references out-of-band if you need
dynamic services.

**NSXPCConnection is a different protocol.** Most Swift and Objective-C XPC services use
`NSXPCConnection`, which is a Foundation-layer abstraction over raw XPC. It uses
`NSKeyedArchiver` serialization inside XPC data objects — a completely different framing
from raw libXPC dictionaries. `rama-net-apple-xpc` speaks raw libXPC and is not compatible
with `NSXPCConnection` services out of the box.

**This crate does not yet expose the full Apple XPC surface.** It currently focuses on
the raw-XPC pieces needed for structured message passing, endpoint handoff, request-reply,
peer verification, and a first Rama-native server adapter. It does not yet provide:

- typed request/response codecs or higher-level XPC routing helpers on top of `XpcServer<S>`
- launchd/plist-driven end-to-end examples in this book
- compatibility with Foundation `NSXPCConnection`
- wrappers for every newer Apple XPC API family beyond the current raw connection/endpoint model

Contributions are appreciated and welcome.

**`suspend` and `resume` must be balanced.** Calling `conn.suspend()` without a matching
`conn.resume()` before the connection is released will crash the process. Imbalanced
suspends are a programming error, not a runtime error.

**`cancel` is idempotent.** Calling `conn.cancel()` multiple times is safe. The connection
is also cancelled automatically when it is dropped.

**Connections are lazy.** On the client side, no handshake occurs until the first message
is sent. Peer requirement failures surface as `XpcConnectionError::PeerRequirementFailed`
in the event stream, not at construction time.

## Integration with Rama

`XpcConnection` implements `rama_core::Service<XpcMessage>` (fire-and-forget send) and
`rama_core::ExtensionsRef` (typed extension storage). `XpcConnector` implements
`Service<XpcClientConfig>` and fits into any Rama client service stack. `XpcServer<S>`
accepts peer connections and dispatches incoming `XpcMessage` values into a regular
Rama service returning `Option<XpcMessage>`, which is enough for the first host-app /
Network Extension style control-plane flows.

Feature flag: `net-apple-xpc`. Only compiled on `target_vendor = "apple"`.

Crate docs: <https://ramaproxy.org/docs/rama_net_apple_xpc/index.html>

Apple XPC reference: <https://developer.apple.com/documentation/xpc>

## Examples: Anonymous Echo and Request/Reply Control Plane

The `xpc_echo` example demonstrates all three XPC message patterns in a single
self-contained binary — no launchd registration or plist required:

```sh
cargo run --example xpc_echo --features=net-apple-xpc
```

It uses `XpcEndpoint::anonymous_channel` to create an in-process anonymous listener plus
endpoint, then serves it through `XpcServer<S>` and exercises fire-and-forget send,
request-reply, and connection shutdown.
Source: [`examples/xpc_echo.rs`](https://github.com/plabayo/rama/blob/main/examples/xpc_echo.rs)

For a control-plane shaped example closer to a host-app / Network Extension workflow:

```sh
cargo run --example xpc_ca_exchange --features=net-apple-xpc
```

That example models a client requesting CA material over XPC request/reply instead of
pushing it through some unrelated opaque configuration transport.
Source: [`examples/xpc_ca_exchange.rs`](https://github.com/plabayo/rama/blob/main/examples/xpc_ca_exchange.rs)
