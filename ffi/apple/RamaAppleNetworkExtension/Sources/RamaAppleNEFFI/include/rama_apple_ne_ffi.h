#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Threading & concurrency contract (violating any of this is UB).
 *
 * - Engine handle: methods are Send + Sync and may be called
 *   concurrently from any thread.
 * - Session handles: single-owner. Never make two concurrent FFI
 *   calls on the same pointer; the Swift wrappers serialise via
 *   NSLock and any other consumer must do the same.
 * - Cancellation (`_tcp_session_cancel`, `_udp_session_on_client_close`):
 *   flips the engine's `callback_active` guard, drops senders, signals
 *   shutdown, and returns. In-flight bridge dispatches that already
 *   passed the guard run to completion before `_session_free` releases
 *   the Swift callback box.
 * - `_session_free` / `_engine_stop`: consume the pointer. The Swift
 *   wrappers null their stored pointer so double-free is a no-op.
 * ==========================================================================*/

/// Opaque transparent proxy engine handle managed by Rust.
typedef struct RamaTransparentProxyEngine RamaTransparentProxyEngine;
/// Opaque TCP flow/session handle managed by Rust.
///
/// Concurrency: see the contract block at the top of this header. The
/// session is single-owner; no two concurrent FFI calls on the same
/// pointer.
typedef struct RamaTransparentProxyTcpSession RamaTransparentProxyTcpSession;
/// Opaque UDP flow/session handle managed by Rust.
///
/// Concurrency: see the contract block at the top of this header.
typedef struct RamaTransparentProxyUdpSession RamaTransparentProxyUdpSession;

/// Borrowed byte view.
///
/// Ownership is retained by the caller. `ptr` may be NULL only if `len == 0`.
typedef struct {
    /// Borrowed pointer to bytes.
    const uint8_t* ptr;
    /// Number of bytes at `ptr`.
    size_t len;
} RamaBytesView;

/// Owned byte buffer allocated by Rust.
///
/// Must be released with `rama_owned_bytes_free`.
typedef struct {
    /// Owned allocation pointer (or NULL when empty).
    uint8_t* ptr;
    /// Number of initialized bytes.
    size_t len;
    /// Allocation capacity.
    size_t cap;
} RamaBytesOwned;

/// Log level for `rama_log`.
typedef enum {
    /// Extremely verbose diagnostic logs.
    RAMA_LOG_LEVEL_TRACE = 0,
    /// Debug logs.
    RAMA_LOG_LEVEL_DEBUG = 1,
    /// Informational logs.
    RAMA_LOG_LEVEL_INFO = 2,
    /// Warning logs.
    RAMA_LOG_LEVEL_WARN = 3,
    /// Error logs.
    RAMA_LOG_LEVEL_ERROR = 4,
} RamaLogLevel;

/// Transport protocol for one intercepted flow.
typedef enum {
    /// TCP flow.
    RAMA_FLOW_PROTOCOL_TCP = 1,
    /// UDP flow.
    RAMA_FLOW_PROTOCOL_UDP = 2,
} RamaTransparentProxyFlowProtocol;

/// Flow policy action returned by Rust transparent-proxy policy code.
typedef enum {
    /// Intercept the flow and route it through the Rust engine.
    RAMA_FLOW_ACTION_INTERCEPT = 1,
    /// Leave the flow untouched and let the system handle it normally.
    RAMA_FLOW_ACTION_PASSTHROUGH = 2,
    /// Explicitly reject the flow.
    RAMA_FLOW_ACTION_BLOCKED = 3,
} RamaTransparentProxyFlowAction;

typedef struct {
    RamaTransparentProxyFlowAction action;
    RamaTransparentProxyTcpSession* session;
} RamaTransparentProxyTcpSessionResult;

typedef struct {
    RamaTransparentProxyFlowAction action;
    RamaTransparentProxyUdpSession* session;
} RamaTransparentProxyUdpSessionResult;

/// Protocol filter used by network interception rules.
typedef enum {
    /// Match any protocol.
    RAMA_RULE_PROTOCOL_ANY = 0,
    /// Match TCP only.
    RAMA_RULE_PROTOCOL_TCP = 1,
    /// Match UDP only.
    RAMA_RULE_PROTOCOL_UDP = 2,
} RamaTransparentProxyRuleProtocol;

/// Endpoint metadata (`host:port`) for one flow side.
///
/// If endpoint is not available, set `host_utf8 = NULL`, `host_utf8_len = 0`,
/// and `port = 0`.
///
/// Apple references:
/// - https://developer.apple.com/documentation/networkextension/neappproxytcpflow/remoteendpoint
/// - https://developer.apple.com/documentation/networkextension/neappproxyudpflow
typedef struct {
    /// UTF-8 hostname/IP bytes (not NUL-terminated). May be NULL.
    const char* host_utf8;
    /// Length of `host_utf8` bytes.
    size_t host_utf8_len;
    /// TCP/UDP port.
    uint16_t port;
} RamaTransparentProxyFlowEndpoint;

/// Per-flow metadata passed from Swift to Rust.
///
/// String fields are not C strings. They are UTF-8 byte slices
/// (`pointer + length`) and are not required to be NUL-terminated.
/// Optional string fields are absent when encoded as (`NULL`, `0`).
///
/// Apple references:
/// - https://developer.apple.com/documentation/networkextension/neappproxyflow/metadata
/// - https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappsigningidentifier
typedef struct {
    /// One of `RamaTransparentProxyFlowProtocol`.
    uint32_t protocol;
    /// Intended remote endpoint of this flow.
    RamaTransparentProxyFlowEndpoint remote_endpoint;
    /// Local endpoint assigned to this flow (if known).
    RamaTransparentProxyFlowEndpoint local_endpoint;
    /// Source app signing identifier UTF-8 bytes (not NUL-terminated). May be NULL.
    const char* source_app_signing_identifier_utf8;
    /// Length of `source_app_signing_identifier_utf8`.
    size_t source_app_signing_identifier_utf8_len;
    /// Source app bundle identifier UTF-8 bytes (not NUL-terminated). May be NULL.
    const char* source_app_bundle_identifier_utf8;
    /// Length of `source_app_bundle_identifier_utf8`.
    size_t source_app_bundle_identifier_utf8_len;
    /// Source app audit token bytes. May be NULL.
    const uint8_t* source_app_audit_token_bytes;
    /// Length of `source_app_audit_token_bytes`.
    size_t source_app_audit_token_bytes_len;
    /// Source app PID resolved by Swift when available.
    /// Only valid when `source_app_pid_is_set` is true.
    int32_t source_app_pid;
    /// Whether `source_app_pid` is explicitly set.
    bool source_app_pid_is_set;
} RamaTransparentProxyFlowMeta;

/// One transparent-proxy network rule used to build Apple NE settings.
///
/// Apple reference:
/// - https://developer.apple.com/documentation/networkextension/nenetworkrule
typedef struct {
    /// Optional remote network address UTF-8 bytes (not NUL-terminated). May be NULL.
    const char* remote_network_utf8;
    /// Length of `remote_network_utf8`.
    size_t remote_network_utf8_len;
    /// Prefix length for remote network (CIDR).
    /// Only valid when `remote_prefix_is_set` is true.
    uint8_t remote_prefix;
    /// Whether `remote_prefix` is explicitly set.
    bool remote_prefix_is_set;
    /// Optional local network address UTF-8 bytes (not NUL-terminated). May be NULL.
    const char* local_network_utf8;
    /// Length of `local_network_utf8`.
    size_t local_network_utf8_len;
    /// Prefix length for local network (CIDR).
    /// Only valid when `local_prefix_is_set` is true.
    uint8_t local_prefix;
    /// Whether `local_prefix` is explicitly set.
    bool local_prefix_is_set;
    /// One of `RamaTransparentProxyRuleProtocol`.
    uint32_t protocol;
} RamaTransparentProxyNetworkRule;

/// Transparent proxy configuration returned by Rust to Swift.
///
/// This structure owns its memory and must be released exactly once with
/// `rama_transparent_proxy_config_free`.
///
/// Apple references:
/// - https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings
/// - https://developer.apple.com/documentation/networkextension/netransparentproxyprovider
typedef struct {
    /// Placeholder tunnel remote address UTF-8 bytes (not NUL-terminated).
    const char* tunnel_remote_address_utf8;
    /// Length of `tunnel_remote_address_utf8`.
    size_t tunnel_remote_address_utf8_len;
    /// Pointer to `rules_len` rules (may be NULL when empty).
    const RamaTransparentProxyNetworkRule* rules;
    /// Number of rules at `rules`.
    size_t rules_len;
    /// Per-flow TCP write-pump back-pressure cap in bytes.
    /// Authoritative on the Swift side — the value emitted here is the
    /// value the pump uses. Default is 256 KiB; there is no
    /// "0 means unset" path.
    size_t tcp_write_pump_max_pending_bytes;
} RamaTransparentProxyConfig;

/// Initialization config passed once before using engine APIs.
///
/// All string fields are UTF-8 byte slices (`pointer + length`) and are not
/// required to be NUL-terminated.
typedef struct {
    /// Writable storage directory for Rust-managed state (certs, cache, etc).
    /// May be NULL/0 to let Rust choose a fallback directory.
    const char* storage_dir_utf8;
    /// Length of `storage_dir_utf8`.
    size_t storage_dir_utf8_len;
    /// Optional shared app-group directory if available.
    /// May be NULL/0 when no app-group is configured.
    const char* app_group_dir_utf8;
    /// Length of `app_group_dir_utf8`.
    size_t app_group_dir_utf8_len;
} RamaTransparentProxyInitConfig;

/// Outcome of `rama_transparent_proxy_tcp_session_on_client_bytes` /
/// `rama_transparent_proxy_tcp_session_on_egress_bytes`.
///
/// Swift MUST distinguish `Paused` from `Closed`:
///   * On `Paused`, pause reads and resume only when the matching
///     `on_*_read_demand` callback fires.
///   * On `Closed`, terminate the read pump immediately — no demand
///     callback will ever follow.
///
/// The underlying type is fixed at `uint8_t` to match the Rust side's
/// `#[repr(u8)]` exactly. Without the explicit `: uint8_t` the C standard
/// leaves the enum width implementation-defined (typically `int`), which
/// would mismatch the 1-byte Rust return on some ABIs / bindgen configs.
typedef enum : uint8_t {
    /// Bytes were queued; Swift may continue reading from the kernel.
    RAMA_TCP_DELIVER_ACCEPTED = 0,
    /// Per-flow channel is full; pause until on_*_read_demand fires.
    RAMA_TCP_DELIVER_PAUSED = 1,
    /// Per-flow channel is closed (session teardown); stop reading.
    RAMA_TCP_DELIVER_CLOSED = 2,
} RamaTcpDeliverStatus;

/// Returns a `RamaTcpDeliverStatus` so the Rust bridge can pause when Swift's
/// `TcpClientWritePump` is full. Swift MUST call
/// `rama_transparent_proxy_tcp_session_signal_server_drain` after its writer
/// drains capacity following a `Paused` return — without that the bridge
/// stays parked forever.
typedef RamaTcpDeliverStatus (*RamaTcpServerBytesFn)(void* context, RamaBytesView bytes);
typedef void (*RamaTcpServerClosedFn)(void* context);
typedef void (*RamaTcpClientReadDemandFn)(void* context);

/// Callbacks Swift provides for Rust TCP session events.
///
/// Lifetime / threading contract for `context`:
///   * `context` MUST remain valid (and the pointee MUST NOT move) until the
///     corresponding session has been freed via
///     `rama_transparent_proxy_tcp_session_free`. Calling
///     `rama_transparent_proxy_tcp_session_cancel` guarantees that no further
///     callbacks fire, but `context` must still outlive the `_free` call —
///     concurrent callbacks already in flight can still observe the pointer
///     until they complete.
///   * Callbacks may be invoked from any thread (Rust async runtime worker
///     threads). The Swift side is responsible for any synchronization the
///     pointee requires.
///   * `bytes` passed to `on_server_bytes` is borrowed for the duration of the
///     call; the receiver MUST copy any data it needs to retain.
typedef struct {
    /// Opaque user context passed back to callbacks. See lifetime contract above.
    void* context;
    /// Called when Rust has bytes to write to client-side TCP flow.
    RamaTcpServerBytesFn on_server_bytes;
    /// Called when Rust closes server-side TCP direction.
    RamaTcpServerClosedFn on_server_closed;
    /// Called when the Rust ingress channel has space again after
    /// `rama_transparent_proxy_tcp_session_on_client_bytes` returned `false`.
    /// Swift MUST keep `flow.readData` paused between the `false` return and
    /// this callback firing — otherwise bytes pile up in Apple's per-flow NE
    /// kernel buffer and eventually abort the shared NEAppProxyProvider
    /// director.
    RamaTcpClientReadDemandFn on_client_read_demand;
} RamaTransparentProxyTcpSessionCallbacks;

/// Per-datagram peer endpoint passed across the FFI in both directions.
///
/// `present = false` means the caller has no endpoint attribution for
/// this datagram (rare; usually a test or a kernel-callback edge case).
/// When `present = true`, `host_utf8` is the textual host — in
/// production this is a numeric IP literal because the kernel's
/// `flow.readDatagrams` returns resolved IPs and the per-peer
/// NWConnection's bound endpoint is also an IP. `host_utf8` is NOT
/// required to be NUL-terminated.
///
/// `scope_id` carries the IPv6 zone identifier (interface index, as
/// returned by `if_nametoindex(3)`) for link-local addresses like
/// `fe80::1%en0`. `0` means "no scope". The textual `host_utf8` MUST
/// NOT carry the `%zone` suffix — Swift converts the kernel-supplied
/// `"fe80::1%en0"` to the numeric index on the way in, and Rust
/// converts the numeric index back to an interface name on the way
/// out. Scoping is meaningless for IPv4 and must be `0` there.
///
/// Borrowed for the duration of the call; the Swift side may stage
/// the host bytes on the stack of the closure that issues the C call,
/// and the Rust side does the same in reverse.
typedef struct {
    bool present;
    const uint8_t* host_utf8;
    size_t host_utf8_len;
    uint16_t port;
    uint32_t scope_id;
} RamaUdpPeerView;

typedef void (*RamaUdpServerDatagramFn)(void* context, RamaBytesView bytes, RamaUdpPeerView peer);
typedef void (*RamaUdpClientReadDemandFn)(void* context);
typedef void (*RamaUdpServerClosedFn)(void* context);

/// Callbacks Swift provides for Rust UDP session events.
///
/// `context` lifetime / threading contract: see the matching contract on
/// `RamaTransparentProxyTcpSessionCallbacks` above. Same rules apply here — the
/// pointee must outlive the `*_free` call, callbacks may run on any thread, and
/// `bytes` is borrowed for the duration of each call.
typedef struct {
    /// Opaque user context passed back to callbacks. See lifetime contract above.
    void* context;
    /// Called when Rust has one datagram to write to client-side UDP flow.
    RamaUdpServerDatagramFn on_server_datagram;
    /// Called when Rust requests one client-side UDP read (`flow.readDatagrams`).
    RamaUdpClientReadDemandFn on_client_read_demand;
    /// Called when Rust closes server-side UDP flow.
    RamaUdpServerClosedFn on_server_closed;
} RamaTransparentProxyUdpSessionCallbacks;

// ── Egress (NWConnection) options ────────────────────────────────────────────

/// NWParameters-level settings shared between TCP and UDP egress NWConnections.
///
/// service_class values:
///   0=Default 1=Background 2=InteractiveVideo 3=InteractiveVoice
///   4=ResponsiveData 5=Signaling
///
/// multipath_service_type values:
///   0=Disabled 1=Handover 2=Interactive 3=Aggregate
///
/// required_interface_type / prohibited mask bits:
///   0=Cellular 1=Loopback 2=Other 3=Wifi 4=Wired
///
/// attribution values:
///   0=Developer 1=User
///
/// Apple references:
/// - https://developer.apple.com/documentation/network/nwparameters
typedef struct {
    bool has_service_class;
    uint8_t service_class;
    bool has_multipath_service_type;
    uint8_t multipath_service_type;
    bool has_required_interface_type;
    uint8_t required_interface_type;
    bool has_attribution;
    uint8_t attribution;
    /// Bitmask: bit0=Cellular bit1=Loopback bit2=Other bit3=Wifi bit4=Wired.
    uint8_t prohibited_interface_types_mask;
    /// When true, Swift stamps the intercepted flow's NEFlowMetaData onto the
    /// egress NWParameters via NEAppProxyFlow.setMetadata(_:) before
    /// constructing the NWConnection. Defaults to true on the Rust side.
    bool preserve_original_meta_data;
} RamaNwEgressParameters;

/// Options for the egress NWConnection on TCP flows.
///
/// Apple reference:
/// - https://developer.apple.com/documentation/network/nwprotocoltcp/options/connectiontimeout
typedef struct {
    RamaNwEgressParameters parameters;
    bool has_connect_timeout_ms;
    /// TCP connection timeout in milliseconds (maps to NWProtocolTCP.Options.connectionTimeout).
    uint32_t connect_timeout_ms;
    /// Whether `linger_close_ms` carries a meaningful value;
    /// `false` ⇒ Swift uses its built-in default.
    bool has_linger_close_ms;
    /// Wall-clock cap (ms) on how long the egress NWConnection lingers
    /// after the local side has sent its FIN before Swift force-cancels
    /// the connection. Without this watchdog a peer that fails to send
    /// its own FIN-ACK keeps the socket pinned in FIN_WAIT_1 and the
    /// macOS NECP flow registration alive, which compounds with new
    /// flow starts into the path-evaluator slowdown.
    uint32_t linger_close_ms;
    /// Whether `egress_eof_grace_ms` carries a meaningful value;
    /// `false` ⇒ Swift uses its built-in default.
    bool has_egress_eof_grace_ms;
    /// Grace window (ms) between the egress read pump observing peer
    /// EOF (or a read error) and the Swift side force-cancelling the
    /// connection. Protects the path where the clean teardown
    /// (`on_server_closed` → cancel) stalls because the originating
    /// app stopped reading from its NEAppProxyFlow.
    uint32_t egress_eof_grace_ms;
} RamaTcpEgressConnectOptions;

/// Returns a `RamaTcpDeliverStatus` so the Rust bridge can pause when Swift's
/// `NwTcpConnectionWritePump` is full. Swift MUST call
/// `rama_transparent_proxy_tcp_session_signal_egress_drain` after its writer
/// drains capacity following a `Paused` return.
typedef RamaTcpDeliverStatus (*RamaTcpEgressWriteFn)(void* context, RamaBytesView bytes);
typedef void (*RamaTcpEgressCloseFn)(void* context);
typedef void (*RamaTcpEgressReadDemandFn)(void* context);

/// Callbacks passed to `rama_transparent_proxy_tcp_session_activate`.
///
/// These are the Rust→Swift data path: Rust calls `on_write_to_egress` when
/// the service has bytes to send to the remote server via the NWConnection,
/// and `on_close_egress` when the service is done writing.
///
/// `context` lifetime / threading contract: see the matching contract on
/// `RamaTransparentProxyTcpSessionCallbacks` above. The pointee must outlive
/// the corresponding `_session_free` call, callbacks may run on any thread,
/// and `bytes` is borrowed for the call's duration.
typedef struct {
    /// Opaque user context passed back to callbacks. See lifetime contract above.
    ///
    /// Do NOT use if for sensitive information and other secrets,
    /// as it is is information freely logged by Apple code.
    void* context;
    RamaTcpEgressWriteFn on_write_to_egress;
    RamaTcpEgressCloseFn on_close_egress;
    /// Called when the Rust egress channel has space again after
    /// `rama_transparent_proxy_tcp_session_on_egress_bytes` returned `false`.
    /// Swift MUST keep `connection.receive(...)` paused between the `false`
    /// return and this callback firing.
    RamaTcpEgressReadDemandFn on_egress_read_demand;
} RamaTransparentProxyTcpEgressCallbacks;

// Logging

/// Forward a log message to Rust tracing.
///
/// `message` is borrowed for the duration of the call.
void rama_log(
    uint32_t level,
    RamaBytesView message
);

/// Resolve a macOS audit token to a PID.
///
/// Returns `-1` when `bytes/len` do not contain one complete `audit_token_t`.
int32_t rama_apple_audit_token_to_pid(const uint8_t* bytes, size_t len);


// Engine lifecycle

/// Initialize Rust-side transparent proxy subsystem (idempotent).
///
/// `config` may be NULL. In that case Rust uses internal fallback paths.
bool rama_transparent_proxy_initialize(const RamaTransparentProxyInitConfig* config);

/// Fetch transparent proxy configuration for NETransparentProxyProvider setup.
///
/// Returns an owned pointer, or NULL on failure.
/// Caller must release it with `rama_transparent_proxy_config_free`.
RamaTransparentProxyConfig* rama_transparent_proxy_get_config(RamaTransparentProxyEngine* engine);

/// Free a config previously returned by `rama_transparent_proxy_get_config`.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_config_free(
    RamaTransparentProxyConfig* config
);

/// Allocate a new transparent proxy engine.
///
/// Returns NULL on failure.
RamaTransparentProxyEngine* rama_transparent_proxy_engine_new(void);

/// Allocate a new transparent proxy engine with an optional opaque config blob.
///
/// `engine_config` is borrowed for the duration of the call only.
/// Returns NULL on failure.
RamaTransparentProxyEngine* rama_transparent_proxy_engine_new_with_config(RamaBytesView engine_config);

/// Free an engine previously returned by `rama_transparent_proxy_engine_new`.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_engine_free(RamaTransparentProxyEngine* engine);

/// Stop the transparent proxy engine with provider stop reason.
///
/// Consumes the engine pointer. Do not free the engine again after calling this.
///
/// NULL is allowed and ignored.
/// Apple reference:
/// - https://developer.apple.com/documentation/networkextension/neproviderstopreason
void rama_transparent_proxy_engine_stop(RamaTransparentProxyEngine* engine, int32_t reason);

/// Forward an app-to-provider message into the transparent proxy handler.
///
/// `message` is borrowed for the duration of the call.
/// Returns an owned reply payload. Empty reply means "no reply payload".
RamaBytesOwned rama_transparent_proxy_engine_handle_app_message(
    RamaTransparentProxyEngine* engine,
    RamaBytesView message
);

// TCP flow lifecycle

/// Create a TCP session for one intercepted flow.
///
/// `meta` may be NULL (Rust will fall back to default TCP metadata).
/// Returns the merged Rust decision plus an optional session handle.
RamaTransparentProxyTcpSessionResult rama_transparent_proxy_engine_new_tcp_session(
    RamaTransparentProxyEngine* engine,
    const RamaTransparentProxyFlowMeta* meta,
    RamaTransparentProxyTcpSessionCallbacks callbacks
);

/// Free a TCP session.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_tcp_session_free(RamaTransparentProxyTcpSession* session);

/// Deliver client->server TCP bytes into the Rust session.
///
/// `bytes` is borrowed for duration of the call.
///
/// Returns a `RamaTcpDeliverStatus`:
///   * `RAMA_TCP_DELIVER_ACCEPTED`: Swift may keep reading from the kernel.
///   * `RAMA_TCP_DELIVER_PAUSED`: per-flow ingress channel is full; pause
///     `flow.readData` until `on_client_read_demand` fires.
///   * `RAMA_TCP_DELIVER_CLOSED`: session has been torn down; terminate the
///     read pump immediately, no demand callback will follow.
RamaTcpDeliverStatus rama_transparent_proxy_tcp_session_on_client_bytes(
    RamaTransparentProxyTcpSession* session,
    RamaBytesView bytes
);

/// Signal EOF on client->server TCP direction.
void rama_transparent_proxy_tcp_session_on_client_eof(RamaTransparentProxyTcpSession* session);

/// Cancel TCP session and suppress any future server callbacks for this session.
void rama_transparent_proxy_tcp_session_cancel(RamaTransparentProxyTcpSession* session);

/// Query handler-supplied egress connect options for a TCP session.
///
/// Fills `out_options` and returns `true` when the handler provided custom
/// options. Returns `false` when Swift should use default NWParameters.
///
/// `out_options` must point to caller-allocated storage.
bool rama_transparent_proxy_tcp_session_get_egress_connect_options(
    RamaTransparentProxyTcpSession* session,
    RamaTcpEgressConnectOptions* out_options
);

/// Activate a TCP session after the egress NWConnection is ready and the
/// intercepted flow has been successfully opened.
///
/// `callbacks` provides the Rust→Swift write channel for the egress direction.
void rama_transparent_proxy_tcp_session_activate(
    RamaTransparentProxyTcpSession* session,
    RamaTransparentProxyTcpEgressCallbacks callbacks
);

/// Deliver bytes from the egress NWConnection to the Rust TCP session.
///
/// Called by Swift when NWConnection.receive delivers data from the remote server.
/// `bytes` is borrowed for the duration of the call.
///
/// Same `RamaTcpDeliverStatus` return contract as
/// `rama_transparent_proxy_tcp_session_on_client_bytes`.
RamaTcpDeliverStatus rama_transparent_proxy_tcp_session_on_egress_bytes(
    RamaTransparentProxyTcpSession* session,
    RamaBytesView bytes
);

/// Signal EOF on the egress NWConnection direction.
///
/// Called by Swift when the NWConnection closes or enters a failed state.
void rama_transparent_proxy_tcp_session_on_egress_eof(
    RamaTransparentProxyTcpSession* session
);

/// Swift → Rust: signal that the response writer pump (`TcpClientWritePump`)
/// has drained capacity after `on_server_bytes` returned `RAMA_TCP_DELIVER_PAUSED`.
///
/// Wakes the Rust bridge so it resumes pulling response bytes through the
/// duplex. Idempotent — collapses redundant calls into a single permit.
void rama_transparent_proxy_tcp_session_signal_server_drain(
    RamaTransparentProxyTcpSession* session
);

/// Swift → Rust: signal that the egress writer pump
/// (`NwTcpConnectionWritePump`) has drained capacity after
/// `on_write_to_egress` returned `RAMA_TCP_DELIVER_PAUSED`.
void rama_transparent_proxy_tcp_session_signal_egress_drain(
    RamaTransparentProxyTcpSession* session
);

// UDP flow lifecycle

/// Create a UDP session for one intercepted flow.
///
/// `meta` may be NULL (Rust will fall back to default UDP metadata).
/// Returns the merged Rust decision plus an optional session handle.
RamaTransparentProxyUdpSessionResult rama_transparent_proxy_engine_new_udp_session(
    RamaTransparentProxyEngine* engine,
    const RamaTransparentProxyFlowMeta* meta,
    RamaTransparentProxyUdpSessionCallbacks callbacks
);

/// Free a UDP session.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_udp_session_free(RamaTransparentProxyUdpSession* session);

/// Deliver one client->server UDP datagram into Rust session.
///
/// `bytes` and `peer` are borrowed for duration of the call.
/// `peer.present = false` is allowed and is treated as "no peer
/// attribution"; in production every kernel-delivered datagram comes
/// with an endpoint.
void rama_transparent_proxy_udp_session_on_client_datagram(
    RamaTransparentProxyUdpSession* session,
    RamaBytesView bytes,
    RamaUdpPeerView peer
);

/// Signal UDP flow closure from client side.
void rama_transparent_proxy_udp_session_on_client_close(RamaTransparentProxyUdpSession* session);

/// Activate a UDP session.
///
/// UDP egress is the handler's responsibility (one or more sockets,
/// pooled or per-flow, opened however the handler's service wants
/// using rama-udp / `tokio::net::UdpSocket` / anything else).
/// Subsequent calls are ignored.
void rama_transparent_proxy_udp_session_activate(
    RamaTransparentProxyUdpSession* session
);

// RAII

/// Free Rust-owned byte buffer returned over FFI.
void rama_owned_bytes_free(RamaBytesOwned bytes);

#ifdef __cplusplus
}
#endif
