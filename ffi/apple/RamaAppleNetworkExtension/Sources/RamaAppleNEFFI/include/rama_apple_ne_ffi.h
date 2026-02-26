#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque transparent proxy engine handle managed by Rust.
typedef struct RamaTransparentProxyEngine RamaTransparentProxyEngine;
/// Opaque TCP flow/session handle managed by Rust.
typedef struct RamaTransparentProxyTcpSession RamaTransparentProxyTcpSession;
/// Opaque UDP flow/session handle managed by Rust.
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

/// Protocol filter used by network interception rules.
typedef enum {
    /// Match any protocol.
    RAMA_RULE_PROTOCOL_ANY = 0,
    /// Match TCP only.
    RAMA_RULE_PROTOCOL_TCP = 1,
    /// Match UDP only.
    RAMA_RULE_PROTOCOL_UDP = 2,
} RamaTransparentProxyRuleProtocol;

/// Traffic direction filter used by network interception rules.
typedef enum {
    /// Match outbound traffic.
    RAMA_TRAFFIC_DIRECTION_OUTBOUND = 0,
    /// Match inbound traffic.
    RAMA_TRAFFIC_DIRECTION_INBOUND = 1,
    /// Match both directions.
    RAMA_TRAFFIC_DIRECTION_ANY = 2,
} RamaTransparentProxyTrafficDirection;

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
    /// One of `RamaTransparentProxyTrafficDirection`.
    uint32_t direction;
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
} RamaTransparentProxyConfig;

typedef void (*RamaTcpServerBytesFn)(void* context, RamaBytesView bytes);
typedef void (*RamaTcpServerClosedFn)(void* context);

/// Callbacks Swift provides for Rust TCP session events.
typedef struct {
    /// Opaque user context passed back to callbacks.
    void* context;
    /// Called when Rust has bytes to write to client-side TCP flow.
    RamaTcpServerBytesFn on_server_bytes;
    /// Called when Rust closes server-side TCP direction.
    RamaTcpServerClosedFn on_server_closed;
} RamaTransparentProxyTcpSessionCallbacks;

typedef void (*RamaUdpServerDatagramFn)(void* context, RamaBytesView bytes);
typedef void (*RamaUdpServerClosedFn)(void* context);

/// Callbacks Swift provides for Rust UDP session events.
typedef struct {
    /// Opaque user context passed back to callbacks.
    void* context;
    /// Called when Rust has one datagram to write to client-side UDP flow.
    RamaUdpServerDatagramFn on_server_datagram;
    /// Called when Rust closes server-side UDP flow.
    RamaUdpServerClosedFn on_server_closed;
} RamaTransparentProxyUdpSessionCallbacks;

// Logging

/// Forward a log message to Rust tracing.
///
/// `message` is borrowed for the duration of the call.
void rama_log(
    uint32_t level,
    RamaBytesView message
);


// Engine lifecycle

/// Initialize Rust-side transparent proxy subsystem (idempotent).
bool rama_transparent_proxy_initialize(void);

/// Fetch transparent proxy configuration for NETransparentProxyProvider setup.
///
/// Returns an owned pointer, or NULL on failure.
/// Caller must release it with `rama_transparent_proxy_config_free`.
RamaTransparentProxyConfig* rama_transparent_proxy_get_config(void);

/// Free a config previously returned by `rama_transparent_proxy_get_config`.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_config_free(
    RamaTransparentProxyConfig* config
);

/// Ask Rust whether a flow should be intercepted.
///
/// Returns false if `meta` is NULL.
bool rama_transparent_proxy_should_intercept_flow(
    const RamaTransparentProxyFlowMeta* meta
);

/// Allocate a new transparent proxy engine.
///
/// Returns NULL on failure.
RamaTransparentProxyEngine* rama_transparent_proxy_engine_new(void);

/// Free an engine previously returned by `rama_transparent_proxy_engine_new`.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_engine_free(RamaTransparentProxyEngine* engine);

/// Start the transparent proxy engine.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_engine_start(RamaTransparentProxyEngine* engine);

/// Stop the transparent proxy engine with provider stop reason.
///
/// NULL is allowed and ignored.
/// Apple reference:
/// - https://developer.apple.com/documentation/networkextension/neproviderstopreason
void rama_transparent_proxy_engine_stop(RamaTransparentProxyEngine* engine, int32_t reason);

// TCP flow lifecycle

/// Create a TCP session for one intercepted flow.
///
/// `meta` may be NULL (Rust will fall back to default TCP metadata).
/// Returns NULL if session creation is rejected/fails.
RamaTransparentProxyTcpSession* rama_transparent_proxy_engine_new_tcp_session(
    RamaTransparentProxyEngine* engine,
    const RamaTransparentProxyFlowMeta* meta,
    RamaTransparentProxyTcpSessionCallbacks callbacks
);

/// Free a TCP session.
///
/// NULL is allowed and ignored.
void rama_transparent_proxy_tcp_session_free(RamaTransparentProxyTcpSession* session);

/// Deliver client->server TCP bytes into Rust session.
///
/// `bytes` is borrowed for duration of the call.
void rama_transparent_proxy_tcp_session_on_client_bytes(
    RamaTransparentProxyTcpSession* session,
    RamaBytesView bytes
);

/// Signal EOF on client->server TCP direction.
void rama_transparent_proxy_tcp_session_on_client_eof(RamaTransparentProxyTcpSession* session);

// UDP flow lifecycle

/// Create a UDP session for one intercepted flow.
///
/// `meta` may be NULL (Rust will fall back to default UDP metadata).
/// Returns NULL if session creation is rejected/fails.
RamaTransparentProxyUdpSession* rama_transparent_proxy_engine_new_udp_session(
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
/// `bytes` is borrowed for duration of the call.
void rama_transparent_proxy_udp_session_on_client_datagram(
    RamaTransparentProxyUdpSession* session,
    RamaBytesView bytes
);

/// Signal UDP flow closure from client side.
void rama_transparent_proxy_udp_session_on_client_close(RamaTransparentProxyUdpSession* session);

// RAII

/// Free Rust-owned byte buffer returned over FFI.
void rama_owned_bytes_free(RamaBytesOwned bytes);

#ifdef __cplusplus
}
#endif
