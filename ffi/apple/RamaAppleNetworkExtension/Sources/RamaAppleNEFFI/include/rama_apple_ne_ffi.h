#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RamaTransparentProxyEngine RamaTransparentProxyEngine;
typedef struct RamaTransparentProxyTcpSession RamaTransparentProxyTcpSession;
typedef struct RamaTransparentProxyUdpSession RamaTransparentProxyUdpSession;

typedef struct {
    const uint8_t* ptr;
    size_t len;
} RamaBytesView;

typedef struct {
    uint8_t* ptr;
    size_t len;
} RamaBytesOwned;

typedef enum {
    RAMA_LOG_LEVEL_TRACE = 0,
    RAMA_LOG_LEVEL_DEBUG = 1,
    RAMA_LOG_LEVEL_INFO = 2,
    RAMA_LOG_LEVEL_WARN = 3,
    RAMA_LOG_LEVEL_ERROR = 4,
} RamaLogLevel;

typedef enum {
    RAMA_FLOW_PROTOCOL_TCP = 1,
    RAMA_FLOW_PROTOCOL_UDP = 2,
} RamaTransparentProxyFlowProtocol;

typedef enum {
    RAMA_RULE_PROTOCOL_ANY = 0,
    RAMA_RULE_PROTOCOL_TCP = 1,
    RAMA_RULE_PROTOCOL_UDP = 2,
} RamaTransparentProxyRuleProtocol;

typedef enum {
    RAMA_TRAFFIC_DIRECTION_OUTBOUND = 0,
    RAMA_TRAFFIC_DIRECTION_INBOUND = 1,
    RAMA_TRAFFIC_DIRECTION_ANY = 2,
} RamaTransparentProxyTrafficDirection;

typedef struct {
    const char* host_utf8;
    size_t host_utf8_len;
    uint16_t port;
} RamaTransparentProxyFlowEndpoint;

typedef struct {
    uint32_t protocol;
    RamaTransparentProxyFlowEndpoint remote_endpoint;
    RamaTransparentProxyFlowEndpoint local_endpoint;
    const char* source_app_signing_identifier_utf8;
    size_t source_app_signing_identifier_utf8_len;
    const char* source_app_bundle_identifier_utf8;
    size_t source_app_bundle_identifier_utf8_len;
} RamaTransparentProxyFlowMeta;

typedef struct {
    const char* remote_network_utf8;
    size_t remote_network_utf8_len;
    uint8_t remote_prefix;
    const char* local_network_utf8;
    size_t local_network_utf8_len;
    uint8_t local_prefix;
    uint32_t protocol;
    uint32_t direction;
} RamaTransparentProxyNetworkRule;

typedef struct {
    const RamaTransparentProxyNetworkRule* rules;
    size_t rules_len;
} RamaTransparentProxyStartupConfig;

typedef void (*RamaTcpServerBytesFn)(void* context, RamaBytesView bytes);
typedef void (*RamaTcpServerClosedFn)(void* context);

typedef struct {
    void* context;
    RamaTcpServerBytesFn on_server_bytes;
    RamaTcpServerClosedFn on_server_closed;
} RamaTransparentProxyTcpSessionCallbacks;

typedef void (*RamaUdpServerDatagramFn)(void* context, RamaBytesView bytes);
typedef void (*RamaUdpServerClosedFn)(void* context);

typedef struct {
    void* context;
    RamaUdpServerDatagramFn on_server_datagram;
    RamaUdpServerClosedFn on_server_closed;
} RamaTransparentProxyUdpSessionCallbacks;

// Logging

void rama_log(
    uint32_t level,
    RamaBytesView message
);


// Engine lifecycle

bool rama_transparent_proxy_initialize(void);

bool rama_transparent_proxy_get_startup_config(
    RamaTransparentProxyStartupConfig* out_config
);

bool rama_transparent_proxy_should_intercept_flow(
    const RamaTransparentProxyFlowMeta* meta
);

RamaTransparentProxyEngine* rama_transparent_proxy_engine_new(void);

void rama_transparent_proxy_engine_free(RamaTransparentProxyEngine* engine);

void rama_transparent_proxy_engine_start(RamaTransparentProxyEngine* engine);

void rama_transparent_proxy_engine_stop(RamaTransparentProxyEngine* engine, int32_t reason);

// TCP flow lifecycle

RamaTransparentProxyTcpSession* rama_transparent_proxy_engine_new_tcp_session(
    RamaTransparentProxyEngine* engine,
    const RamaTransparentProxyFlowMeta* meta,
    RamaTransparentProxyTcpSessionCallbacks callbacks
);

void rama_transparent_proxy_tcp_session_free(RamaTransparentProxyTcpSession* session);

void rama_transparent_proxy_tcp_session_on_client_bytes(
    RamaTransparentProxyTcpSession* session,
    RamaBytesView bytes
);

void rama_transparent_proxy_tcp_session_on_client_eof(RamaTransparentProxyTcpSession* session);

// UDP flow lifecycle

RamaTransparentProxyUdpSession* rama_transparent_proxy_engine_new_udp_session(
    RamaTransparentProxyEngine* engine,
    const RamaTransparentProxyFlowMeta* meta,
    RamaTransparentProxyUdpSessionCallbacks callbacks
);

void rama_transparent_proxy_udp_session_free(RamaTransparentProxyUdpSession* session);

void rama_transparent_proxy_udp_session_on_client_datagram(
    RamaTransparentProxyUdpSession* session,
    RamaBytesView bytes
);

void rama_transparent_proxy_udp_session_on_client_close(RamaTransparentProxyUdpSession* session);

// RAII

void rama_owned_bytes_free(RamaBytesOwned bytes);

#ifdef __cplusplus
}
#endif
