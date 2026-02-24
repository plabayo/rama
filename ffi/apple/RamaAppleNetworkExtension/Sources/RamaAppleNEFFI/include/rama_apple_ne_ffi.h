#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RamaTransparentProxyEngine RamaTransparentProxyEngine;
typedef struct RamaTcpSession RamaTcpSession;
typedef struct RamaUdpSession RamaUdpSession;

typedef struct {
    const uint8_t* ptr;
    int32_t len;
} RamaBytesView;

typedef struct {
    uint8_t* ptr;
    int32_t len;
} RamaBytesOwned;

typedef void (*RamaTcpServerBytesFn)(void* context, RamaBytesView bytes);
typedef void (*RamaTcpServerClosedFn)(void* context);

typedef struct {
    void* context;
    RamaTcpServerBytesFn on_server_bytes;
    RamaTcpServerClosedFn on_server_closed;
} RamaTcpSessionCallbacks;

typedef void (*RamaUdpServerDatagramFn)(void* context, RamaBytesView bytes);
typedef void (*RamaUdpServerClosedFn)(void* context);

typedef struct {
    void* context;
    RamaUdpServerDatagramFn on_server_datagram;
    RamaUdpServerClosedFn on_server_closed;
} RamaUdpSessionCallbacks;

// Engine lifecycle

RamaTransparentProxyEngine* rama_transparent_proxy_engine_new(const char* config_utf8);
void rama_transparent_proxy_engine_free(RamaTransparentProxyEngine* engine);

void rama_transparent_proxy_engine_start(RamaTransparentProxyEngine* engine);
void rama_transparent_proxy_engine_stop(RamaTransparentProxyEngine* engine, int32_t reason);

// TCP flow lifecycle

RamaTcpSession* rama_transparent_proxy_engine_new_tcp_session(
    RamaTransparentProxyEngine* engine,
    const char* meta_json_utf8,
    RamaTcpSessionCallbacks callbacks
);

void rama_tcp_session_free(RamaTcpSession* session);

// Called with bytes read from the client side of the flow.
void rama_tcp_session_on_client_bytes(
    RamaTcpSession* session,
    RamaBytesView bytes
);

// Called when the client side has reached EOF or closed.
void rama_tcp_session_on_client_eof(RamaTcpSession* session);

// UDP flow lifecycle

RamaUdpSession* rama_transparent_proxy_engine_new_udp_session(
    RamaTransparentProxyEngine* engine,
    const char* meta_json_utf8,
    RamaUdpSessionCallbacks callbacks
);

void rama_udp_session_free(RamaUdpSession* session);

// Called with one datagram received from the client side.
void rama_udp_session_on_client_datagram(
    RamaUdpSession* session,
    RamaBytesView bytes
);

// Called when the UDP flow is closed.
void rama_udp_session_on_client_close(RamaUdpSession* session);

// Memory management for buffers returned by Rust.

void rama_bytes_free(uint8_t* ptr, int32_t len);

#ifdef __cplusplus
}
#endif
