// Stub implementations of the `rama_apple_se_*` Secure Enclave bridge
// symbols for the e2e test binary.
//
// In a real deployment those symbols are provided by the
// `RamaAppleSecureEnclave` Swift product (linked into the sysext bundle
// at Xcode link time). This e2e harness, however, exercises the static
// Rust library `librama_tproxy_example.a` directly from a Cargo test
// binary and never goes through the Xcode pipeline, so the Swift symbols
// would otherwise be undefined at link time.
//
// The stubs always report "Secure Enclave unavailable" so the example's
// TLS module takes its plaintext fallback path. Cert/key PEMs in this
// harness are supplied via the inline override (see
// `DemoProxyConfig::ca_cert_pem` / `ca_key_pem`), so neither the SE path
// nor the plaintext-keychain path is actually exercised — these stubs
// just have to keep the link step happy.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Mirrors the layout in
// `ffi/apple/RamaAppleSecureEnclave/Sources/RamaAppleSEFFI/include/rama_apple_se_ffi.h`.
typedef struct {
    uint8_t* ptr;
    size_t   len;
} RamaSeBytes;

// Matches `RAMA_SE_ERR_UNAVAILABLE` on the real bridge.
#define RAMA_SE_ERR_UNAVAILABLE (-1)

bool rama_apple_se_is_available(void) {
    return false;
}

int32_t rama_apple_se_p256_create(int32_t accessibility, RamaSeBytes* out_blob) {
    (void)accessibility;
    if (out_blob != NULL) {
        out_blob->ptr = NULL;
        out_blob->len = 0;
    }
    return RAMA_SE_ERR_UNAVAILABLE;
}

int32_t rama_apple_se_p256_encrypt(
    const uint8_t* blob, size_t blob_len,
    const uint8_t* pt,   size_t pt_len,
    RamaSeBytes*   out_ct
) {
    (void)blob; (void)blob_len; (void)pt; (void)pt_len;
    if (out_ct != NULL) {
        out_ct->ptr = NULL;
        out_ct->len = 0;
    }
    return RAMA_SE_ERR_UNAVAILABLE;
}

int32_t rama_apple_se_p256_decrypt(
    const uint8_t* blob, size_t blob_len,
    const uint8_t* ct,   size_t ct_len,
    RamaSeBytes*   out_pt
) {
    (void)blob; (void)blob_len; (void)ct; (void)ct_len;
    if (out_pt != NULL) {
        out_pt->ptr = NULL;
        out_pt->len = 0;
    }
    return RAMA_SE_ERR_UNAVAILABLE;
}

void rama_apple_se_bytes_free(RamaSeBytes bytes) {
    // Stubs never allocate. (NULL, 0) is the only shape we ever produce,
    // and the real bridge defines `bytes.ptr == NULL` as a no-op too.
    (void)bytes;
}
