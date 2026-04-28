#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Owned byte buffer allocated by the Swift bridge with `malloc`.
///
/// Must be released exactly once with `rama_apple_se_bytes_free`.
/// `ptr` is NULL when `len == 0`.
typedef struct {
    uint8_t* ptr;
    size_t len;
} RamaSeBytes;

/// Accessibility class for the SE-protected key.
typedef enum {
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (CryptoKit default).
    /// The key is unusable before the first user login on the Mac.
    /// Suitable for processes that only run while a user is signed in.
    RAMA_SE_ACCESSIBILITY_AFTER_FIRST_UNLOCK = 0,
    /// `kSecAttrAccessibleAlways` (deprecated by Apple but still functional).
    /// The key is usable before any user has logged in. This is the only
    /// option that works for a Network Extension System Extension daemon
    /// that may need to operate prior to login.
    RAMA_SE_ACCESSIBILITY_ALWAYS = 1,
} RamaSeAccessibility;

/// Bridge return codes.
#define RAMA_SE_OK             0
/// SE hardware is not available on this Mac (Intel without T2, or disabled).
#define RAMA_SE_ERR_UNAVAILABLE -1
/// Caller passed bad pointers/lengths or a malformed input blob.
#define RAMA_SE_ERR_BAD_INPUT  -2
/// Cryptographic operation failed (decrypt tag mismatch, malformed envelope, etc.).
#define RAMA_SE_ERR_CRYPTO     -3
/// SE / Security framework returned an unexpected error. Check the system log.
#define RAMA_SE_ERR_SYSTEM     -4

/// Returns `true` when this Mac has a usable Secure Enclave.
bool rama_apple_se_is_available(void);

/// Create a new SE-protected P-256 key suitable for ECDH key agreement.
///
/// On success, `out_blob` is filled with the opaque `dataRepresentation`
/// of the key. The blob is wrapped by the SE on this device and is the only
/// way to reload the key. It contains no usable private key material in the
/// clear.
///
/// `out_blob` must point to caller-allocated storage. On non-OK returns the
/// fields are zeroed.
int32_t rama_apple_se_p256_create(
    RamaSeAccessibility accessibility,
    RamaSeBytes* out_blob
);

/// Encrypt `pt[0..pt_len]` using the SE key wrapped in `blob[0..blob_len]`.
///
/// The output envelope layout is:
///   `[1 byte version=1][65 byte ephemeral pubkey, X9.63 uncompressed]`
///   `[12 byte AES-GCM nonce][N byte ciphertext][16 byte GCM tag]`
///
/// The key blob is borrowed for the duration of the call.
int32_t rama_apple_se_p256_encrypt(
    const uint8_t* blob, size_t blob_len,
    const uint8_t* pt,   size_t pt_len,
    RamaSeBytes* out_ct
);

/// Decrypt an envelope previously produced by `rama_apple_se_p256_encrypt`
/// using the same SE key.
int32_t rama_apple_se_p256_decrypt(
    const uint8_t* blob, size_t blob_len,
    const uint8_t* ct,   size_t ct_len,
    RamaSeBytes* out_pt
);

/// Free a `RamaSeBytes` returned by the bridge.
///
/// Calling with `bytes.ptr == NULL` is safe and a no-op.
void rama_apple_se_bytes_free(RamaSeBytes bytes);

#ifdef __cplusplus
}
#endif
