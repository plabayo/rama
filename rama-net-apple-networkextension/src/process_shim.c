// Tiny C shim for libbsm's audit_token_to_pid().
//
// Apple documents audit_token_t as opaque: only the libbsm accessors may
// interpret it, so the Rust side never reads its fields.
//
// The Rust caller passes (pointer, length); we require an exact
// `sizeof(audit_token_t)` match, memcpy into a local, and call libbsm.

#if __has_include(<bsm/libbsm.h>)
#include <bsm/libbsm.h>
#else
// iOS SDKs export `audit_token_to_pid` from libbsm without shipping its
// header; this is the macOS <bsm/libbsm.h> prototype.
#include <mach/message.h>
#include <sys/types.h>
pid_t audit_token_to_pid(audit_token_t atoken);
#endif
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int32_t __rama_audit_token_to_pid(const uint8_t *bytes, size_t len) {
    if (bytes == NULL || len != sizeof(audit_token_t)) {
        return -1;
    }
    audit_token_t token;
    memcpy(&token, bytes, sizeof(token));
    return (int32_t)audit_token_to_pid(token);
}
