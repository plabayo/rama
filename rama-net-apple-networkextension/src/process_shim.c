// Tiny C shim for the libbsm audit_token_to_pid macro.
//
// Apple's <bsm/libbsm.h> exposes audit_token_to_pid() as a macro that
// reads internal fields of `audit_token_t`. Apple does not commit to
// the layout — only the macro/function form is stable across SDK
// updates. We therefore call the macro from C (where the SDK header
// is authoritative) instead of extracting fields from Rust.
//
// The Rust caller passes (pointer, length); we re-validate the
// length, memcpy into a local `audit_token_t`, and call the macro.

#include <bsm/libbsm.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int32_t __rama_audit_token_to_pid(const uint8_t *bytes, size_t len) {
    if (bytes == NULL || len < sizeof(audit_token_t)) {
        return -1;
    }
    audit_token_t token;
    memcpy(&token, bytes, sizeof(token));
    return (int32_t)audit_token_to_pid(token);
}
