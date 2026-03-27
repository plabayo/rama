#include "rama_apple_ne_ffi.h"
#include <bsm/libbsm.h>
#include <mach/message.h>
#include <string.h>

int32_t rama_apple_audit_token_to_pid(const uint8_t* bytes, size_t len) {
    if (bytes == NULL || len != sizeof(audit_token_t)) {
        return -1;
    }

    audit_token_t token;
    memcpy(&token, bytes, sizeof(token));
    return (int32_t)audit_token_to_pid(token);
}
