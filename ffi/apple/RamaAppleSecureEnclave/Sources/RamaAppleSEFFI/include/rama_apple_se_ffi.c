#include "rama_apple_se_ffi.h"
#include <stddef.h>
#include <stdlib.h>

void rama_apple_se_bytes_free(RamaSeBytes bytes) {
    if (bytes.ptr != NULL) {
        // Wipe before free: on decrypt this holds the CA private key. Volatile so
        // it isn't optimized away.
        volatile unsigned char *p = (volatile unsigned char *)bytes.ptr;
        for (size_t i = 0; i < bytes.len; i++) {
            p[i] = 0;
        }
        free(bytes.ptr);
    }
}
