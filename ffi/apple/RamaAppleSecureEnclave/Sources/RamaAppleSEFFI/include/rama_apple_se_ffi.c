#include "rama_apple_se_ffi.h"
#include <stdlib.h>

void rama_apple_se_bytes_free(RamaSeBytes bytes) {
    if (bytes.ptr != NULL) {
        free(bytes.ptr);
    }
}
