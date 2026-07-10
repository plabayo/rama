#include <os/log.h>

void rama_os_log_split(os_log_t log, os_log_type_t type,
                       const char *public_message,
                       const char *private_metadata) {
    if (private_metadata[0] == '\0') {
        os_log_with_type(log, type, "%{public}s", public_message);
    } else {
        os_log_with_type(log, type, "%{public}s %{private}s", public_message,
                         private_metadata);
    }
}
