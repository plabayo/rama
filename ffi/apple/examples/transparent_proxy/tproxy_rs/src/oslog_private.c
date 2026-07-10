#include <os/log.h>

void rama_os_log_private(os_log_t log, os_log_type_t type, const char *message) {
    os_log_with_type(log, type, "%{private}s", message);
}
