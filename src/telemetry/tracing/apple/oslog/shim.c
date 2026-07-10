#include "shim.h"

#include <os/log.h>
#include <os/signpost.h>

void *rama_apple_oslog_create(const char *subsystem, const char *category) {
    return (void *)os_log_create(subsystem, category);
}

void rama_apple_oslog_release(void *log) {
    os_release((os_log_t)log);
}

uint8_t rama_apple_oslog_enabled(void *log, uint8_t type) {
    return os_log_type_enabled((os_log_t)log, (os_log_type_t)type);
}

void rama_apple_oslog_emit(void *log, uint8_t type, const char *message, uint8_t is_public) {
    if (is_public) {
        os_log_with_type((os_log_t)log, (os_log_type_t)type, "%{public}s", message);
    } else {
        os_log_with_type((os_log_t)log, (os_log_type_t)type, "%{private}s", message);
    }
}

uint8_t rama_apple_oslog_signpost_enabled(void *log) {
    if (__builtin_available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, *)) {
        return os_signpost_enabled((os_log_t)log);
    }
    return 0;
}

uint64_t rama_apple_oslog_signpost_id_generate(void *log) {
    if (__builtin_available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, *)) {
        return os_signpost_id_generate((os_log_t)log);
    }
    return OS_SIGNPOST_ID_NULL;
}

void rama_apple_oslog_signpost_begin(
    void *log,
    uint64_t signpost_id,
    const char *message,
    uint8_t is_public
) {
    if (__builtin_available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, *)) {
        if (is_public) {
            os_signpost_interval_begin(
                (os_log_t)log,
                (os_signpost_id_t)signpost_id,
                "tracing-span",
                "%{public}s",
                message
            );
        } else {
            os_signpost_interval_begin(
                (os_log_t)log,
                (os_signpost_id_t)signpost_id,
                "tracing-span",
                "%{private}s",
                message
            );
        }
    }
}

void rama_apple_oslog_signpost_end(
    void *log,
    uint64_t signpost_id,
    const char *message,
    uint8_t is_public
) {
    if (__builtin_available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, *)) {
        if (is_public) {
            os_signpost_interval_end(
                (os_log_t)log,
                (os_signpost_id_t)signpost_id,
                "tracing-span",
                "%{public}s",
                message
            );
        } else {
            os_signpost_interval_end(
                (os_log_t)log,
                (os_signpost_id_t)signpost_id,
                "tracing-span",
                "%{private}s",
                message
            );
        }
    }
}
