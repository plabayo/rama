#ifndef RAMA_APPLE_OSLOG_SHIM_H
#define RAMA_APPLE_OSLOG_SHIM_H

#include <stdint.h>

void *rama_apple_oslog_create(const char *subsystem, const char *category);
void rama_apple_oslog_release(void *log);
uint8_t rama_apple_oslog_enabled(void *log, uint8_t type);
void rama_apple_oslog_emit(void *log, uint8_t type, const char *message, uint8_t is_public);

uint8_t rama_apple_oslog_signpost_enabled(void *log);
uint64_t rama_apple_oslog_signpost_id_generate(void *log);
void rama_apple_oslog_signpost_begin(
    void *log,
    uint64_t signpost_id,
    const char *message,
    uint8_t is_public
);
void rama_apple_oslog_signpost_end(
    void *log,
    uint64_t signpost_id,
    const char *message,
    uint8_t is_public
);

#endif
