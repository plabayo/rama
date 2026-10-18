#ifndef RAMA_DNS_RESOLV_WRAPPER_H
#define RAMA_DNS_RESOLV_WRAPPER_H

#include <stdint.h>

/* Only Rama-owned records cross this interface; <resolv.h> stays in C. */
struct rama_res_config {
  int retrans;
  int retry;
  int nscount;
  unsigned long options;
  unsigned int ndots; /* initialized once; used by Rust's search walk */
};

struct rama_res_result {
  int len;
  int system_error;
  int resolver_error;
};

struct rama_res_nameserver {
  /* 4 or 6, independent of the platform's AF_* constants. */
  int family;
  uint8_t address[16];
  uint16_t port; /* host byte order */
  uint32_t scope_id;
};

struct rama_resolver;

struct rama_resolver *rama_res_create(struct rama_res_config *config);
void rama_res_destroy(struct rama_resolver *resolver);
const char *rama_res_search(const struct rama_resolver *resolver, int index);
int rama_res_nameserver(const struct rama_resolver *resolver, int index,
                        struct rama_res_nameserver *out);
struct rama_res_result rama_res_query(struct rama_resolver *resolver,
                                      struct rama_res_config *config,
                                      const char *name, int type,
                                      unsigned char *answer, int capacity);

#endif
