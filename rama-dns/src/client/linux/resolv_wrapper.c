#include "resolv_wrapper.h"

#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

/* The isolated test fixture gives its copies internal linkage. */
#ifndef RAMA_RES_API
#define RAMA_RES_API
#endif

struct rama_resolver {
  struct __res_state state;
  int nscount;
};

RAMA_RES_API struct rama_resolver *
rama_res_create(struct rama_res_config *config) {
  struct rama_resolver *resolver = calloc(1, sizeof(*resolver));
  if (resolver == NULL) {
    return NULL;
  }
  errno = 0;
  if (res_ninit(&resolver->state) != 0) {
    int saved_errno = errno;
    free(resolver);
    errno = saved_errno;
    return NULL;
  }
  const struct __res_state *state = &resolver->state;
  resolver->nscount = state->nscount;
  config->retrans = state->retrans;
  config->retry = state->retry;
  config->nscount = state->nscount;
  config->options = state->options;
  config->ndots = state->ndots;
  return resolver;
}

RAMA_RES_API void rama_res_destroy(struct rama_resolver *resolver) {
  /* A short-budget query may temporarily ask fewer nameservers. libc must
     see the full count when closing its sockets and freeing IPv6 copies. */
  resolver->state.nscount = resolver->nscount;
  res_nclose(&resolver->state);
  free(resolver);
}

RAMA_RES_API const char *rama_res_search(const struct rama_resolver *resolver,
                                         int index) {
  if (index < 0 || index >= MAXDNSRCH) {
    return NULL;
  }
  return resolver->state.dnsrch[index];
}

RAMA_RES_API int rama_res_nameserver(const struct rama_resolver *resolver,
                                     int index,
                                     struct rama_res_nameserver *out) {
  if (index < 0 || index >= resolver->nscount || index >= MAXNS) {
    return 0;
  }
  const struct __res_state *state = &resolver->state;
  const struct sockaddr_in6 *copy = state->_u._ext.nsaddrs[index];
  const struct sockaddr *address =
      copy != NULL ? (const struct sockaddr *)copy
                   : (const struct sockaddr *)&state->nsaddr_list[index];
  memset(out, 0, sizeof(*out));
  if (address->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
    out->family = 4;
    memcpy(out->address, &v4->sin_addr, 4);
    out->port = ntohs(v4->sin_port);
    return 1;
  }
  if (address->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
    out->family = 6;
    memcpy(out->address, &v6->sin6_addr, 16);
    out->port = ntohs(v6->sin6_port);
    out->scope_id = v6->sin6_scope_id;
    return 1;
  }
  return 0;
}

RAMA_RES_API struct rama_res_result
rama_res_query(struct rama_resolver *resolver, struct rama_res_config *config,
               const char *name, int type, unsigned char *answer,
               int capacity) {
  struct __res_state *state = &resolver->state;
  state->retrans = config->retrans;
  state->retry = config->retry;
  state->nscount = config->nscount;
  state->options = config->options;
  errno = 0;
  int len = res_nquery(state, name, ns_c_in, type, answer, capacity);
  struct rama_res_result result = {len, errno, state->res_h_errno};
  /* Keep any option changes libc made while sending this query, just as
     direct access to the native state did before the shim owned it. */
  config->retrans = state->retrans;
  config->retry = state->retry;
  config->nscount = state->nscount;
  config->options = state->options;
  /* ndots belongs to Rust's search walk; res_nquery does not use it. */
  state->nscount = resolver->nscount;
  return result;
}
