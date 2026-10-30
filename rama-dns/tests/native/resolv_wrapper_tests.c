/* Exercise the production shim with deterministic libc calls. This archive
   is linked only by Rust's unit tests, never bundled with the production rlib.
 */
#include "resolv_wrapper.h"

#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Preserve the target header's res_nclose alias before mocking it below. */
static void close_native_state(res_state state) { res_nclose(state); }

static int fail_allocation;
static int fail_init;
static int allocations;
static int frees;
static int closes;
static int closed_nscount;
static int query_arguments_match;
static int expected_nscount;
static unsigned long expected_options;

static void *test_calloc(size_t count, size_t size) {
  if (fail_allocation) {
    errno = ENOMEM;
    return NULL;
  }
  allocations++;
  return calloc(count, size);
}

static void test_free(void *pointer) {
  frees++;
  free(pointer);
  /* Initialization failures must preserve their error across cleanup. */
  errno = EBADF;
}

static int test_init(res_state state) {
  if (fail_init) {
    if (fail_init == 1) {
      errno = EACCES;
    }
    return -1;
  }
  state->retrans = 5;
  state->retry = 2;
  state->nscount = 3;
  state->options = RES_INIT | RES_DEFNAMES | RES_DNSRCH;
  state->ndots = 2;
  state->dnsrch[0] = (char *)"corp.test";
  state->dnsrch[1] = (char *)"other.test";
  return 0;
}

static void test_close(res_state state) {
  closes++;
  closed_nscount = state->nscount;
}

static int test_query(res_state state, const char *name, int class, int type,
                      unsigned char *answer, int capacity) {
  query_arguments_match =
      errno == 0 && state->retrans == 1 && state->retry == 1 &&
      state->nscount == expected_nscount &&
      state->options == expected_options &&
      strcmp(name, "example.test.") == 0 && class == ns_c_in &&
      type == ns_t_txt && capacity == 16;
  answer[0] = 42;
  state->options |= RES_IGNTC;
  state->ndots = 4;
  state->res_h_errno = HOST_NOT_FOUND;
  errno = EACCES;
  return -1;
}

/* Rename the shim's exports so the fixture never replaces the real resolver
   used by the other Rust tests. All logic below is the production source. */
#define RAMA_RES_API static
#define rama_res_create test_res_create
#define rama_res_destroy test_res_destroy
#define rama_res_search test_res_search
/* Function-like so the struct tag keeps its original name. */
#define rama_res_nameserver(...) test_res_nameserver(__VA_ARGS__)
#define rama_res_query test_res_query
#define calloc test_calloc
#define free test_free
#undef res_ninit
#define res_ninit test_init
#undef res_nclose
#define res_nclose test_close
#undef res_nquery
#define res_nquery test_query
#include "resolv_wrapper.c"
#undef calloc
#undef free
#undef res_ninit
#undef res_nclose
#undef res_nquery

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      return __LINE__;                                                         \
    }                                                                          \
  } while (0)

/* Return the failing source line to Rust instead of aborting its test runner.
 */
int rama_res_test_contract(void) {
  fail_allocation = fail_init = allocations = frees = closes = 0;
  closed_nscount = query_arguments_match = 0;
  struct rama_res_config config;

  fail_allocation = 1;
  CHECK(test_res_create(&config) == NULL);
  CHECK(errno == ENOMEM && allocations == 0 && frees == 0 && closes == 0);
  fail_allocation = 0;
  fail_init = 1;
  CHECK(test_res_create(&config) == NULL);
  CHECK(errno == EACCES && allocations == 1 && frees == 1 && closes == 0);
  fail_init = 2;
  errno = EBADF;
  CHECK(test_res_create(&config) == NULL);
  CHECK(errno == 0 && allocations == 2 && frees == 2 && closes == 0);
  fail_init = 0;

  struct rama_resolver *resolver = test_res_create(&config);
  CHECK(resolver != NULL);
  CHECK(config.retrans == 5 && config.retry == 2 && config.nscount == 3);
  CHECK(config.ndots == 2);
  CHECK(config.options == (RES_INIT | RES_DEFNAMES | RES_DNSRCH));
  CHECK(strcmp(test_res_search(resolver, 0), "corp.test") == 0);
  CHECK(strcmp(test_res_search(resolver, 1), "other.test") == 0);
  CHECK(test_res_search(resolver, 2) == NULL);
  CHECK(test_res_search(resolver, -1) == NULL);
  CHECK(test_res_search(resolver, MAXDNSRCH) == NULL);

  struct rama_res_nameserver server;
  resolver->state.nsaddr_list[0].sin_family = AF_INET;
  resolver->state.nsaddr_list[0].sin_port = htons(12345);
  resolver->state.nsaddr_list[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(test_res_nameserver(resolver, 0, &server) == 1);
  CHECK(server.family == 4 && server.port == 12345 && server.scope_id == 0);
  CHECK(server.address[0] == 127 && server.address[3] == 1);
  for (int i = 4; i < 16; i++) {
    CHECK(server.address[i] == 0);
  }

  /* libc may keep an IPv4 address in its IPv6-sized extension copy. */
  struct sockaddr_in6 copy;
  memset(&copy, 0, sizeof(copy));
  struct sockaddr_in *v4 = (struct sockaddr_in *)&copy;
  v4->sin_family = AF_INET;
  v4->sin_port = htons(23456);
  v4->sin_addr.s_addr = htonl(0xc0000201); /* 192.0.2.1 */
  resolver->state._u._ext.nsaddrs[0] = &copy;
  CHECK(test_res_nameserver(resolver, 0, &server) == 1);
  CHECK(server.family == 4 && server.port == 23456);
  CHECK(server.address[0] == 192 && server.address[2] == 2);

  memset(&copy, 0, sizeof(copy));
  copy.sin6_family = AF_INET6;
  copy.sin6_port = htons(853);
  copy.sin6_scope_id = 7;
  const unsigned char ipv6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0,    0,
                                  0,    0,    0, 0, 0, 0, 0x12, 0x34};
  memcpy(&copy.sin6_addr, ipv6, sizeof(ipv6));
  CHECK(test_res_nameserver(resolver, 0, &server) == 1);
  CHECK(server.family == 6 && server.port == 853 && server.scope_id == 7);
  CHECK(memcmp(server.address, ipv6, sizeof(ipv6)) == 0);
  copy.sin6_family = AF_UNSPEC;
  CHECK(test_res_nameserver(resolver, 0, &server) == 0);
  CHECK(test_res_nameserver(resolver, -1, &server) == 0);
  CHECK(test_res_nameserver(resolver, MAXNS, &server) == 0);
  resolver->state._u._ext.nsaddrs[0] = NULL;

  config.retrans = config.retry = config.nscount = 1;
  config.ndots = 5;
  config.options = expected_options = RES_USEVC;
  expected_nscount = 1;
  unsigned char answer[16] = {0};
  errno = EBADF;
  struct rama_res_result result = test_res_query(
      resolver, &config, "example.test.", ns_t_txt, answer, sizeof(answer));
  CHECK(query_arguments_match && answer[0] == 42);
  CHECK(result.len == -1 && result.system_error == EACCES);
  CHECK(result.resolver_error == HOST_NOT_FOUND);
  CHECK(config.options == (RES_USEVC | RES_IGNTC));
  CHECK(config.ndots == 5 && config.nscount == 1);
  CHECK(resolver->state.nscount == 3);

  /* The next query can use all nameservers again while retaining libc's
     option changes from the previous call. */
  config.nscount = expected_nscount = 3;
  expected_options = RES_USEVC | RES_IGNTC;
  query_arguments_match = 0;
  test_res_query(resolver, &config, "example.test.", ns_t_txt, answer,
                 sizeof(answer));
  CHECK(query_arguments_match && config.nscount == 3 && config.ndots == 5);

  /* A count beyond the configured set, or below zero, is clamped into it. */
  config.nscount = MAXNS + 1;
  expected_nscount = 3;
  query_arguments_match = 0;
  test_res_query(resolver, &config, "example.test.", ns_t_txt, answer,
                 sizeof(answer));
  CHECK(query_arguments_match && config.nscount == 3);
  resolver->nscount = 2;
  config.nscount = 3;
  expected_nscount = 2;
  query_arguments_match = 0;
  test_res_query(resolver, &config, "example.test.", ns_t_txt, answer,
                 sizeof(answer));
  CHECK(query_arguments_match && config.nscount == 2);
  resolver->nscount = 3;
  config.nscount = -1;
  expected_nscount = 0;
  query_arguments_match = 0;
  test_res_query(resolver, &config, "example.test.", ns_t_txt, answer,
                 sizeof(answer));
  CHECK(query_arguments_match && config.nscount == 0);

  /* Observe the count at the actual close call, and that destruction frees
     the allocation once, even if the last query restricted the count. */
  resolver->state.nscount = 1;
  test_res_destroy(resolver);
  CHECK(closes == 1 && closed_nscount == 3 && frees == 3);
  return 0;
}

/* These helpers operate on the real resolver owned by Rust, without mocks. */
int rama_res_test_override_nameservers(
    struct rama_resolver *resolver, const struct rama_res_nameserver *servers,
    int count) {
  struct __res_state *state = &resolver->state;
  state->nscount = resolver->nscount;
  close_native_state(state);
  memset(&state->_u, 0, sizeof(state->_u));
  memset(state->nsaddr_list, 0, sizeof(state->nsaddr_list));
  if (count < 0)
    count = 0;
  if (count > MAXNS)
    count = MAXNS;
  state->nscount = resolver->nscount = count;
  for (int i = 0; i < MAXNS; i++) {
    state->_u._ext.nssocks[i] = -1;
  }
  for (int i = 0; i < count; i++) {
    if (servers[i].family == 4) {
      struct sockaddr_in *v4 = &state->nsaddr_list[i];
      v4->sin_family = AF_INET;
      v4->sin_port = htons(servers[i].port);
      memcpy(&v4->sin_addr, servers[i].address, 4);
    } else if (servers[i].family == 6) {
      struct sockaddr_in6 *v6 = calloc(1, sizeof(*v6));
      if (v6 == NULL)
        return 0; /* the resolver owns any earlier allocations */
      v6->sin6_family = AF_INET6;
      v6->sin6_port = htons(servers[i].port);
      v6->sin6_scope_id = servers[i].scope_id;
      memcpy(&v6->sin6_addr, servers[i].address, 16);
      state->_u._ext.nsaddrs[i] = v6;
    } else {
      return 0;
    }
  }
  return 1;
}

/* Check every field offset as well as size/alignment across the real ABI.
   Only scalar size_t values cross this test interface. */
size_t rama_res_test_layout(size_t index) {
  const size_t layout[] = {
      sizeof(struct rama_res_config),
      _Alignof(struct rama_res_config),
      offsetof(struct rama_res_config, retrans),
      offsetof(struct rama_res_config, retry),
      offsetof(struct rama_res_config, nscount),
      offsetof(struct rama_res_config, options),
      offsetof(struct rama_res_config, ndots),
      sizeof(struct rama_res_result),
      _Alignof(struct rama_res_result),
      offsetof(struct rama_res_result, len),
      offsetof(struct rama_res_result, system_error),
      offsetof(struct rama_res_result, resolver_error),
      sizeof(struct rama_res_nameserver),
      _Alignof(struct rama_res_nameserver),
      offsetof(struct rama_res_nameserver, family),
      offsetof(struct rama_res_nameserver, address),
      offsetof(struct rama_res_nameserver, port),
      offsetof(struct rama_res_nameserver, scope_id),
  };
  return index < sizeof(layout) / sizeof(layout[0]) ? layout[index]
                                                    : (size_t)-1;
}
