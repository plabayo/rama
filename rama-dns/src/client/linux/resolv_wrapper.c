#include <resolv.h>

int rama_res_ninit(res_state state) { return res_ninit(state); }

void rama_res_nclose(res_state state) { res_nclose(state); }

int rama_res_nsearch(res_state state, const char *dname, int class, int type,
                     unsigned char *answer, int anslen) {
  return res_nsearch(state, dname, class, type, answer, anslen);
}
