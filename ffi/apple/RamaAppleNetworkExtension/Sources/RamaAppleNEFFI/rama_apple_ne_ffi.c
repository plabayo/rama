#include "rama_apple_ne_ffi.h"
#include <bsm/libbsm.h>
#include <mach/message.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct RamaWriterBudgetAtomic {
    _Atomic uint64_t value;
};

RamaWriterBudgetAtomic* rama_writer_budget_atomic_new(uint64_t initial_value) {
    RamaWriterBudgetAtomic* atomic = malloc(sizeof(*atomic));
    if (atomic == NULL) {
        return NULL;
    }
    atomic_init(&atomic->value, initial_value);
    return atomic;
}

void rama_writer_budget_atomic_free(RamaWriterBudgetAtomic* atomic) {
    free(atomic);
}

uint64_t rama_writer_budget_atomic_load(const RamaWriterBudgetAtomic* atomic) {
    return atomic_load_explicit(&atomic->value, memory_order_acquire);
}

bool rama_writer_budget_atomic_compare_exchange(
    RamaWriterBudgetAtomic* atomic,
    uint64_t* expected,
    uint64_t desired
) {
    return atomic_compare_exchange_strong_explicit(
        &atomic->value,
        expected,
        desired,
        memory_order_acq_rel,
        memory_order_acquire
    );
}

uint64_t rama_writer_budget_atomic_load_seq_cst(const RamaWriterBudgetAtomic* atomic) {
    return atomic_load_explicit(&atomic->value, memory_order_seq_cst);
}

bool rama_writer_budget_atomic_compare_exchange_seq_cst(
    RamaWriterBudgetAtomic* atomic,
    uint64_t* expected,
    uint64_t desired
) {
    return atomic_compare_exchange_strong_explicit(
        &atomic->value,
        expected,
        desired,
        memory_order_seq_cst,
        memory_order_seq_cst
    );
}

bool rama_writer_budget_atomic_is_lock_free(const RamaWriterBudgetAtomic* atomic) {
    return atomic_is_lock_free(&atomic->value);
}

int32_t rama_apple_audit_token_to_pid(const uint8_t* bytes, size_t len) {
    if (bytes == NULL || len != sizeof(audit_token_t)) {
        return -1;
    }

    audit_token_t token;
    memcpy(&token, bytes, sizeof(token));
    return (int32_t)audit_token_to_pid(token);
}
