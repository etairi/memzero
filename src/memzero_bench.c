/*
 * Set of benchmarks comparing different memory zeroing techniques.
 * Based on: https://github.com/open-quantum-safe/liboqs/issues/48
 */

#define __STDC_WANT_LIB_EXT1__ 1
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ds_benchmark.h"

#define MEMZERO_TEST_SMALL_BLOCK_SIZE   0x1000L
#define MEMZERO_TEST_LARGE_BLOCK_SIZE   0x1000000L
#define MEMZERO_BENCH_SECONDS           1

enum memzero_alg_name {
    memzero_alg_memset,
    memzero_alg_volatile1,
    memzero_alg_volatile2,
    memzero_alg_volatile3,
    memzero_alg_sodium,
    memzero_alg_explicit_bzero,
#ifdef __STDC_LIB_EXT1__
    memzero_alg_memset_s,
#endif
#ifdef _WIN32
    memzero_alg_SecureZeroMemory,
#endif
    memzero_alg_default
};

typedef void (*memzero_func_t)(void * const ptr, const size_t len);
memzero_func_t memzero_func(enum memzero_alg_name alg_name);

typedef struct memzero_testcase {
    enum memzero_alg_name alg_name;
    const char *name;
} memzero_testcase_t;

memzero_testcase_t memzero_testcases[] = {
    { memzero_alg_memset, "memset" },
    { memzero_alg_volatile1, "volatile1" },
    { memzero_alg_volatile2, "volatile2" },
    { memzero_alg_volatile3, "volatile3" },
    { memzero_alg_sodium, "sodium" },
    { memzero_alg_explicit_bzero, "explicit_bzero" },
#ifdef __STDC_LIB_EXT1__
    { memzero_alg_memset_s, "memset_s" },
#endif
#ifdef _WIN32
    { memzero_alg_SecureZeroMemory, "SecureZeroMemory" }
#endif
};

typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t memset_func = memset;

void memzero_volatile1(void * const ptr, const size_t len) {
    memset_func(ptr, 0, len);
}

void memzero_volatile2(void * const ptr, const size_t len) {
    void *(*volatile const volatile_memset)(void *, int, size_t) = memset;
    volatile_memset(ptr, 0, len);
}

void memzero_volatile3(void * const ptr, const size_t len) {
    void *volatile const ptrv = ptr;
    memset(ptrv, 0, len);
}

void memzero_memset(void * const ptr, const size_t len) {
    memset(ptr, 0, len);
}

void memzero_sodium(void * const pnt, const size_t len) {
    volatile unsigned char * volatile pnt_ =
        (volatile unsigned char * volatile) pnt;
    size_t i = (size_t)0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}

// NOTE: Platforms that do not support explicit_bzero will throw an error here!
void memzero_explicit_bzero(void * const pnt, const size_t len) {
    explicit_bzero(pnt, len);
}

#ifdef __STDC_LIB_EXT1__
void memzero_memset_s(void * const pnt, const size_t len) {
    if (0U < len && memset_s(pnt, (rsize_t)len, 0, (rsize_t)len) != 0) {
        abort(); /* LCOV_EXCL_LINE */
    }
}
#endif

#ifdef _WIN32
void memzero_SecureZeroMemory(void * const pnt, const size_t len) {
    SecureZeroMemory(pnt, len);
}
#endif

void memzero_defualt(void * const ptr, const size_t len) {
    memset_func(ptr, 0, len);
}

memzero_func_t memzero_func(enum memzero_alg_name alg_name) {
    switch (alg_name) {
        case memzero_alg_memset:
            return &memzero_memset;
        case memzero_alg_volatile1:
            return &memzero_volatile1;
        case memzero_alg_volatile2:
            return &memzero_volatile2;
        case memzero_alg_volatile3:
            return &memzero_volatile3;
        case memzero_alg_sodium:
            return &memzero_sodium;
        case memzero_alg_explicit_bzero:
            return &memzero_explicit_bzero;
    #ifdef __STDC_LIB_EXT1__
        case memzero_alg_memset_s:
            return &memzero_memset_s;
    #endif
    #ifdef _WIN32
        case memzero_alg_SecureZeroMemory:
            return memzero_SecureZeroMemory;
    #endif
        case memzero_alg_default:
            return memzero_defualt;
        default:
            assert(0);
            return NULL; // Avoid the warning of potentialy uninitialized variable in VS.
    }
}

static int memzero_test_wrapper(enum memzero_alg_name alg_name, const char *name) {
    memzero_func_t memzero = memzero_func(alg_name);
    if (memzero == NULL) {
        fprintf(stderr, "Error: memzero is NULL\n");
        return 0;
    }

    printf("\n================================================================================\n");
    printf("Benchmarking %s\n", name);
    printf("================================================================================\n");

    PRINT_TIMER_HEADER
    TIME_OPERATION_SECONDS({ 
        char *buff = malloc(MEMZERO_TEST_SMALL_BLOCK_SIZE);
        memzero(buff, MEMZERO_TEST_SMALL_BLOCK_SIZE);
        free(buff); 
    }, "small block", MEMZERO_BENCH_SECONDS);
    TIME_OPERATION_SECONDS({ 
        char *buff = malloc(MEMZERO_TEST_LARGE_BLOCK_SIZE);
        memzero(buff, MEMZERO_TEST_LARGE_BLOCK_SIZE);
        free(buff);
    }, "large block", MEMZERO_BENCH_SECONDS);
    PRINT_TIMER_FOOTER

    return 1;
}

int main(void) {
    int success;
    const char * current_test;

    size_t memzero_testcases_len = sizeof(memzero_testcases) / sizeof(struct memzero_testcase);
    for (size_t i = 0; i < memzero_testcases_len; i++) {
        current_test = memzero_testcases[i].name;
        success = memzero_test_wrapper(memzero_testcases[i].alg_name, memzero_testcases[i].name);
        if (success != 1) {
            goto error;
        }
    }

    success = 1;
    goto cleanup;

    error:
        success = 0;
        fprintf(stderr, "Error: %s failed\n", current_test);

    cleanup:
        return (success == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
}