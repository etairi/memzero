/*
 * Set of benchmarks comparing different memory zeroing techniques.
 * Based on: https://github.com/open-quantum-safe/liboqs/issues/48
 *
 * Author:
 * - Erkan Tairi <erkan.tairi@gmail.com>
 */

#ifndef _WIN32
#define _GNU_SOURCE
#else
#pragma once
#define _CRT_SECURE_NO_WARNINGS 1
#endif
#define __STDC_WANT_LIB_EXT1__ 1
#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "ds_benchmark.h"
#include "memzero.h"

/* Constants for our benchmarks. */
#define MEMZERO_TEST_SMALL_BLOCK_SIZE   0x1000L
#define MEMZERO_TEST_LARGE_BLOCK_SIZE   0x1000000L
#define MEMZERO_BENCH_SECONDS           1

/* Custom stack size which will include the secret. */
#ifdef _WIN32
#define MEMZERO_STACK_SIZE				(4096 + sizeof(secret))
#else
#define MEMZERO_STACK_SIZE              (SIGSTKSZ + sizeof(secret))
#endif

/*
 * The secret that we write out to the stack. 
 * After cleaning, we shouldn't be able to find it in our stack.
*/
static const char secret[24] = {
	0x4e, 0x65, 0x76, 0x65, 0x72, 0x20, 0x67, 0x6f,
	0x6e, 0x6e, 0x61, 0x20, 0x67, 0x69, 0x76, 0x65,
	0x20, 0x79, 0x6f, 0x75, 0x20, 0x75, 0x70, 0x2c,
};

/* Memory and pointer allocated for our stack. */
#ifdef _WIN32
static char *stack_buf = NULL;
PVOID stack_pointer = NULL;
void *main_fiber = NULL;
#else
static char stack_buf[MEMZERO_STACK_SIZE];
#endif

typedef struct memzero_testcase {
    enum memzero_alg_name alg_name;
    const char *name;
} memzero_testcase_t;

memzero_testcase_t memzero_testcases[] = {
    { memzero_alg_memset, "memset" },
	{ memzero_alg_memset_s, "memset_s" },
    { memzero_alg_volatile1, "volatile1" },
    { memzero_alg_volatile2, "volatile2" },
    { memzero_alg_volatile3, "volatile3" },
    { memzero_alg_sodium, "sodium" },
#ifdef _WIN32
	{ memzero_alg_SecureZeroMemory, "SecureZeroMemory" },
#elif !defined(__APPLE__)
	{ memzero_alg_explicit_bzero, "explicit_bzero" }
#endif
};

#ifdef _WIN32
/* Windows does not offer memmem function by default. */
void *memmem(const void *haystack, size_t haystack_len,
			 const void * const needle, const size_t needle_len)
{
	if (needle_len == 0) {
		return (void*)haystack;
	}

	assert(haystack != NULL);
	assert(needle != NULL);

	for (const char *h = haystack; haystack_len >= needle_len; ++h, --haystack_len) {
		if (!memcmp(h, needle, needle_len)) {
			return h;
		}
	}
	return NULL;
}

/* Verify that we are on the custom stack in Windows. */
static void assert_on_stack(void) {
	assert(stack_pointer != NULL);
	assert(stack_pointer == GetCurrentFiber());
}

/* Call the provided signal handler on a custom stack in Windows. */
static void call_on_stack(DWORD(_stdcall Fn)(LPVOID)) {
	main_fiber = ConvertThreadToFiber(NULL);
	void *stack_fiber = CreateFiberEx(MEMZERO_STACK_SIZE, 0, 0, Fn, NULL);

	SwitchToFiber(stack_fiber);
	DeleteFiber(stack_fiber);
}
#else
/* Verify that we are on the custom stack in Linux/macOS. */
static void assert_on_stack(void) {
    stack_t current_stack;
    assert(0 == sigaltstack(NULL, &current_stack));
    assert(SS_ONSTACK == (current_stack.ss_flags & SS_ONSTACK));
}

/* Call the provided signal handler on a custom stack in Linux/macOS. */
static void call_on_stack(void (*fn)(int)) {
    const stack_t stack = {
        .ss_sp = stack_buf,
        .ss_size = sizeof(stack_buf),
    };

    const struct sigaction action = {
        .sa_handler = fn,
        .sa_flags = SA_ONSTACK,
    };

    stack_t old_stack;
    struct sigaction old_action;

    /* Setup the stack and signal handler. */
    assert(0 == sigaltstack(&stack, &old_stack));
    assert(0 == sigaction(SIGUSR1, &action, &old_action));

    /* Raise a signal. This will only return after the signal handler has returned. */
    assert(0 == raise(SIGUSR1));

    /* Restore the previous state, disable our alt stack. */
    sigaction(SIGUSR1, &old_action, NULL);
    sigaltstack(&old_stack, NULL);
}
#endif

/*
 * Tests a provided memory clean algorithm. Must be called from the custom stack.
 * First writes the secret to the stack, then runs the provided cleaning algorithm.
 * If no cleaning algorithm is provided, just falls back to using memset.
 *
 * Returns the address of where the secret was written. If memory cleaning was successful,
 * the secret should no longer be readable.
 */
static char *memzero_test(memzero_func_t memzero) {
    char buf[sizeof(secret)];
    char *result;

    assert_on_stack();
    memcpy(buf, secret, sizeof(secret));

#ifdef _WIN32
	ULONG_PTR lo, hi;
	GetCurrentThreadStackLimits(&lo, &hi);
	stack_buf = hi - MEMZERO_STACK_SIZE;
#endif

    result = memmem(stack_buf, MEMZERO_STACK_SIZE, buf, sizeof(buf));
    if (memzero != NULL) {
        memzero(buf, sizeof(buf));
    } else {
        // Fallback to memset. If optimization are enabled, this gets optimized out.
        memset(buf, 0, sizeof(buf));
    }

    return result;
}

/*
 * Verifies the secret is where we expect it to be if things are not zeroed out properly.
 * This implementation uses memset, which should get optimized away. If optimizations are not 
 * enabled, this test is skipped.
 *
 * We can disable memset being optimized away by using the compiler flag -fno-builtin-memset in 
 * GCC, and the macro #pragma optimize("", off) in MSVC.
 *
 * In GCC the macro __OPTIMIZE__ is defined in all optimizing compilations. Whereas MSVC does
 * not define such a macro. Hence, we define our own macro _MSVC_OPTIMIZE only for the Release
 * configuration, which uses optimizations.
 */
static int memzero_test_correctness_noclean() {
#if defined(__OPTIMIZE__) || defined(_MSVC_OPTIMIZE)
	printf("%-30s", "no clean");
    char *buf = memzero_test(NULL);

    if (memcmp(buf, secret, sizeof(secret)) == 0) {
        /* The secret is still present, memset was optmized away (as predicted). */
        printf("Test passed\n");
        return 1;
    } else {
        printf("Test failed\n");
        return 0;
    }
#else
    printf("%-30s", "no clean");
    printf("Test skipped (no optimizations)\n");
    return 1;
#endif
}

static int memzero_test_correctness_clean(enum memzero_alg_name alg_name, const char *name) {
    memzero_func_t memzero = memzero_func(alg_name);
    if (memzero == NULL) {
        fprintf(stderr, "Error: memzero is NULL\n");
        return 0;
    }

	printf("%-30s", name);
    char *buf = memzero_test(memzero);

    if (memcmp(buf, secret, sizeof(secret)) != 0) {
        printf("Test passed\n");
        return 1;
    } else {
        printf("Test failed\n");
        return 0;
    }
}

#ifdef _WIN32
static DWORD WINAPI memzero_test_correctness_signal_handler(LPVOID lpParam) {
	stack_pointer = GetCurrentFiber();
#else
static void memzero_test_correctness_signal_handler(int arg) {
	(void)(arg);
#endif
	int success = 1;
    size_t memzero_testcases_len = sizeof(memzero_testcases) / sizeof(memzero_testcase_t);
    const char *current_test = NULL;

    printf("\n================================================================================\n");
    printf("Memory Cleaning Correctness Test\n");
    printf("================================================================================\n");

    memzero_test_correctness_noclean();

    for (size_t i = 0; i < memzero_testcases_len; i++) {
        current_test = memzero_testcases[i].name;
        if (memzero_test_correctness_clean(memzero_testcases[i].alg_name, memzero_testcases[i].name) != 1) {
            goto error;
        }
    }

	if (success) {
		printf("Success: all memory cleaning correctness tests passed.\n\n");
		goto cleanup;
	}

	error:
		success = 0;
        printf("Error: %s failed the memory cleaning correctness test.\n", current_test);

	cleanup:
	#ifdef _WIN32
		SwitchToFiber(main_fiber);
	#endif
        return;
}

static int memzero_bench(enum memzero_alg_name alg_name, const char *name) {
    memzero_func_t memzero = memzero_func(alg_name);
    if (memzero == NULL) {
        fprintf(stderr, "Error: memzero is NULL\n");
        return 0;
    }

    printf("\n================================================================================\n");
    printf("Benchmark Test: %s\n", name);
    printf("================================================================================\n");

    PRINT_TIMER_HEADER
    TIME_OPERATION_SECONDS({ 
        char *buffer = malloc(MEMZERO_TEST_SMALL_BLOCK_SIZE);
        memzero(buffer, MEMZERO_TEST_SMALL_BLOCK_SIZE);
        free(buffer); 
    }, "small block", MEMZERO_BENCH_SECONDS);
    TIME_OPERATION_SECONDS({ 
        char *buffer = malloc(MEMZERO_TEST_LARGE_BLOCK_SIZE);
        memzero(buffer, MEMZERO_TEST_LARGE_BLOCK_SIZE);
        free(buffer);
    }, "large block", MEMZERO_BENCH_SECONDS);
    PRINT_TIMER_FOOTER

    return 1;
}

int main(void) {
    int success;
    const char *current_test;
    size_t memzero_testcases_len = sizeof(memzero_testcases) / sizeof(memzero_testcase_t);

    call_on_stack(memzero_test_correctness_signal_handler);

    for (size_t i = 0; i < memzero_testcases_len; i++) {
        current_test = memzero_testcases[i].name;
        success = memzero_bench(memzero_testcases[i].alg_name, memzero_testcases[i].name);
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