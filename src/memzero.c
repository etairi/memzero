#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "memzero.h"

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
		(volatile unsigned char * volatile)pnt;
	size_t i = (size_t)0U;

	while (i < len) {
		pnt_[i++] = 0U;
	}
}

#ifdef __STDC_LIB_EXT1__
void memzero_memset_s(void * const pnt, const size_t len) {
	if (0U < len && memset_s(pnt, (rsize_t)len, 0, (rsize_t)len) != 0) {
		abort(); /* LCOV_EXCL_LINE */
	}
}
#else
/*
 * If memset_s is not provided by the system (which is not supported by most 
 * compilers), we define our own. The following implementation is taken from 
 * Intel: https://github.com/intel/linux-sgx/blob/master/sdk/tlibc/string/memset_s.c
 */
static void * (*const volatile __memset_vp)(void *, int, size_t)
= (memset);

#ifdef _WIN32
errno_t memset_s(void *s, size_t smax, int c, size_t n) {
	errno_t err = 0;
#else
int memset_s(void *s, size_t smax, int c, size_t n) {
	int err = 0;
#endif
	if (s == NULL) {
		err = EINVAL;
		goto out;
	}
	if (smax > SIZE_MAX) {
		err = E2BIG;
		goto out;
	}
	if (n > SIZE_MAX) {
		err = E2BIG;
		n = smax;
	}
	if (n > smax) {
		err = EOVERFLOW;
		n = smax;
	}

	/* Calling through a volatile pointer should never be optimized away. */
	(*__memset_vp)(s, c, n);

	out:
		if (err == 0) {
			return 0;
		} 
		else {
			errno = err;
			return err;
		}
}

void memzero_memset_s(void * const pnt, const size_t len) {
	if (0U < len && memset_s(pnt, len, 0, len) != 0) {
		abort(); /* LCOV_EXCL_LINE */
	}
}
#endif

#ifdef _WIN32
void memzero_SecureZeroMemory(void * const pnt, const size_t len) {
	SecureZeroMemory(pnt, len);
}
#elif !defined(__APPLE__)
void memzero_explicit_bzero(void * const pnt, const size_t len) {
	explicit_bzero(pnt, len);
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
		case memzero_alg_memset_s:
			return &memzero_memset_s;
	#ifdef _WIN32
		case memzero_alg_SecureZeroMemory:
			return memzero_SecureZeroMemory;
	#elif !defined(__APPLE__)
		case memzero_alg_explicit_bzero:
			return &memzero_explicit_bzero;
	#endif
		case memzero_alg_default:
			return memzero_defualt;
		default:
			assert(0);
			return NULL;
	}
}
