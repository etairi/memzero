#include <assert.h>
#include <stddef.h>
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
		abort(); // LCOV_EXCL_LINE
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
	#ifdef __STDC_LIB_EXT1__
		case memzero_alg_memset_s:
			return &memzero_memset_s;
	#endif
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
