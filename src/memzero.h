#ifndef MEMZERO_H
#define MEMZERO_H

enum memzero_alg_name {
	memzero_alg_memset,
	memzero_alg_memset_s,
	memzero_alg_volatile1,
	memzero_alg_volatile2,
	memzero_alg_volatile3,
	memzero_alg_sodium,
#ifdef _WIN32
	memzero_alg_SecureZeroMemory,
#elif !defined(__APPLE__)
	memzero_alg_explicit_bzero,
#endif
	memzero_alg_default
};

typedef void(*memzero_func_t)(void * const ptr, const size_t len);
memzero_func_t memzero_func(enum memzero_alg_name alg_name);

void memzero_memset(void * const ptr, const size_t len);
void memzero_memset_s(void * const pnt, const size_t len);
void memzero_volatile1(void * const ptr, const size_t len);
void memzero_volatile2(void * const ptr, const size_t len);
void memzero_volatile3(void * const ptr, const size_t len);
void memzero_sodium(void * const pnt, const size_t len);
void memzero_defualt(void * const ptr, const size_t len);

/* Platform specific functions. */
#ifdef _WIN32
void memzero_SecureZeroMemory(void * const pnt, const size_t len);
#elif !defined(__APPLE__)
void memzero_explicit_bzero(void * const pnt, const size_t len);
#endif

#endif