// D9a: string.h minimal untuk BearSSL (freestanding). Implementasi
// memcpy/memmove/memset/memcmp/strlen disediakan kernel saat BearSSL di-link (D9b).
#ifndef BMAHOS_COMPAT_STRING_H
#define BMAHOS_COMPAT_STRING_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
#endif
