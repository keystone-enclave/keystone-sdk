#ifndef __STRING_H__
#define __STRING_H__
#include <stddef.h>
void* memcpy(void* dest, const void* src, size_t len);
void* memset(void* dest, int byte, size_t len);
int memcmp(const void* ptr1, const void* ptr2, size_t len);
int strcmp (const char *p1, const char *p2);
#endif
