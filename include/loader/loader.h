#include "elf.h"

// page constants
#define IS_ALIGNED(x, align) (!((x) & (align - 1)))
#define PAGE_BITS 12
#define PAGE_SIZE (1UL << PAGE_BITS)

// Mode constants
#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

// method definitions
extern int hello(void * i);
extern int loadElf(void* elf);

inline void* memset(void* s, int c, size_t sz) {
    char* p = (char*)s;

    /* c should only be a byte's worth of information anyway, but let's mask out
     * everything else just in case.
     */
    char x = c & 0xff;

    while (sz--)
        *p++ = x;
    return s;
}

inline void * memcpy(void* dst, const void* src, long unsigned int cnt)
{
    char *pszDest = (char *)dst;
    const char *pszSource =( const char*)src;
    if((pszDest!= NULL) && (pszSource!= NULL))
    {
        while(cnt) //till cnt
        {
            //Copy byte by byte
            *(pszDest++)= *(pszSource++);
            --cnt;
        }
    }
    return dst;
}
