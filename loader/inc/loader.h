#include "elf.h"
#include "string.h"

// Mode constants
#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

// method definitions
extern int hello(void * i, uintptr_t dram_base);
extern int loadElf(void* elf);
