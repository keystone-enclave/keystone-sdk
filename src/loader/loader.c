#include <common.h>
#include <loader.h>

int hello(void* i) {
    uintptr_t minRuntimePaddr;
    uintptr_t maxRuntimePaddr;
    elf_getMemoryBounds(i, 1, &minRuntimePaddr, &maxRuntimePaddr);
    if (!IS_ALIGNED(minRuntimePaddr, PAGE_SIZE)) {
        return false;
    }
    if (loadElf(i)) {
        return false;
    }
    return 10;
}

int loadElf(void* elf) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };

  unsigned int mode = RT_FULL; /* change later, this is only for runtime */
  for (unsigned int i = 0; i < elf_getNumProgramHeaders(elf); i++) {
    if (elf_getProgramHeaderType(elf, i) != PT_LOAD) {
      continue;
    }

    uintptr_t start      = elf_getProgramHeaderPaddr(elf, i);
    uintptr_t file_end   = start + elf_getProgramHeaderFileSize(elf, i);
    uintptr_t memory_end = start + elf_getProgramHeaderMemorySize(elf, i);
    void* src            = elf_getProgramSegment(elf, i);
    uintptr_t pa         = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(pa, PAGE_SIZE)) {
      size_t offset = pa - PAGE_DOWN(pa);
      size_t length = PAGE_UP(pa) - pa;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void*)src, length);
      if (!pMemory->allocPage(PAGE_DOWN(pa), (uintptr_t)page, mode))
        return 1; // failed to alloc page
      pa += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (pa + PAGE_SIZE <= file_end) {
      if (!pMemory->allocPage(pa, (uintptr_t)src, mode))
        return 1; // failed to allooc page

      src += PAGE_SIZE;
      pa += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (pa < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*)src, (size_t)(file_end - pa));
      if (!pMemory->allocPage(pa, (uintptr_t)page, mode))
        return 1;
      pa += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (pa < memory_end) {
      if (!pMemory->allocPage(pa, (uintptr_t)nullpage, mode))
        return 1;
      pa += PAGE_SIZE;
    }
  }
  return 0;
}
