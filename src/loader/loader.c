#include <common.h>
#include <loader.h>
#include <csr.h>
#include <vm.h>

static int print_pgtable(int level, pte* tb, uintptr_t vaddr)
{
  pte* walk;
  int ret = 0;
  int i=0;

   for (walk=tb, i=0; walk < tb + ((1<<12)/sizeof(pte)) ; walk += 1, i++)
  {
    if(*walk == 0)
      continue;

     pte e = *walk;
    uintptr_t phys_addr = (e >> 10) << 12;

    if(level == 1 || (e & PTE_R) || (e & PTE_W) || (e & PTE_X))
    {
      printf("[pgtable] level:%d, base: 0x%ln, i:%d (0x%lx -> 0x%lx)\r\n", level, tb, i, ((vaddr << 9) | (i&0x1ff))<<12, phys_addr);
    }
    else
    {
      printf("[pgtable] level:%d, base: 0x%ln, i:%d, pte: 0x%lx \r\n", level, tb, i, e);
    }

    if(level > 1 && !(e & PTE_R) && !(e & PTE_W) && !(e & PTE_X))
    {
      if(level == 3 && (i&0x100))
        vaddr = 0xffffffffffffffffUL;
      ret |= print_pgtable(level - 1, (pte*) __va(phys_addr), (vaddr << 9) | (i&0x1ff));
    }
  }
  return ret;
}

int mapVAtoPA(uintptr_t vaddr, uintptr_t paddr, size_t size) {

    pte app = pte_create(ppn(paddr), PTE_R | PTE_W | PTE_X);
    load_l3_page_table[0] = app;
    load_l2_page_table[0] = ptd_create((uintptr_t) load_l3_page_table);
    root_page_table[0] = ptd_create((uintptr_t) load_l2_page_table);
    // create page table by following eyrie rt
    // alloc page and map into page table according to size
//    uintptr_t pages = alloc_pages(vpn(vaddr), PAGE_UP(size/PAGE_SIZE), PTE_R | PTE_W | PTE_X);
//    pte appmem = pte_create(vpn(vaddr), PTE_R | PTE_W);
    return 0;
}

void csr_write_regs(uintptr_t entry_point) {
    csr_write(satp, satp_new(kernel_va_to_pa(root_page_table)));
    csr_write(stvec, entry_point);
}

int hello(void* i) {
    uintptr_t minRuntimePaddr;
    uintptr_t maxRuntimePaddr;
    uintptr_t minRuntimeVaddr;
    uintptr_t maxRuntimeVaddr;
    elf_getMemoryBounds(i, 1, &minRuntimePaddr, &maxRuntimePaddr);
    elf_getMemoryBounds(i, 0, &minRuntimeVaddr, &maxRuntimeVaddr);
    if (!IS_ALIGNED(minRuntimePaddr, PAGE_SIZE)) {
        return false;
    }
/*    if (loadElf(i)) {
        return false;
    }*/
    int status = mapVAtoPA(minRuntimeVaddr, minRuntimePaddr, 0 /* size */);
    if (status != 0) {
       return 1;
    }
    print_pgtable(0, root_page_table, minRuntimeVaddr);
    return 10;
}
