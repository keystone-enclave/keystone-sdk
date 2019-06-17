/*
 * Generic page.h implementation, for NOMMU architectures.
 * This provides the dummy definitions for the memory management.
 */


/*
 * These are used to make use of C type-checking..
 */
typedef struct {
    unsigned long pte;
} pte_t;
typedef struct {
    unsigned long pmd[16];
} pmd_t;
typedef struct {
    unsigned long pgd;
} pgd_t;
typedef struct {
    unsigned long pgprot;
} pgprot_t;
typedef struct page *pgtable_t;


#define pte_val(x)	((x).pte)
#define pmd_val(x)	((&x)->pmd[0])
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __va(x) ((void *)((unsigned long) (x)))
#define __pa(x) ((unsigned long) (x))

#define __pte(x)	((pte_t) { (x) } )
#define __pmd(x)	((pmd_t) { (x) } )
#define __pgd(x)	((pgd_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

// page table entry (PTE) fields
#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_SOFT  0x300 // Reserved for Software

#define PTE_PPN_SHIFT 10

#define VA_BITS 39

#define RISCV_PGLEVEL_BITS 9
#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE (1 << RISCV_PGSHIFT)

extern unsigned long memory_start;
extern unsigned long memory_end;

static inline pte_t pte_create(unsigned long ppn, int type)
{
	return __pte( (ppn << PTE_PPN_SHIFT) | PTE_V | type );
}

static inline pte_t ptd_create(unsigned long ppn)
{
	return pte_create(ppn, PTE_V);
}

static paddr_t pte_ppn(pte_t pte)
{
	return pte_val(pte) >> PTE_PPN_SHIFT;
}

static paddr_t ppn(vaddr_t addr)
{
	return __pa(addr) >> RISCV_PGSHIFT;
}

static size_t pt_idx(vaddr_t addr, int level)
{
	size_t idx = addr >> (RISCV_PGLEVEL_BITS*level + RISCV_PGSHIFT);
	return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}


static pte_t* __ept_walk_create(vaddr_t *pg_list, pte_t* root_page_table, vaddr_t addr);

static pte_t* __ept_continue_walk_create(vaddr_t *pg_list, pte_t* root_page_table, vaddr_t addr, pte_t* pte)
{
	//Gets free page list from pg_list
	unsigned long free_ppn = ppn(*pg_list);
	*pte = ptd_create(free_ppn);
  *pg_list += PAGE_SIZE;
//	printf("ptd_create: ppn = %p, pte = %p\n", (void *) (free_ppn << RISCV_PGSHIFT), (void *) (*pte).pte);
	return __ept_walk_create(pg_list, root_page_table, addr);
}

static pte_t* __ept_walk_internal(vaddr_t* pg_list, pte_t* root_page_table, vaddr_t addr, int create)
{
	int fd_mem;
	fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
	if (fd_mem < 0) {
		return 0;
	}

	pte_t* t = (root_page_table);

	int i;
	for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
		size_t idx = pt_idx(addr, i);
//		printf("pg_list: %p, pt: %p\n", (void *) *pg_list, (void *) __pa(root_page_table + idx));
//		printf("    level %d: pt_idx %d (%lu)\n", i, (int) idx, idx);
		if (!(pte_val(t[idx]) & PTE_V)){
			return create ? __ept_continue_walk_create(pg_list, root_page_table, addr, &t[idx]) : 0;
			}

		t = (pte_t*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_mem, pte_ppn(t[idx]) << RISCV_PGSHIFT);
	}
	close(fd_mem);
	return &t[pt_idx(addr, 0)];
}

static pte_t* __ept_walk_create(vaddr_t *pg_list, pte_t* root_page_table, vaddr_t addr)
{
	return __ept_walk_internal(pg_list, root_page_table, addr, 1);
}

/* This function pre-allocates the required page tables so that
 * the virtual addresses are linearly mapped to the physical memory */
size_t epm_alloc_vspace(vaddr_t *pg_list, pte_t* root_page_table, vaddr_t addr, size_t num_pages)
{
	size_t count;

	for(count=0; count < num_pages; count++, addr += PAGE_SIZE)
	{
		pte_t* pte = __ept_walk_create(pg_list, root_page_table, addr);
		if(!pte)
			break;
	}

	return count;
}