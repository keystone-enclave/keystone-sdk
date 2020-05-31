//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __MEMORY_H__
#define __MEMORY_H__
#include <stddef.h>
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <stdarg.h>
#include <assert.h>
#include "common.h"
#include "KeystoneDevice.h"

/*
 * Generic page.h implementation, for NOMMU architectures.
 * This provides the dummy definitions for the memory management.
 */
//#include "memory.h"

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

#if __riscv_xlen == 64
# define RISCV_PGLEVEL_MASK 0x1ff
# define RISCV_PGTABLE_HIGHEST_BIT 0x100
#else
# define RISCV_PGLEVEL_MASK 0x3ff
# define RISCV_PGTABLE_HIGHEST_BIT 0x300
#endif

#define RISCV_PGLEVEL_TOP ((VA_BITS - RISCV_PGSHIFT)/RISCV_PGLEVEL_BITS)


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


class Memory
{
public:
  Memory();
  ~Memory() {};
  virtual void init(KeystoneDevice* dev, vaddr_t phys_addr, size_t min_pages) = 0;
  virtual vaddr_t ReadMem(vaddr_t src, size_t size) = 0;
  virtual void WriteMem(vaddr_t src, vaddr_t dst, size_t size) = 0;
  virtual vaddr_t AllocMem(size_t size) = 0;
  virtual vaddr_t allocUTM(size_t size) = 0;
  bool allocPage(vaddr_t eva, vaddr_t src, unsigned int mode);
  size_t epm_alloc_vspace(vaddr_t addr, size_t num_pages);

  // getters to be deprecated
  vaddr_t getStartAddr() { return startAddr; }
  vaddr_t getCurrentEPMAddress() { return epmFreeList; }
  vaddr_t getRootPageTable() { return rootPageTable; }
protected:
  pte_t* __ept_walk_create(vaddr_t addr);
  pte_t* __ept_continue_walk_create(vaddr_t addr, pte_t* pte);
  pte_t* __ept_walk_internal(vaddr_t addr, int create);
  pte_t* __ept_walk(vaddr_t addr);
  vaddr_t epm_va_to_pa(vaddr_t addr);

  KeystoneDevice* pDevice;
  vaddr_t epmFreeList;
  vaddr_t utmFreeList;
  vaddr_t rootPageTable;
  vaddr_t startAddr;
};


class PhysicalEnclaveMemory : public Memory
{
private:
  vaddr_t start_phys_addr;
public:
  PhysicalEnclaveMemory() {};
  ~PhysicalEnclaveMemory() {};
  void init(KeystoneDevice* dev, vaddr_t phys_addr, size_t min_pages);
  vaddr_t ReadMem(vaddr_t src, size_t size);
  void WriteMem(vaddr_t src, vaddr_t dst, size_t size);
  vaddr_t AllocMem(size_t size);
  vaddr_t allocUTM(size_t size);
};

// Simulated memory reads/writes from calloc'ed memory
class SimulatedEnclaveMemory : public Memory
{
private:
  void* allocateAligned(size_t size, size_t alignment);
public:
  SimulatedEnclaveMemory() {};
  ~SimulatedEnclaveMemory() {};
  void init(KeystoneDevice* dev, vaddr_t phys_addr, size_t min_pages);
  vaddr_t ReadMem(vaddr_t src, size_t size);
  void WriteMem(vaddr_t src, vaddr_t dst, size_t size);
  vaddr_t AllocMem(size_t size);
  vaddr_t allocUTM(size_t size);
};


#endif
