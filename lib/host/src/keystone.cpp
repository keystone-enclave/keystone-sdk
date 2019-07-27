//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sys/stat.h>
#include <sys/mman.h>
//#include <linux/elf.h>
#include <keystone_user.h>
#include "keystone.h"
#include "memory.h"
#include "elffile.h"
#include "keystone_user.h"
#include "page.h"
#include "hash_util.h"
#include <math.h>

Keystone::Keystone() {
    runtimeFile = NULL;
    enclaveFile = NULL;
    untrusted_size = 0;
    untrusted_start = 0;
    epm_free_list = 0;
    root_page_table = 0;
    start_addr = 0;
//    hash[MDSIZE];
    eid = -1;
}

Keystone::~Keystone() {
  if(runtimeFile)
    delete runtimeFile;
  if(enclaveFile)
    delete enclaveFile;
  destroy();
}

unsigned long calculate_required_pages(
        unsigned long eapp_sz,
        unsigned long rt_sz) {
    unsigned long req_pages = 0;

    req_pages += ceil(eapp_sz / PAGE_SIZE);
    req_pages += ceil(rt_sz / PAGE_SIZE);

    /* FIXME: calculate the required number of pages for the page table.
     * We actually don't know how many page tables the enclave might need,
     * because the SDK never knows how its memory will be aligned.
     * Ideally, this should be managed by the driver.
     * For now, we naively allocate enough pages so that we can temporarily get away from this problem.
     * 15 pages will be more than sufficient to cover several hundreds of megabytes of enclave/runtime. */
    req_pages += 15;
    return req_pages;
}


keystone_status_t Keystone::loadUntrusted(bool hash) {
    vaddr_t va_start = ROUND_DOWN(untrusted_start, PAGE_BITS);
    vaddr_t va_end = ROUND_UP(untrusted_start + untrusted_size, PAGE_BITS);
    static char nullpage[PAGE_SIZE] = {0,};

    while (va_start < va_end) {
        if (allocPage(va_start, &utm_free_list, (vaddr_t) nullpage, UTM_FULL, hash) == KEYSTONE_ERROR){
          PERROR("failed to add page - allocPage() failed");
        }

        va_start += PAGE_SIZE;
    }
    return KEYSTONE_SUCCESS;
}

/* This function will be deprecated when we implement freemem */
keystone_status_t Keystone::initStack(vaddr_t start, size_t size, bool is_rt, bool hash)
{
  static char nullpage[PAGE_SIZE] = {0,};
  vaddr_t high_addr = ROUND_UP(start, PAGE_BITS);
  vaddr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (allocPage(va_start_stk,  &epm_free_list, (vaddr_t) nullpage, (is_rt ? RT_NOEXEC : USER_NOEXEC), hash) == KEYSTONE_ERROR)
      return KEYSTONE_ERROR;

    va_start_stk += PAGE_SIZE;
  }

  return KEYSTONE_SUCCESS;
}

void * allocate_aligned(size_t size, size_t alignment)
{
  const size_t mask = alignment - 1;
  const uintptr_t mem = (uintptr_t) calloc(size + alignment, sizeof(char));
  return (void *) ((mem + mask) & ~mask);
}

keystone_status_t Keystone::allocPage(vaddr_t va, vaddr_t *free_list, vaddr_t src, unsigned int mode, bool hash)
{

  vaddr_t page_addr, new_page;

  pte_t* pte = __ept_walk_create(start_addr, &epm_free_list, (pte_t *) root_page_table, va, fd, hash);

  /* if the page has been already allocated, return the page */
  if(pte_val(*pte) & PTE_V) {
      return KEYSTONE_SUCCESS;
  }

  /* otherwise, allocate one from EPM freelist */
  page_addr = *free_list >> PAGE_BITS;
  *free_list += PAGE_SIZE;

  switch (mode) {
    case USER_NOEXEC: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V);
      break;
    }
    case RT_NOEXEC: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_V);
      break;
    }
    case RT_FULL: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V);

      if(hash) {
        memcpy((void *) (page_addr << PAGE_BITS), (void *) src, PAGE_SIZE);
      } else {
        new_page = (vaddr_t) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                  (page_addr << PAGE_BITS) - start_addr);
        memcpy((void *) new_page, (void *) src, PAGE_SIZE);
      }
      break;
  }
    case USER_FULL: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);
      if(hash) {
        memcpy((void *) (page_addr << PAGE_BITS), (void *) src, PAGE_SIZE);
      }
      else{
        new_page = (vaddr_t) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (page_addr << PAGE_BITS) - start_addr);
        memcpy((void *) new_page, (void *) src, PAGE_SIZE);
      }
      break;
    }
    case UTM_FULL: {
      *pte = pte_create(page_addr, PTE_D | PTE_A | PTE_R | PTE_W |PTE_V);
      if(hash){
        memcpy((void *) (page_addr << PAGE_BITS), (void *) src, PAGE_SIZE);
      }
      break;
    }
    default: {
      PERROR("failed to add page - mode is invalid");
      return KEYSTONE_ERROR;
    }
  }

  return KEYSTONE_SUCCESS;

}

keystone_status_t Keystone::loadELF(ELFFile* elf, bool hash)
{
  static char nullpage[PAGE_SIZE] = {0,};
  unsigned int mode = elf->getPageMode();
  vaddr_t va;

  size_t num_pages = ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  va = elf->getMinVaddr();

  if (epm_alloc_vspace(start_addr, &epm_free_list, (pte_t *) root_page_table, va, num_pages, fd, hash) != num_pages)
  {
    ERROR("failed to allocate vspace\n");
    return KEYSTONE_ERROR;
  }


  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {

    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    vaddr_t start = elf->getProgramHeaderVaddr(i);
    vaddr_t file_end = start + elf->getProgramHeaderFileSize(i);
    vaddr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char* src = (char*) elf->getProgramSegment(i);
    va = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if(!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void*) src, length);
      if (allocPage(PAGE_DOWN(va), &epm_free_list, (vaddr_t) page, mode, hash) != KEYSTONE_SUCCESS)
        return KEYSTONE_ERROR;
      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (allocPage(va, &epm_free_list, (vaddr_t) src, mode, hash) != KEYSTONE_SUCCESS)
        return KEYSTONE_ERROR;

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments */
    if (va < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) src, (size_t) (file_end - va));
      if (allocPage(va,  &epm_free_list, (vaddr_t) page, mode, hash) != KEYSTONE_SUCCESS)
        return KEYSTONE_ERROR;
      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end)
    {
      if (allocPage(va,  &epm_free_list, (vaddr_t) nullpage, mode, hash) != KEYSTONE_SUCCESS)
        return KEYSTONE_ERROR;
      va += PAGE_SIZE;
    }
  }

  return KEYSTONE_SUCCESS;
}


/* This will walk the entire vaddr space in the enclave, validating
   linear at-most-once paddr mappings, and then hashing valid pages */
int validate_and_hash_epm(hash_ctx_t* hash_ctx, int level,
                          pte_t* tb, uintptr_t vaddr, int contiguous,
                          struct keystone_hash_enclave* cargs,
                          uintptr_t* runtime_max_seen,
                          uintptr_t* user_max_seen,
                          int fd)
{
  pte_t* walk;
  int i;

  /* iterate over PTEs */
  for (walk=tb, i=0; walk < tb + (RISCV_PGSIZE/sizeof(pte_t)); walk += 1,i++)
  {
    if (pte_val(*walk) == 0) {
      contiguous = 0;
      continue;
    }
    uintptr_t vpn;
    uintptr_t phys_addr = (pte_val(*walk) >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
    /* Check for blatently invalid mappings */
    int map_in_epm = (phys_addr >= cargs->epm_paddr &&
                      phys_addr < cargs->epm_paddr + cargs->epm_size);
    int map_in_utm = (phys_addr >= cargs->utm_paddr &&
                      phys_addr < cargs->utm_paddr + cargs->utm_size);

    /* EPM may map anything, UTM may not map pgtables */
    if(!map_in_epm && (!map_in_utm || level != 1)){
      goto fatal_bail;
    }

    /* propagate the highest bit of the VA */
    if ( level == RISCV_PGLEVEL_TOP && i & RISCV_PGTABLE_HIGHEST_BIT )
      vpn = ((-1UL << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));
    else
      vpn = ((vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK));

    uintptr_t va_start = vpn << RISCV_PGSHIFT;

    /* include the first virtual address of a contiguous range */
    if (level == 1 && !contiguous)
    {

      hash_extend(hash_ctx, &va_start, sizeof(uintptr_t));
//      printf("user VA hashed: 0x%lx\n", va_start);
      contiguous = 1;
    }

    if (level == 1)
    {

      /*
       * This is where we enforce the at-most-one-mapping property.
       * To make our lives easier, we also require a 'linear' mapping
       * (for each of the user and runtime spaces independently).
       *
       * That is: Given V1->P1 and V2->P2:
       *
       * V1 < V2  ==> P1 < P2  (Only for within a given space)
       *
       * V1 != V2 ==> P1 != P2
       *
       * We also validate that all utm vaddrs -> utm paddrs
       */
      int in_runtime = ((phys_addr >= cargs->runtime_paddr) &&
                        (phys_addr < (cargs->user_paddr)));
      int in_user = ((phys_addr >= cargs->user_paddr) &&
                     (phys_addr < (cargs->free_paddr)));

      /* Validate U bit */
      if(in_user && !(pte_val(*walk) & PTE_U)){
        goto fatal_bail;
      }

      /* If the vaddr is in UTM, the paddr must be in UTM */
      if(va_start >= cargs->untrusted_ptr &&
         va_start < (cargs->untrusted_ptr + cargs->untrusted_size) &&
         !map_in_utm){
        goto fatal_bail;
      }

      /* Do linear mapping validation */
      if(in_runtime){
        if(phys_addr <= *runtime_max_seen){
          goto fatal_bail;
        }
        else{
          *runtime_max_seen = phys_addr;
        }
      }
      else if(in_user){
        if(phys_addr <= *user_max_seen){
          goto fatal_bail;
        }
        else{
          *user_max_seen = phys_addr;
        }
      }
      else if(map_in_utm){
        // we checked this above, its OK
      }
      else{
        //printm("BAD GENERIC MAP %x %x %x\n", in_runtime, in_user, map_in_utm);
        goto fatal_bail;
      }

      /* Page is valid, add it to the hash */

      /* if PTE is leaf, extend hash for the page */
      hash_extend_page(hash_ctx, (void*)phys_addr);
//      printf("user PAGE hashed: 0x%lx (pa: 0x%lx)\n", vpn << RISCV_PGSHIFT, phys_addr);
    }
    else
    {
      /* otherwise, recurse on a lower level */
      contiguous = validate_and_hash_epm(hash_ctx,
                                         level - 1,
                                         (pte_t*) phys_addr,
                                         vpn,
                                         contiguous,
                                         cargs,
                                         runtime_max_seen,
                                         user_max_seen,
                                         fd);
      if(contiguous == -1){
        printf("BAD MAP: %lu->%lu epm %u %llu uer %u %llu\n",
               va_start,phys_addr,
                //in_runtime,
               0,
               cargs->runtime_paddr,
               0,
                //in_user,
               cargs->user_paddr);
        goto fatal_bail;
      }
    }
  }

  return contiguous;

  fatal_bail:
  return -1;
}


keystone_status_t Keystone::validate_and_hash_enclave(struct runtime_params_t args,
                                           struct keystone_hash_enclave* cargs){

  hash_ctx_t hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));


  uintptr_t runtime_max_seen=0;
  uintptr_t user_max_seen=0;

  // hash the epm contents including the virtual addresses
  int valid = validate_and_hash_epm(&hash_ctx,
                                    ptlevel,
                                    (pte_t*) root_page_table,
                                    0, 0, cargs, &runtime_max_seen, &user_max_seen, fd);

  if(valid == -1){
    return KEYSTONE_ERROR;
  }

  hash_finalize(hash, &hash_ctx);

  return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::measure(const char *eapppath, const char *runtimepath, Params params)
{
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return KEYSTONE_ERROR;
  }

  runtimeFile = new ELFFile(runtimepath);
  enclaveFile = new ELFFile(eapppath);

  if(!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return KEYSTONE_ERROR;
  }

  if(!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return KEYSTONE_ERROR;
  }


  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return KEYSTONE_ERROR;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return KEYSTONE_ERROR;
  }


  /* Call Keystone Driver */
  struct keystone_ioctl_create_enclave enclp;
  /* Struct for hashing */
  struct keystone_hash_enclave hash_enclave;

  enclp.params.runtime_entry = (unsigned long) runtimeFile->getEntryPoint();
  enclp.params.user_entry = (unsigned long) enclaveFile->getEntryPoint();
  enclp.params.untrusted_ptr = (unsigned long) params.getUntrustedMem();
  enclp.params.untrusted_size = (unsigned long) params.getUntrustedSize();

  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  enclp.min_pages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS)/PAGE_SIZE;
  enclp.min_pages += calculate_required_pages(enclaveFile->getTotalMemorySize(),
                                              runtimeFile->getTotalMemorySize());
  enclp.runtime_vaddr = (unsigned long) runtimeFile->getMinVaddr();
  enclp.user_vaddr = (unsigned long) enclaveFile->getMinVaddr();

  untrusted_size = params.getUntrustedSize();
  untrusted_start = params.getUntrustedMem();

  /* Malloc enclave pages
   *
   * */
  eid = enclp.eid;
  root_page_table =
//  root_page_table = (vaddr_t)allocate_aligned(PAGE_SIZE * enclp.min_pages, PAGE_SIZE);
  start_addr = root_page_table;
  epm_free_list = start_addr + PAGE_SIZE;

  hash_enclave.runtime_paddr = epm_free_list;
  if(loadELF(runtimeFile, true) != KEYSTONE_SUCCESS) {
    ERROR("failed to load runtime ELF");
    destroy();
    return KEYSTONE_ERROR;
  }

  hash_enclave.user_paddr = epm_free_list;
  if(loadELF(enclaveFile, true) != KEYSTONE_SUCCESS) {
    ERROR("failed to load enclave ELF");
    destroy();
    return KEYSTONE_ERROR;
  }


  /* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if( initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0, true) != KEYSTONE_SUCCESS){
    ERROR("failed to init static stack");
    destroy();
    return KEYSTONE_ERROR;
  }
#endif /* USE_FREEMEM */


  utm_free_list = (vaddr_t) allocate_aligned(enclp.params.untrusted_size, PAGE_SIZE);
  hash_enclave.free_paddr = epm_free_list;
  hash_enclave.utm_paddr = utm_free_list;

  /* Don't hash untrusted memory ??
   * Requires intitial state of the physical memory, which the user space doesn't have access to.
   * */

  loadUntrusted(true);

  /* We don't finalize the enclave, no page mapping is done after this step!
   * We also don't have to map it either.
   * */


  hash_enclave.utm_size = params.getUntrustedSize();
  hash_enclave.epm_size = PAGE_SIZE * enclp.min_pages;
  hash_enclave.epm_paddr = root_page_table;
  hash_enclave.untrusted_ptr = enclp.params.untrusted_ptr;
  hash_enclave.untrusted_size = enclp.params.untrusted_size;

  validate_and_hash_enclave(enclp.params, &hash_enclave);
  printHash(hash);



  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;

  return KEYSTONE_SUCCESS;

}

keystone_status_t Keystone::init(const char *eapppath, const char *runtimepath, Params params)
{
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return KEYSTONE_ERROR;
  }

  runtimeFile = new ELFFile(runtimepath);
  enclaveFile = new ELFFile(eapppath);

  if(!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return KEYSTONE_ERROR;
  }

  if(!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return KEYSTONE_ERROR;
  }

  /* open device driver */
  fd = open(KEYSTONE_DEV_PATH, O_RDWR);
  if (fd < 0) {
    PERROR("cannot open device file");
    destroy();
    return KEYSTONE_ERROR;
  }

  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return KEYSTONE_ERROR;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return KEYSTONE_ERROR;
  }

  //Create Memory struct
  Memory mem;

  /* Call Keystone Driver */
  struct keystone_ioctl_create_enclave enclp;

  enclp.params.runtime_entry = (unsigned long) runtimeFile->getEntryPoint();
  enclp.params.user_entry = (unsigned long) enclaveFile->getEntryPoint();
  enclp.params.untrusted_ptr = (unsigned long) params.getUntrustedMem();
  enclp.params.untrusted_size = (unsigned long) params.getUntrustedSize();

  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  enclp.min_pages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS)/PAGE_SIZE;
  enclp.min_pages += calculate_required_pages(enclaveFile->getTotalMemorySize(),
      runtimeFile->getTotalMemorySize());
  enclp.runtime_vaddr = (unsigned long) runtimeFile->getMinVaddr();
  enclp.user_vaddr = (unsigned long) enclaveFile->getMinVaddr();

  untrusted_size = params.getUntrustedSize();
  untrusted_start = params.getUntrustedMem();

  /* Pass in pages to map to enclave here. */

  int ret = ioctl(fd, KEYSTONE_IOC_CREATE_ENCLAVE, &enclp);

  if (ret) {
    ERROR("failed to create enclave - ioctl() failed: %d", ret);
    destroy();
    return KEYSTONE_ERROR;
  }

  mem.init(fd, enclp.pt_ptr);

  eid = enclp.eid;
  start_addr = enclp.pt_ptr;
  //Map root page table to user space
  root_page_table = mem.AllocMem(true, PAGE_SIZE); // (vaddr_t) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  epm_free_list = enclp.pt_ptr + PAGE_SIZE;

  if(loadELF(runtimeFile, false) != KEYSTONE_SUCCESS) {
    ERROR("failed to load runtime ELF");
    destroy();
    return KEYSTONE_ERROR;
  }

  if(loadELF(enclaveFile, false) != KEYSTONE_SUCCESS) {
    ERROR("failed to load enclave ELF");
    destroy();
    return KEYSTONE_ERROR;
  }

  /* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if( initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0) != KEYSTONE_SUCCESS){
    ERROR("failed to init static stack");
    destroy();
    return KEYSTONE_ERROR;
  }
#endif /* USE_FREEMEM */


  enclp.free_paddr = epm_free_list;
  ret = ioctl(fd, KEYSTONE_IOC_UTM_INIT, &enclp);

  if (ret) {
    ERROR("failed to init untrusted memory - ioctl() failed: %d", ret);
    destroy();
    return KEYSTONE_ERROR;
  }

  utm_free_list = enclp.utm_free_ptr;
  loadUntrusted(false);


  ret = ioctl(fd, KEYSTONE_IOC_FINALIZE_ENCLAVE, &enclp);

  if (ret) {
    ERROR("failed to finalize enclave - ioctl() failed: %d", ret);
    destroy();
    return KEYSTONE_ERROR;
  }

  if (mapUntrusted(params.getUntrustedSize()))
  {
    ERROR("failed to finalize enclave - cannot obtain the untrusted buffer pointer \n");
    destroy();
    return KEYSTONE_ERROR;
  }

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;

  return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::mapUntrusted(size_t size)
{
  if (size == 0) {
    return KEYSTONE_SUCCESS;
  }

  shared_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (shared_buffer == NULL) {
    return KEYSTONE_ERROR;
  }

  shared_buffer_size = size;

  return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::destroy()
{
  /* if the enclave has ever created, we destroy it. */
  if(eid >= 0)
  {
    struct keystone_ioctl_create_enclave enclp;
    enclp.eid = eid;
    int ret = ioctl(fd, KEYSTONE_IOC_DESTROY_ENCLAVE, &enclp);

    if (ret) {
      ERROR("failed to destroy enclave - ioctl() failed: %d", ret);
      return KEYSTONE_ERROR;
    }
  }

  if(enclaveFile) {
    delete enclaveFile;
    enclaveFile = NULL;
  }

  if(runtimeFile) {
    delete runtimeFile;
    runtimeFile = NULL;
  }

  return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::run()
{
  int ret;
  struct keystone_ioctl_run_enclave run;
  run.eid = eid;

  ret = ioctl(fd, KEYSTONE_IOC_RUN_ENCLAVE, &run);
  while (ret == KEYSTONE_ENCLAVE_EDGE_CALL_HOST) {
    /* enclave is stopped in the middle. */
    if (oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run);
  }

  if (ret) {
    ERROR("failed to run enclave - ioctl() failed: %d", ret);
    destroy();
    return KEYSTONE_ERROR;
  }

  return KEYSTONE_SUCCESS;
}

void *Keystone::getSharedBuffer() {
  return shared_buffer;
}

size_t Keystone::getSharedBufferSize() {
  return shared_buffer_size;
}

keystone_status_t Keystone::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return KEYSTONE_SUCCESS;
}
