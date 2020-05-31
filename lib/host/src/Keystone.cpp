//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Keystone.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "./hash_util.h"
#include "./keystone_user.h"
#include "ELFFile.hpp"

Keystone::Keystone() {
  runtimeFile = NULL;
  enclaveFile = NULL;
}

Keystone::~Keystone() {
  if (runtimeFile) delete runtimeFile;
  if (enclaveFile) delete enclaveFile;
  destroy();
}

uint64_t
calculate_required_pages(uint64_t eapp_sz, uint64_t rt_sz) {
  uint64_t req_pages = 0;

  req_pages += ceil(eapp_sz / PAGE_SIZE);
  req_pages += ceil(rt_sz / PAGE_SIZE);

  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  req_pages += 15;
  return req_pages;
}

KeystoneError
Keystone::loadUntrusted() {
  vaddr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
  vaddr_t va_end = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);
  static char nullpage[PAGE_SIZE] = {
      0,
  };

  while (va_start < va_end) {
    if (!pMemory->allocPage(va_start, (vaddr_t)nullpage, UTM_FULL)) {
      return KeystoneError::PageAllocationFailure;
    }
    va_start += PAGE_SIZE;
  }
  return KeystoneError::Success;
}

/* This function will be deprecated when we implement freemem */
bool
Keystone::initStack(vaddr_t start, size_t size, bool is_rt) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };
  vaddr_t high_addr = ROUND_UP(start, PAGE_BITS);
  vaddr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!pMemory->allocPage(
            va_start_stk, (vaddr_t)nullpage, (is_rt ? RT_NOEXEC : USER_NOEXEC)))
      return false;

    va_start_stk += PAGE_SIZE;
  }

  return true;
}

KeystoneError
Keystone::loadELF(ELFFile *elf, uintptr_t *data_start) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };
  unsigned int mode = elf->getPageMode();
  vaddr_t va;

  size_t num_pages =
      ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  va = elf->getMinVaddr();

  if (pMemory->epm_alloc_vspace(va, num_pages) != num_pages) {
    ERROR("failed to allocate vspace\n");
    return KeystoneError::VSpaceAllocationFailure;
  }
  *data_start = pMemory->getCurrentEPMAddress();
  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    vaddr_t start = elf->getProgramHeaderVaddr(i);
    vaddr_t file_end = start + elf->getProgramHeaderFileSize(i);
    vaddr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char *src = reinterpret_cast<char *>(elf->getProgramSegment(i));
    va = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void *)src, length);
      if (!pMemory->allocPage(PAGE_DOWN(va), (vaddr_t)page, mode))
        return KeystoneError::PageAllocationFailure;
      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (!pMemory->allocPage(va, (vaddr_t)src, mode))
        return KeystoneError::PageAllocationFailure;

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void *)src, (size_t)(file_end - va));
      if (!pMemory->allocPage(va, (vaddr_t)page, mode))
        return KeystoneError::PageAllocationFailure;
      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      if (!pMemory->allocPage(va, (vaddr_t)nullpage, mode))
        return KeystoneError::PageAllocationFailure;
      va += PAGE_SIZE;
    }
  }

  return KeystoneError::Success;
}

KeystoneError
Keystone::validate_and_hash_enclave(
    struct runtime_params_t args, struct keystone_hash_enclave *cargs) {
  hash_ctx_t hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));

  uintptr_t runtime_max_seen = 0;
  uintptr_t user_max_seen = 0;

  // hash the epm contents including the virtual addresses
  int valid = validate_and_hash_epm(
      &hash_ctx, ptlevel,
      reinterpret_cast<pte_t *>(pMemory->getRootPageTable()), 0, 0, cargs,
      &runtime_max_seen, &user_max_seen);

  if (valid == -1) {
    return KeystoneError::InvalidEnclave;
  }

  hash_finalize(hash, &hash_ctx);

  return KeystoneError::Success;
}

bool
Keystone::initFiles(const char *eapppath, const char *runtimepath) {
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  runtimeFile = new ELFFile(runtimepath);
  enclaveFile = new ELFFile(eapppath);

  if (!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return false;
  }

  if (!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return false;
  }

  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return false;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return false;
  }

  return true;
}

bool
Keystone::prepareEnclave(uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  minPages += calculate_required_pages(
      enclaveFile->getTotalMemorySize(), runtimeFile->getTotalMemorySize());

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Keystone Driver */
  if (pDevice->create(minPages) != KeystoneError::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

KeystoneError
Keystone::init(const char *eapppath, const char *runtimepath, Params _params) {
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

const char *
Keystone::getHash() {
  return this->hash;
}

KeystoneError
Keystone::init(
    const char *eapppath, const char *runtimepath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
  } else {
    pMemory = new PhysicalEnclaveMemory();
    pDevice = new KeystoneDevice();
  }

  if (!initFiles(eapppath, runtimepath)) {
    return KeystoneError::FileInitFailure;
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return KeystoneError::DeviceInitFailure;
  }

  if (!prepareEnclave(alternatePhysAddr)) {
    destroy();
    return KeystoneError::DeviceError;
  }

  // Map root page table to user space
  struct keystone_hash_enclave hash_enclave;

  uintptr_t data_start;
  uintptr_t runtimePhysAddr;
  uintptr_t eappPhysAddr;

  hash_enclave.runtime_paddr = pMemory->getCurrentEPMAddress();
  if (loadELF(runtimeFile, &data_start) != KeystoneError::Success) {
    ERROR("failed to load runtime ELF");
    destroy();
    return KeystoneError::ELFLoadFailure;
  }
  runtimePhysAddr =
      (data_start - pMemory->getStartAddr()) + pDevice->getPhysAddr();

  hash_enclave.user_paddr = pMemory->getCurrentEPMAddress();
  if (loadELF(enclaveFile, &data_start) != KeystoneError::Success) {
    ERROR("failed to load enclave ELF");
    destroy();
    return KeystoneError::ELFLoadFailure;
  }
  eappPhysAddr =
      (data_start - pMemory->getStartAddr()) + pDevice->getPhysAddr();

/* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if (!initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0)) {
    ERROR("failed to init static stack");
    destroy();
    return KeystoneError::PageAllocationFailure;
  }
#endif /* USE_FREEMEM */
  if (params.isSimulated()) {
    vaddr_t utm_free;
    utm_free = pMemory->allocUTM(params.getUntrustedSize());
    hash_enclave.free_paddr = pMemory->getCurrentEPMAddress();
    hash_enclave.utm_paddr = utm_free;
  } else {
    vaddr_t utm_free;
    utm_free = pMemory->allocUTM(params.getUntrustedSize());
    if (!utm_free) {
      ERROR("failed to init untrusted memory - ioctl() failed");
      destroy();
      return KeystoneError::DeviceError;
    }
  }

  if (loadUntrusted() != KeystoneError::Success) {
    ERROR("failed to load untrusted");
  }
  // if(params.isSimulated()) {
  // hash_enclave.utm_size = params.getUntrustedSize();
  // hash_enclave.epm_size = PAGE_SIZE * enclp.min_pages;
  // hash_enclave.epm_paddr = pMemory->getRootPageTable();
  // hash_enclave.untrusted_ptr = enclp.params.untrusted_ptr;
  // hash_enclave.untrusted_size = enclp.params.untrusted_size;

  // validate_and_hash_enclave(enclp.params, &hash_enclave);
  //} else {
  struct runtime_params_t runtimeParams;
  runtimeParams.runtime_entry =
      reinterpret_cast<uintptr_t>(runtimeFile->getEntryPoint());
  runtimeParams.user_entry =
      reinterpret_cast<uintptr_t>(enclaveFile->getEntryPoint());
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(params.getUntrustedMem());
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

  uintptr_t freePhysAddr = pMemory->getCurrentEPMAddress() -
                           pMemory->getStartAddr() + pDevice->getPhysAddr();
  if (pDevice->finalize(
          runtimePhysAddr, eappPhysAddr, freePhysAddr, runtimeParams) !=
      KeystoneError::Success) {
    destroy();
    return KeystoneError::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return KeystoneError::DeviceMemoryMapError;
  }
  //}

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;
  return KeystoneError::Success;
}

bool
Keystone::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  shared_buffer_size = size;

  return true;
}

KeystoneError
Keystone::destroy() {
  if (enclaveFile) {
    delete enclaveFile;
    enclaveFile = NULL;
  }

  if (runtimeFile) {
    delete runtimeFile;
    runtimeFile = NULL;
  }

  return pDevice->destroy();
}

KeystoneError
Keystone::run() {
  if (params.isSimulated()) {
    return KeystoneError::Success;
  }

  KeystoneError ret = pDevice->run();
  while (ret == KeystoneError::EdgeCallHost ||
         ret == KeystoneError::EnclaveInterrupted) {
    /* enclave is stopped in the middle. */
    if (ret == KeystoneError::EdgeCallHost && oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = pDevice->resume();
  }

  if (ret != KeystoneError::Success) {
    ERROR("failed to run enclave - ioctl() failed: %d", ret);
    destroy();
    return KeystoneError::DeviceError;
  }

  return KeystoneError::Success;
}

void *
Keystone::getSharedBuffer() {
  return shared_buffer;
}

size_t
Keystone::getSharedBufferSize() {
  return shared_buffer_size;
}

KeystoneError
Keystone::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return KeystoneError::Success;
}
