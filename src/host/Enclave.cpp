//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "hash_util.hpp"

namespace Keystone {

Enclave::Enclave() {
  runtimeFile = NULL;
  enclaveFile = NULL;
}

Enclave::~Enclave() {
  if (runtimeFile) delete runtimeFile;
  if (enclaveFile) delete enclaveFile;
  destroy();
}

static size_t
fstatFileSize(int filep) {
  int rc;
  struct stat stat_buf;
  rc = fstat(filep, &stat_buf);
  return (rc == 0 ? stat_buf.st_size : 0);
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

// Error
// Enclave::loadUntrusted() {
//   uintptr_t va_start = ROUND_DOWN(params.getUntrustedMem(), PAGE_BITS);
//   uintptr_t va_end   = ROUND_UP(params.getUntrustedEnd(), PAGE_BITS);
//   static char nullpage[PAGE_SIZE] = {
//       0,
//   };
// 
//   while (va_start < va_end) {
//     if (!pMemory->allocPage(va_start, (uintptr_t)nullpage, UTM_FULL)) {
//       return Error::PageAllocationFailure;
//     }
//     va_start += PAGE_SIZE;
//   }
//   return Error::Success;
// }
// 
// /* This function will be deprecated when we implement freemem */
// bool
// Enclave::initStack(uintptr_t start, size_t size, bool is_rt) {
//   static char nullpage[PAGE_SIZE] = {
//       0,
//   };
//   uintptr_t high_addr    = ROUND_UP(start, PAGE_BITS);
//   uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
//   int stk_pages          = (high_addr - va_start_stk) / PAGE_SIZE;
// 
//   for (int i = 0; i < stk_pages; i++) {
//     if (!pMemory->allocPage(
//             va_start_stk, (uintptr_t)nullpage,
//             (is_rt ? RT_NOEXEC : USER_NOEXEC)))
//       return false;
// 
//     va_start_stk += PAGE_SIZE;
//   }
// 
//   return true;
// }

uintptr_t
Enclave::copyFile(uintptr_t filePtr, size_t fileSize) {
	uintptr_t startOffset = pMemory->getCurrentOffset(); 
  size_t bytesRemaining = fileSize; 
	
	uintptr_t currOffset;
	while (bytesRemaining > 0) {
		currOffset = pMemory->getCurrentOffset(); 
    pMemory->incrementEPMFreeList();

		size_t bytesToWrite = (bytesRemaining > PAGE_SIZE) ? PAGE_SIZE : bytesRemaining;
		size_t bytesWritten = fileSize - bytesRemaining;

    if (bytesToWrite < PAGE_SIZE) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) filePtr + bytesWritten, (size_t)(bytesToWrite));
      pMemory->writeMem(filePtr + bytesWritten, currOffset, bytesToWrite);
    } else {
		  pMemory->writeMem(filePtr + bytesWritten, currOffset, bytesToWrite);
    }
		bytesRemaining -= bytesToWrite;
	}
	return startOffset;
}

void 
Enclave::allocUninitialized(ElfFile* elfFile) {
	size_t memSize = elfFile->getTotalMemorySize(); 
	size_t fileSize = elfFile->getTotalMemorySize();

	if (memSize > fileSize) {
		size_t remaining_space = PAGE_SIZE - fileSize % PAGE_SIZE; 
    size_t overflow = memSize - fileSize - remaining_space; 

    uintptr_t currentOffset = pMemory->getCurrentOffset();
    pMemory->allocPages(overflow); 
    char nullPages[overflow] = {0}; 
    pMemory->writeMem((uintptr_t) nullPages, currentOffset, overflow);
	}
}

Error
Enclave::validate_and_hash_enclave(struct runtime_params_t args) {
  return Error::Success;
}

bool
Enclave::initFiles(const char* eapppath, const char* runtimepath) {
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  runtimeFile = new ElfFile(runtimepath);
  enclaveFile = new ElfFile(eapppath);

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
Enclave::prepareEnclave(uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  minPages += calculate_required_pages(
      enclaveFile->getFileSize(), runtimeFile->getFileSize());

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages) != Error::Success) {
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

Error
Enclave::init(const char* eapppath, const char* runtimepath, Params _params) {
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

const char*
Enclave::getHash() {
  return this->hash;
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, Params _params,
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
    return Error::FileInitFailure;
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  if (!prepareEnclave(alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }

 	uintptr_t utm_free;
  utm_free = pMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }
	
	/* Copy loader into beginning of enclave memory */
	int loaderfp = open("toy.bin", O_RDONLY); 
	size_t loaderSize = fstatFileSize(loaderfp); 
	uintptr_t loaderPtr = (uintptr_t) mmap(NULL, loaderSize, PROT_READ, MAP_PRIVATE, loaderfp, 0); 
	copyFile(loaderPtr, loaderSize);

	pMemory->startRuntimeMem();
  runtimeElfAddr = copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());
	allocUninitialized(runtimeFile);	
  
	pMemory->startEappMem();
	enclaveElfAddr = copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());
  allocUninitialized(enclaveFile);

	pMemory->startFreeMem();	

/* This should be replaced with functions that perform the same function 
 * but with new implementation of memory */
//  /* TODO: This should be invoked with some other function e.g., measure() */
//  if (params.isSimulated()) {
//    validate_and_hash_enclave(runtimeParams);
//  }
//
  struct runtime_params_t runtimeParams;
  runtimeParams.untrusted_ptr =
      reinterpret_cast<uintptr_t>(utm_free);
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
//  if (!mapUntrusted(params.getUntrustedSize())) {
//    ERROR(
//        "failed to finalize enclave - cannot obtain the untrusted buffer "
//        "pointer \n");
//    destroy();
//    return Error::DeviceMemoryMapError;
//  }
//  //}

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;
  return Error::Success;
}

bool
Enclave::mapUntrusted(size_t size) {
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

Error
Enclave::destroy() {
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

Error
Enclave::run(uintptr_t* retval) {
  if (params.isSimulated()) {
    return Error::Success;
  }

  Error ret = pDevice->run(retval);
  while (ret == Error::EdgeCallHost || ret == Error::EnclaveInterrupted) {
    /* enclave is stopped in the middle. */
    if (ret == Error::EdgeCallHost && oFuncDispatch != NULL) {
      oFuncDispatch(getSharedBuffer());
    }
    ret = pDevice->resume(retval);
  }

  if (ret != Error::Success) {
    ERROR("failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

Memory*
Enclave::getMemory() {
  return pMemory;
}

Error
Enclave::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return Error::Success;
}

}  // namespace Keystone
