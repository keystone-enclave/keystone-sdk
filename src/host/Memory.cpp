//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Memory.hpp"
#include <keystone_user.h>
#include <sys/stat.h>

namespace Keystone {

Memory::Memory() {
  epmFreeList   = 0;
  utmFreeList   = 0;
  startAddr     = 0;
}

void
Memory::startRuntimeMem() {
  runtimePhysAddr = getCurrentEPMAddress();
}

void
Memory::startEappMem() {
  eappPhysAddr = getCurrentEPMAddress();
}

void
Memory::startFreeMem() {
  freePhysAddr = getCurrentEPMAddress();
}



/* This will walk the entire vaddr space in the enclave, validating
   linear at-most-once paddr mappings, and then hashing valid pages */
int
Memory::validateAndHashEpm(
    hash_ctx_t* hash_ctx, int level, pte* tb, uintptr_t vaddr, int contiguous,
    uintptr_t* runtime_max_seen, uintptr_t* user_max_seen) {
	return 0;
}

}  // namespace Keystone
