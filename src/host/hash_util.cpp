//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
extern "C" {
#include "common/sha256.h"
}
#include "Memory.hpp"
#include "hash_util.hpp"

void
hash_init(hash_ctx_t* hash_ctx) {
  sha256_init(hash_ctx);
}

void
hash_extend(hash_ctx_t* hash_ctx, const BYTE* ptr, size_t len) {
  sha256_update(hash_ctx, ptr, len);
}

void
hash_extend_page(hash_ctx_t* hash_ctx, const BYTE* ptr) {
  sha256_update(hash_ctx, ptr, RISCV_PGSIZE);
}

void
hash_finalize(BYTE* md, hash_ctx_t* hash_ctx) {
  sha256_final(hash_ctx, md);
}
