//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

extern "C" {
#include "common/sha256.h"
}

void
hash_init(hash_ctx_t* hash_ctx);
void
hash_extend(hash_ctx_t* hash_ctx, const BYTE* ptr, size_t len);
void
hash_extend_page(hash_ctx_t* hash_ctx, const BYTE* ptr);
void
hash_finalize(BYTE* md, hash_ctx_t* hash_ctx);
