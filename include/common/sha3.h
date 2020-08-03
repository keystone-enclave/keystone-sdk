// sha3.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

#define MDSIZE 64

// state context
typedef struct {
  union {            // state:
    uint8_t b[200];  // 8-bit bytes
    uint64_t q[25];  // 64-bit words
  } st;
  int pt, rsiz, mdlen;  // these don't overflow
} sha3_ctx_t;

// Compression function.
void
sha3_keccakf(uint64_t st[25]);

// OpenSSL - like interfece
int
sha3_init(sha3_ctx_t* c, int mdlen);  // mdlen = hash output in bytes
int
sha3_update(sha3_ctx_t* c, const void* data, size_t len);
int
sha3_final(void* md, sha3_ctx_t* c);  // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
void*
sha3(const void* in, size_t inlen, void* md, int mdlen);
