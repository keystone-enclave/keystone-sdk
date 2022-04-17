#include "common/sha256.h"
#include "ed25519/ed25519.h"
#include "ed25519/ge.h"

void
ed25519_create_keypair(
    unsigned char* public_key, unsigned char* private_key,
    const unsigned char* seed) {
  ge_p3 A;

  hash_ctx_t sha256;

  sha256_init(&sha256);
  sha256_update(&sha256, seed, 64);
  sha256_final(&sha256, private_key);

  private_key[0] &= 248;
  private_key[31] &= 63;
  private_key[31] |= 64;

  ge_scalarmult_base(&A, private_key);
  ge_p3_tobytes(public_key, &A);
}
