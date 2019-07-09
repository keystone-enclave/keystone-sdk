//
// Created by Alex Thomas on 7/7/19.
//

void hash_init(hash_ctx_t* hash_ctx)
{
  sha3_init(hash_ctx, MDSIZE);
}

void hash_extend(hash_ctx_t* hash_ctx, const void* ptr, size_t len)
{
  sha3_update(hash_ctx, ptr, len);
}

void hash_extend_page(hash_ctx_t* hash_ctx, const void* ptr)
{
  sha3_update(hash_ctx, ptr, RISCV_PGSIZE);
}

void hash_finalize(void* md, hash_ctx_t* hash_ctx)
{
  sha3_final(md, hash_ctx);
}

void printHash(char *hash){
  for(int i = 0; i < MDSIZE; i+=sizeof(uintptr_t))
  {
    printf("%.16lx ", *((uintptr_t*) ((uintptr_t)hash + i)));
  }
  printf("\n");
}