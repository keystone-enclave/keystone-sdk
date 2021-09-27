//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#define IO_SYSCALL_WRAPPING
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "sys/wait.h"

using namespace Keystone;

int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  params.setFreeMemSize(64 * 1024 * 1024); // 50 MB
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 2 * 1024 * 1024);

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  edge_call_init_internals(
      (uintptr_t)enclave.getSharedBuffer(),(size_t)enclave.getSharedBufferSize());

  uintptr_t encl_ret;
  Error ret = enclave.run(&encl_ret);

  if (ret != Error::EnclaveSnapshot) {
    printf("Enclave failed to create snapshot\n");
    printf("Error: %d\n", ret);
    return 1;
  }

  int i;
  for (i=0; i<10; i++)
  {
      printf("%d\n",i);
      Enclave* cloned = enclave.clone(800, 1);
      cloned->registerOcallDispatch(incoming_call_dispatch);
      edge_call_init_internals(
        (uintptr_t)cloned->getSharedBuffer(),(size_t)cloned->getSharedBufferSize());
      printf("resuming\n");
      cloned->resume();
      printf("destroying\n");
      cloned->destroy();
  }

  return 0;
}
