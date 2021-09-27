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

  params.setFreeMemSize(2*1024*1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 2 * 1024 * 1024);

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  edge_call_init_internals(
      (uintptr_t) enclave.getSharedBuffer(), (size_t) enclave.getSharedBufferSize());

  uintptr_t encl_ret;
  Error ret = enclave.run(&encl_ret); // enclave creates snapshot at some point

  if (ret != Error::EnclaveSnapshot) {
    printf("Enclave failed to create snapshot\n");
    printf("Error: %d\n", ret);
    return 1;
  }

  int pid = fork();
  if (pid == 0) {
    printf("Host Child\n");
    Enclave cloned_enclave = *enclave.clone(200, pid);
    printf("Resuming 1\n");
    cloned_enclave.resume();
    printf("Child Done\n");
  } else {
    printf("Host Parent 0\n");
    Enclave cloned_enclave = *enclave.clone(200, pid);
    printf("Resuming 2\n");
    cloned_enclave.resume();
    wait(NULL);
    printf("Parent Done\n");
  }

  printf("Host is returning\n");
  return 0;
}
