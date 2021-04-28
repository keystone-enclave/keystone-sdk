//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#define IO_SYSCALL_WRAPPING
#include "edge/edge_call.h"
#include "host/keystone.h"

using namespace Keystone;

Enclave * pEnclave;

uintptr_t getSharedBuffer()
{
  return (uintptr_t) pEnclave->getSharedBuffer();
}

size_t getSharedBufferSize()
{
  return pEnclave->getSharedBufferSize();
}


int
main(int argc, char** argv) {
  Enclave enclave;
  Params params;

  params.setFreeMemSize(450*1024*1024);
  params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 2 * 1024 * 1024);

  enclave.init(argv[1], argv[2], params);

  enclave.registerOcallDispatch(incoming_call_dispatch);

  pEnclave = &enclave;
  edge_call_init_internals(
      getSharedBuffer, getSharedBufferSize);

  uintptr_t encl_ret;
  enclave.run(&encl_ret);

  return 0;
}
