//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#define IO_SYSCALL_WRAPPING
#include "edge/edge_call.h"
#include "host/keystone.h"
#include "sys/wait.h"

#define OCALL_WAIT_FOR_MESSAGE 1

using namespace Keystone;

Enclave *pEnclave;

typedef struct encl_message_t {
  void* host_ptr;
  size_t len;
} encl_message_t;

encl_message_t wait_for_message(){
  size_t len;
  char *query;

  switch(pEnclave->query_num) {
    case 0: 
      query = "SELECT * FROM employees LIMIT 1";
      // query = "DELETE FROM employees WHERE LastName = 'Adams'";
      break;
    case 1: 
      query = "SELECT * FROM employees LIMIT 5";
      break;
    case 2: 
      query = "UPDATE employees SET LastName = 'TestingTesting' WHERE FirstName = 'Margaret'";
      break;
    default: 
      query = "-1";
  }

  len = strlen(query)+1;

  /* This happens here */
  encl_message_t message;
  message.host_ptr = query;
  message.len = len;
  return message;
}

void wait_for_message_wrapper(void* buffer)
{

  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  encl_message_t host_msg = wait_for_message();

  // This handles wrapping the data into an edge_data_t and storing it
  // in the shared region.
  if( edge_call_setup_wrapped_ret(edge_call, host_msg.host_ptr, host_msg.len)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}

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
  register_call(OCALL_WAIT_FOR_MESSAGE, wait_for_message_wrapper);

  pEnclave = &enclave;
  edge_call_init_internals(
      getSharedBuffer, getSharedBufferSize);

  uintptr_t encl_ret;
  Error ret = enclave.run(&encl_ret);  // enclave creates snapshot at some point 
  if (ret != Error::EnclaveSnapshot) {
    printf("Enclave failed to create snapshot\n");
    printf("Error: %d\n", ret);
    return 1;
  }

  for (int i = 0; i < 1; i++) {
      pEnclave->query_num = i;
      int pid = fork(); 
      if (pid == 0) {
          Enclave cloned_enclave = *enclave.clone(1024*1024); 
          cloned_enclave.resume(); 
      } else {
        wait(NULL);
      }
  }

  return 0;
}
