//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

/* this implementes basic system calls for the enclave */

int ocall(unsigned long call_id,
	  void* data, size_t data_len,
	  void* return_buffer, size_t return_len){
  return SYSCALL_5(SYSCALL_OCALL, call_id, data, data_len, return_buffer, return_len);
}

int copy_from_shared(void* dst,
		     uintptr_t offset, size_t data_len){
  return SYSCALL_3(SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

int attest_enclave(void* report, void* data, size_t size)
{
  return SYSCALL_3(SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

int send_msg(size_t uid, void *buf, size_t msg_size){
  return SYSCALL_3(RUNTIME_SYSCALL_SEND, uid, buf, msg_size);
}

int recv_msg(size_t uid, void *buf, size_t buf_size){
  return SYSCALL_3(RUNTIME_SYSCALL_RCV, uid, buf, buf_size);
}

int get_uid(){
  return SYSCALL_0(RUNTIME_SYSCALL_UID);
}
