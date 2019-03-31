#include "edge_syscall.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
// Special edge-call handler for syscall proxying
void incoming_syscall(edge_call_t* edge_call){



  edge_syscall_t* syscall_info;

  if( edge_call_args_ptr(edge_call, (uintptr_t*)&syscall_info) != 0)
    goto syscall_error;

  edge_call->return_data.call_status = CALL_STATUS_OK;

  int64_t ret;

  // Right now we only handle some io syscalls. See runtime for how
  // others are handled.
  switch(syscall_info->syscall_num){

  case(SYS_openat):;
    sargs_SYS_openat* openat_args = (sargs_SYS_openat*)syscall_info->data;
    ret = openat(openat_args->dirfd, openat_args->path,
                 openat_args->flags, openat_args->mode);
    break;

  case(SYS_write):;
    sargs_SYS_write* write_args = (sargs_SYS_write*)syscall_info->data;
    ret = write(write_args->fd, write_args->buf, write_args->len);
    break;
  case(SYS_read):;
    sargs_SYS_read* read_args = (sargs_SYS_read*)syscall_info->data;
    ret = read(read_args->fd, read_args->buf, read_args->len);
    break;
  default:
    goto syscall_error;
  }

  /* Setup return value */
  void* ret_data_ptr = (void*)edge_call_data_ptr();
  *(int64_t*)ret_data_ptr = ret;
  if(edge_call_setup_ret(edge_call, ret_data_ptr , sizeof(int64_t)) !=0) goto syscall_error;

  return;

 syscall_error:
  edge_call->return_data.call_status = CALL_STATUS_SYSCALL_FAILED;
  return;
}
