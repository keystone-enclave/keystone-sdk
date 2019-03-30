#include "edge_syscall.h"
#include <fcntl.h>
#include <unistd.h>
// Special edge-call handler for syscall proxying
void incoming_syscall(edge_call_t* edge_call){



  edge_syscall_t* syscall_info;

  if( edge_call_args_ptr(edge_call, (uintptr_t*)&syscall_info) != 0)
    goto syscall_error;

  // Right now we only handle some io syscalls. See runtime for how
  // others are handled.
  switch(syscall_info->syscall_num){

  case(SYS_openat):;
    struct sargs_SYS_openat* openat_args = (struct sargs_SYS_openat*)syscall_info->data;
    int fd = openat(openat_args->dirfd, openat_args->path,
                    openat_args->flags, openat_args->mode);
    if( edge_call_setup_wrapped_ret(edge_call, &fd, sizeof(int)) !=0) goto syscall_error;
    break;
  case(SYS_write):;
    struct sargs_SYS_write* write_args = (struct sargs_SYS_write*)syscall_info->data;
    size_t ret = write(write_args->fd, write_args->buf, write_args->len);
    if(edge_call_setup_wrapped_ret(edge_call, &ret, sizeof(size_t)) != 0) goto syscall_error;
    break;
  default:
    goto syscall_error;

  }

  return;

 syscall_error:
  edge_call->return_data.call_status = CALL_STATUS_SYSCALL_FAILED;
  return;
}
