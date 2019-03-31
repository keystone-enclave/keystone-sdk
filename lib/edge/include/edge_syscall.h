#ifndef __EDGE_SYSCALL_H_
#define __EDGE_SYSCALL_H_

#include "edge_common.h"
#include "syscall_nums.h"
#include "edge_call.h"

#ifdef __cplusplus
extern "C" {
#endif


// Special call number
#define EDGECALL_SYSCALL MAX_EDGE_CALL+1

typedef struct edge_syscall_t{
  size_t syscall_num;
  unsigned char data[];
} edge_syscall_t;

typedef struct sargs_SYS_openat{
  int dirfd;
  int flags;
  int mode;
  char path[];
} sargs_SYS_openat;

typedef struct sargs_SYS_write{
  int fd;
  size_t len;
  unsigned char buf[];
} sargs_SYS_write;

  // Read uses the same args as write
typedef sargs_SYS_write sargs_SYS_read;

void incoming_syscall(edge_call_t* buffer);

#ifdef __cplusplus
}
#endif

#endif /* __EDGE_SYSCALL_H_ */
