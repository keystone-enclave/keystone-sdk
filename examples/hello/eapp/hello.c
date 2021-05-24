#include <stdio.h>
#include <stdlib.h>
#include "syscall.h"
#include "eapp_utils.h"
// #define BUF_SIZE (47 * 1024 * 1024)
#define BUF_SIZE (1024 * 1024)

#define TEST_IDX 1024 * 1023

/* This is the baseline fork for the paper */
#define SYSCALL_FORK 1007

int
sbi_enclave_fork() {
  return SYSCALL_0(SYSCALL_FORK);
}

int main()
{
  char *buf = (char *) malloc(sizeof(char) * BUF_SIZE);
  if(!buf){
    printf("malloc failed to allocate: %lu bytes!\n", sizeof(char) * BUF_SIZE);
  }

  buf[TEST_IDX] = 50; 
  int ret = 0;
  int child_eid = sbi_enclave_fork(); 
  if(child_eid){
    ret = buf[TEST_IDX];
    ret += 13093;
  } else {
    //Child should return 1038 + 50
    ret = buf[TEST_IDX];
    ret += 1038;
  }
  printf("buf: %p\n", buf);
  printf("buf[1032]: %d, ret: %d\n", buf[TEST_IDX], ret);
  return ret;
}
