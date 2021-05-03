#include <stdio.h>
#include <stdlib.h>
#include "syscall.h"
#include "eapp_utils.h"
#define BUF_SIZE (47 * 1024 * 1024)

#define TEST_IDX 47*1024*30

/* This is the baseline fork for the paper */
#define SYSCALL_FORK 1007

int
sbi_enclave_fork() {
  return SYSCALL_0(SYSCALL_FORK);
}

int main()
{
  int size = 400;
  unsigned long cycle_start = 0, cycle_end = 0;
  char *buf = (char *) malloc(size * 1024 * 1024);
  if(!buf){
    printf("malloc failed to allocate: %lu bytes!\n", sizeof(char) * BUF_SIZE);
    return 0;
  }

  //buf[TEST_IDX] = 50;
  int ret = 0;
  printf("%d,",size);
  asm volatile("rdcycle %0" : "=r"(cycle_start));
  int child_eid = sbi_enclave_fork();
  if(child_eid){
    //ret = buf[TEST_IDX];
    ret = 1;
    //ret += 13093;
  } else {
    asm volatile("rdcycle %0" : "=r"(cycle_end));
    ret = (cycle_end - cycle_start)/1000;
    //Child should return 1038 + 50
    //ret = buf[TEST_IDX];
    //ret += 1038;
  }
  //printf("buf: %p\n", buf);
  //printf("buf[1032]: %d, ret: %d\n", buf[TEST_IDX], ret);
  return ret;
}
