#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#define SYSCALL_SNAPSHOT 1005

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0)
#define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0)
#define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0)
#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)
#define SYSCALL_4(which, arg0, arg1, arg2, arg3) \
  SYSCALL(which, arg0, arg1, arg2, arg3, 0)
#define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) \
  SYSCALL(which, arg0, arg1, arg2, arg3, arg4)

int sbi_enclave_snapshot() {
  return SYSCALL_0(SYSCALL_SNAPSHOT);
}

int main()
{
  int size = 16;
  char * buf = (char*) malloc(1024*1024*size);
  unsigned long cycle_start, cycle_end;

  //*buf = 0x10;
  asm volatile("rdcycle %0" : "=r"(cycle_start));
  sbi_enclave_snapshot();
  asm volatile("rdcycle %0" : "=r"(cycle_end));

  //*buf = 0x2e;
  printf("%d, %ld\n", size, cycle_end - cycle_start);
  return 0;
}
