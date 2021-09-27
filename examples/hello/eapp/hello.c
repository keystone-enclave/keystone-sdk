#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

int main()
{
  int size = 16;
  char * buf = (char*) malloc(1024*1024*size);
  unsigned long cycle_start, cycle_end;

  //*buf = 0x10;
  int pid = fork();

  if (pid) {
    printf("parent\n");
    return 0;
  } else {
    printf("child\n");
    return 0;
  }
  //asm volatile("rdcycle %0" : "=r"(cycle_end));
  //*buf = 0x2e;
  // printf("%d, %ld\n", size, cycle_end - cycle_start);
  return 0;
}
