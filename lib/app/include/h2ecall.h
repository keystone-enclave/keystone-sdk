#include "syscall.h"

// This is based on the assumption that MAX_EDGE_CALL in edge definition is 10.
#define MAX_EDGE_CALL 10
#define OCALL_HANGUP (MAX_EDGE_CALL + 2)

int hangup();
void receive_calls(int (*dispatch_func)(void*, void**)); 

extern int (*h2ecall_list[MAX_EDGE_CALL])(void*, void**);
int h2ecall_dispatch(void* malloc_pointer, void** return_pointer);

