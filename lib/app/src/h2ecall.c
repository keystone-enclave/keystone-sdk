#include "h2ecall.h"
#include "malloc.h"

int hangup() {
	return SYSCALL_1(SYSCALL_OCALL, OCALL_HANGUP);
}

void receive_calls(int (*dispatch_func)(void*, void**)) {
	int malloc_size, return_size = 0;
	void* return_pointer = 0;
	do {
		SYSCALL_3(SYSCALL_OCALL, OCALL_HANGUP, return_pointer, return_size);
		if (return_pointer && return_size) free(return_pointer);
		copy_from_shared(&malloc_size, 0, 4);
		if (malloc_size) {
			void* malloc_pointer = malloc(malloc_size);
			if (malloc_pointer) {
				copy_from_shared(malloc_pointer, 4, malloc_size);
				return_size = (*dispatch_func)(malloc_pointer, &return_pointer);
				free(malloc_pointer);
			}
		}
	} while (malloc_size);
}

// The first parameter takes the address of the input, the second should be pointed to
// the address of the return data and the function should return the size of the return
// data.

int (*h2ecall_list[MAX_EDGE_CALL])(void*, void**);
int h2ecall_dispatch(void* malloc_pointer, void** return_pointer) {
	int call_index = *(int*) malloc_pointer;
	if (call_index < 0 || call_index >= MAX_EDGE_CALL || !h2ecall_list[call_index]) {
		return 0;
	}
	return (*h2ecall_list[call_index])(malloc_pointer + 4, return_pointer);
}

