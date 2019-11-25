#include <cstring>
#include "keystone.h"
#include "edge_call.h"
#include "edge_common.h"

int loop(Keystone& enclave) {
	char input[256];
	printf("Please enter the string for Ceasar Cipher, or 'q' to quit:\n");
	scanf("%s", input);
	int len = strlen(input);
	if (len == 1 && input[0] == 'q') {
		// Set up for the enclave to quit
		*(int*) enclave.getSharedBuffer() = 0;
		enclave.resume();
		return 0;
	}
	*(int*) enclave.getSharedBuffer() = sizeof(int) + len + 1;
	*(((int*) enclave.getSharedBuffer()) + 1) = 0;
	strcpy((char*) enclave.getSharedBuffer() + 2 * sizeof(int), input);
	enclave.resume();
	edge_call* result = (edge_call*) enclave.getSharedBuffer();
	printf("The result is: %s\n", ((char*) enclave.getSharedBuffer() + result -> call_arg_offset));
	return 1;
}

int main(int argc, char** argv) {
	Keystone enclave;
	Params params;

	params.setFreeMemSize(1024*1024);
	params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 1024*1024);

	enclave.init(argv[1], argv[2], params);

	enclave.registerOcallDispatch(incoming_call_dispatch);
	edge_call_init_internals((uintptr_t) enclave.getSharedBuffer(),
		enclave.getSharedBufferSize());

	enclave.run();
	
	while (loop(enclave));
	
	return 0;
}

