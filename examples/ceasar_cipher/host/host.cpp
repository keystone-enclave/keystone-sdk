#include "keystone.h"
#include "edge_call.h"

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
	return 0;
}

