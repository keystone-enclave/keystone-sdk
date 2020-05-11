#include "eapp_utils.h"
#include "malloc.h"
#include "string.h"
#include "edge_call.h"
#include "h2ecall.h"
#include <syscall.h>

int cipher(void* input, void** output) {
	char* str = (char*) input;
	int len = strlen(str);
	char* ret = (char*) malloc((len + 1) * sizeof(char));
	for (int i = 0; i < len + 1; ++i) {
		if (str[i] >= 'A' && str[i] <= 'Z')
			ret[i] = (char) ((str[i] - 'A' + 1) % 26 + 'A');
		else if (str[i] >= 'a' && str[i] <= 'z')
			ret[i] = (char) ((str[i] - 'a' + 1) % 26 + 'a');
		else
			ret[i] = str[i];
	}
	*output = ret;
	return len + 1;
}
	
void EAPP_ENTRY eapp_entry() {
	h2ecall_list[0] = cipher;
	receive_calls(h2ecall_dispatch);
	EAPP_RETURN(0);
}

