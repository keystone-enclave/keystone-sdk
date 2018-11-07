#ifndef __EDGE_CALL_H_
#define __EDGE_CALL_H__

#include "edge_common.h"

/* Used by edge call wrappers to safely generate pointers into shared
   data structs */

int edge_call_get_ptr_from_offset(uintptr_t shared_start, size_t shared_len,
				  edge_data_offset offset, size_t data_len,
				  uintptr_t* ptr);

int edge_call_get_offset_from_ptr(uintptr_t shared_start, size_t shared_len,
				  uintptr_t ptr, size_t data_len,
				  edge_data_offset* offset);


#endif /* __EDGE_CALL_H_ */
