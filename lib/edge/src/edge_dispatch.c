//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "edge_call.h"

#ifdef IO_SYSCALL_WRAPPING
#include "edge_syscall.h"
#endif /*  IO_SYSCALL_WRAPPING */

edgecallwrapper edge_call_table[MAX_EDGE_CALL];

/* Registered handler for incoming edge calls */
int incoming_call_dispatch(void* buffer){
  struct edge_call* edge_call = (struct edge_call*) buffer;

#ifdef IO_SYSCALL_WRAPPING
  /* If its a syscall handle it specially */
  if( edge_call->call_id == EDGECALL_SYSCALL){
    incoming_syscall(buffer);
    return EDGEROUTINE_RESUME;
  }
#endif /*  IO_SYSCALL_WRAPPING */

  /* If it indicates a hangup directly returns */
  if( edge_call->call_id == EDGECALL_HANGUP){
  	return EDGEROUTINE_PAUSE;
  }
  
  /* Otherwise try to lookup the call in the table */
  if( edge_call->call_id > MAX_EDGE_CALL ||
      edge_call_table[edge_call->call_id] == NULL ){
    /* Fatal error */
    goto fatal_error;
  }
  edge_call_table[edge_call->call_id](buffer);
  return EDGEROUTINE_RESUME;

  fatal_error:
    edge_call->return_data.call_status = CALL_STATUS_BAD_CALL_ID;
    return EDGEROUTINE_RESUME;
}

int register_call(unsigned long call_id, edgecallwrapper func){
  if( call_id > MAX_EDGE_CALL){
    return -1;
  }

  edge_call_table[call_id] = func;
  return 0;
}
