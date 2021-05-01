//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "edge_wrapper.h"

#define BUF_SIZE (1 << 20)


void EAPP_ENTRY eapp_entry(){
  int child_eid; 
  int ret = 0; 

  child_eid = sbi_enclave_fork();

  if(!child_eid){
    ret = 30913; 
  } else {
    ret = 57005; 
  }

  EAPP_RETURN(ret);
}
