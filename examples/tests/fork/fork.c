//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"

#include "edge_wrapper.h"
int global_variable;
void EAPP_ENTRY eapp_entry(){
  //edge_init();

  sbi_enclave_snapshot();

  // clone (220)
  int pid = SYSCALL_0(220);

  EAPP_RETURN(pid);
}
