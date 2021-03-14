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

  //ocall_print_value(3);

  global_variable = 0xdead;

  EAPP_RETURN(global_variable);
}
