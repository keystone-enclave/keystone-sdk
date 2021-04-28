//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "edge_wrapper.h"
#include "malloc.h"

int global_variable;
void EAPP_ENTRY eapp_entry(){
  edge_init();

  int * ptr = (int*) malloc(512*1024*1024);

  *ptr = 0xf;

  ocall_print_value(*ptr);

  sbi_enclave_snapshot();

  *ptr = 0xd;

  global_variable = 0xdea0;

  ocall_print_value(global_variable + *ptr);

  EAPP_RETURN(global_variable + *ptr);
}
