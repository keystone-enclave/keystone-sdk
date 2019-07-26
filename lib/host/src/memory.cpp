//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sys/stat.h>
#include <sys/mman.h>
#include <keystone_user.h>
#include "keystone.h"
#include "elffile.h"
#include "keystone_user.h"
#include "page.h"
#include "hash_util.h"

Memory::Memory() {
  start_phys_addr = 0;
}

Memory::~Memory() {

}

void Memory::Read(bool is_phys, vaddr_t src, vaddr_t buf, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, dst - start_phys_addr);
    memcpy((void *) buf, (void *) src, size);
  }
  else{
    memcpy((void *) buf, (void *) src, size);
  }
}


void Memory::Write(bool is_phys, vaddr_t src, vaddr_t dst, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, dst - start_phys_addr);
    memcpy((void *) va_dst, (void *) src, size);
  }
  else{
    memcpy((void *) dst, (void *) src, size);
  }
}

