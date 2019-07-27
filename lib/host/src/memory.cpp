//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <sys/stat.h>
#include <sys/mman.h>
#include <keystone_user.h>
#include "memory.h"

Memory::Memory() {
  start_phys_addr = 0;
  keystone_fd = 0;
}

Memory::~Memory() {

}

void Memory::init(int fd, vaddr_t phys_addr){
  keystone_fd = fd;
  start_phys_addr = phys_addr;
}


vaddr_t Memory::AllocMem(bool is_phys, size_t size){

  vaddr_t ret;
  if(is_phys) {
    ret = (vaddr_t) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, 0);
  }
  else{
    ret = (vaddr_t) allocate_aligned(size, PAGE_SIZE);
  }

  return ret;
}

void Memory::ReadMem(bool is_phys, vaddr_t src, vaddr_t buf, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, src - start_phys_addr);
    memcpy((void *) buf, (void *) va_dst, size);
  }
  else{
    memcpy((void *) buf, (void *) src, size);
  }
}


void Memory::WriteMem(bool is_phys, vaddr_t src, vaddr_t dst, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, dst - start_phys_addr);
    memcpy((void *) va_dst, (void *) src, size);
  }
  else{
    memcpy((void *) dst, (void *) src, size);
  }
}

