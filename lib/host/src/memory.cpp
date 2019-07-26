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
#include "memory.h"

Memory::Memory(int fd) {
  start_phys_addr = 0;
  keystone_fd = fd;
}

Memory::~Memory() {

}

void * allocate_aligned(size_t size, size_t alignment)
{
  const size_t mask = alignment - 1;
  const uintptr_t mem = (uintptr_t) calloc(size + alignment, sizeof(char));
  return (void *) ((mem + mask) & ~mask);
}

vaddr_t Memory::AllocMem(bool is_phys, size_t size){

  vaddr_t ret;
  if(is_phys) {
    ret = (vaddr_t) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, 0);
  }
  else{
    ret = allocate_aligned(size, PAGE_SIZE);
  }

  return ret;
}

void Memory::Read(bool is_phys, vaddr_t src, vaddr_t buf, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, dst - start_phys_addr);
    memcpy((void *) buf, (void *) src, size);
  }
  else{
    memcpy((void *) buf, (void *) src, size);
  }
}


void Memory::Write(bool is_phys, vaddr_t src, vaddr_t dst, size_t size){

  if(is_phys) {
    vaddr_t va_dst = (vaddr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, keystone_fd, dst - start_phys_addr);
    memcpy((void *) va_dst, (void *) src, size);
  }
  else{
    memcpy((void *) dst, (void *) src, size);
  }
}

