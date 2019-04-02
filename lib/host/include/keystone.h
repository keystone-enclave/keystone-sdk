//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <stddef.h>
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <stdarg.h>
#include <assert.h>
#include "common.h"
#include "elffile.h"
#include "params.h"
#include "sha3.h"

#define MDSIZE  64

class Keystone;
typedef void (*OcallFunc)(void*);
typedef sha3_ctx_t hash_ctx_t;

class Keystone
{
private:
  ELFFile* runtimeFile;
  ELFFile* enclaveFile;
  vaddr_t enclave_stk_start;
  vaddr_t enclave_stk_sz;
  vaddr_t runtime_stk_sz;
  hash_ctx_t hash_ctx;
  int eid;
  int fd;
  void* shared_buffer;
  size_t shared_buffer_size;
  OcallFunc oFuncDispatch;
  keystone_status_t mapUntrusted(size_t size);
  keystone_status_t loadELF(ELFFile* file, bool hash_flag);
  keystone_status_t initStack(vaddr_t start, size_t size, bool is_rt);
  keystone_status_t allocPage(vaddr_t va, void* src, unsigned int mode, bool hash_flag);
  keystone_status_t init_epm_hash(const char* filepath, const char* runtime, Params parameters, bool hash_flag);
public:
  Keystone();
  ~Keystone();
  void* getSharedBuffer();
  size_t getSharedBufferSize();
  keystone_status_t registerOcallDispatch(OcallFunc func);
  keystone_status_t init(const char* filepath, const char* runtime, Params parameters);
  keystone_status_t destroy();
  keystone_status_t run();
  keystone_status_t measure(const char* filepath, const char* runtime, Params parameters);
  char hash[MDSIZE];
};

unsigned long calculate_required_pages(
        unsigned long eapp_sz,
        unsigned long eapp_stack_sz,
        unsigned long rt_sz,
        unsigned long rt_stack_sz);

#endif
