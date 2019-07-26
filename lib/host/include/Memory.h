//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

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


class Memory;

class Memory
{
private:
  vaddr_t start_phys_addr;
public:
  Memory();
  ~Memory();
  ReadMem(bool is_phys, vaddr_t src, size_t size);
  WriteMem(bool is_phys, vaddr_t src, vaddr_t dst, size_t size);
};


