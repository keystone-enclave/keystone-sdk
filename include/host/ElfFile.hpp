//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include "./common.h"
#include "./keystone_user.h"

extern "C" {
#include "./elf.h"
}

namespace Keystone {

class ElfFile {
 public:
  explicit ElfFile(std::string filename);
  ~ElfFile();
  size_t getFileSize() { return fileSize; }
  bool isValid();
  void* getPtr() { return ptr; }

 private:
  int filep;

  /* virtual addresses */
  uintptr_t minVaddr;
  uintptr_t maxVaddr;

  void* ptr;
  size_t fileSize;

  /* is this runtime binary */
  bool isRuntime;

  /* libelf structure */
  elf_t elf;
};

}  // namespace Keystone
