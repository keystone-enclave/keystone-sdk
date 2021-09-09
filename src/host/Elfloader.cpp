//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Elfloader.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>


static int 
parseElf(char* fileName, bool isRuntime) {
  int ret; 

  ElfFile* elfFile = ElfFile(fileName);
  

  if (!elfFile->initialize(isRuntime)) {
    // TODO: Error handling 
    return false; 
  }
  
  

    


  return 1;
}
