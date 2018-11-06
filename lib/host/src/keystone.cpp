#include <sys/stat.h>
#include <sys/mman.h>
#include "keystone.h"
#include "keystone_user.h"

Keystone::Keystone()
{
  runtimeFile = NULL;
  enclaveFile = NULL;
  eid = -1;
}

Keystone::~Keystone()
{
  delete runtimeFile;
  delete enclaveFile;
  destroy();
}

keystone_status_t Keystone::init(char* eapppath, char* runtimepath, size_t stack_size, size_t untrusted_size, unsigned long usr_entry_ptr)
{
  if(runtimeFile || enclaveFile)
  {
    ERROR("ELF files already initialized");
    return KEYSTONE_ERROR;
  }

  runtimeFile = new ELFFile(runtimepath);
  enclaveFile = new ELFFile(eapppath);
  
  /* these should be parsed by ELF lib */
  runtimeFile->setEntry(0xffffffffc0000000);
  enclaveFile->setEntry(usr_entry_ptr); 
 
  /* open device driver */
  fd = open(KEYSTONE_DEV_PATH, O_RDWR);
  if(fd < 0){
    PERROR("cannot open device file");
    return KEYSTONE_ERROR;
  }
  // Open up the target file and read it into memory
  
  if(!runtimeFile->isValid())
  {
    ERROR("runtime file is not valid");
    return KEYSTONE_ERROR;
  }
  if(!enclaveFile->isValid())
  {
    ERROR("enclave file is not valid");
    return KEYSTONE_ERROR;
  }
  
  struct keystone_ioctl_create_enclave enclp;

  enclp.eapp_ptr = (unsigned long) enclaveFile->getPtr();
  enclp.eapp_sz = (unsigned long) enclaveFile->getSize();
  enclp.eapp_stack_sz = (unsigned long) stack_size;
  enclp.runtime_ptr = (unsigned long) runtimeFile->getPtr();
  enclp.runtime_sz = (unsigned long) runtimeFile->getSize();
  enclp.runtime_stack_sz = (unsigned long) 4096*2;
  enclp.untrusted_sz = untrusted_size;

  //printf("Enclave info: ptr:%p code_sz:%ul mem_sz:%ul\n",app_code_buffer, code_size, stack_size);
  int ret = ioctl(fd, KEYSTONE_IOC_CREATE_ENCLAVE, &enclp);
  if(ret) {
    ERROR("failed to create enclave - ioctl() failed: %d", ret);
    return KEYSTONE_ERROR;
  }
  eid = enclp.eid;

  return mapUntrusted(untrusted_size);
}

keystone_status_t Keystone::mapUntrusted(size_t size)
{
  buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (buffer == NULL)
  {
    return KEYSTONE_ERROR;
  }
  return KEYSTONE_SUCCESS;
}

keystone_status_t Keystone::destroy()
{
  struct keystone_ioctl_create_enclave enclp;
  enclp.eid = eid;
  int ret = ioctl(fd, KEYSTONE_IOC_DESTROY_ENCLAVE, &enclp);

  if(ret) {
    ERROR("failed to destroy enclave - ioctl() failed: %d", ret);
    return KEYSTONE_ERROR;
  }

  return KEYSTONE_SUCCESS;
}

#define KEYSTONE_ENCLAVE_INTERRUPTED  2
keystone_status_t Keystone::run(uintptr_t* retval)
{
  int	ret;
  struct keystone_ioctl_run_enclave run;
  run.eid = eid;
  run.entry = enclaveFile->getEntry();

  ret = ioctl(fd, KEYSTONE_IOC_RUN_ENCLAVE, &run);
  while (ret == KEYSTONE_ENCLAVE_INTERRUPTED)
  {
    /* enclave is stopped in the middle. */
    if (oFuncs[run.ret] != NULL) {
      oFuncs[run.ret](this);
    }
    ret = ioctl(fd, KEYSTONE_IOC_RESUME_ENCLAVE, &run);
  }
  if(ret)
  {
    ERROR("failed to run enclave - ioctl() failed: %d", ret);
    return KEYSTONE_ERROR;
  }

  *retval = run.ret;

  return KEYSTONE_SUCCESS;
}

void* Keystone::getBuffer()
{
  return buffer;
}

keystone_status_t Keystone::registerOcall(unsigned int request, OcallFunc func)
{
  oFuncs[request] = func;
}
