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
#include "loader.h"

#define BOOST_STRINGIZE(X) BOOST_DO_STRINGIZE(X)
#define BOOST_DO_STRINGIZE(X) #X

#define KEYSTONE_DEV_PATH "/dev/keystone_enclave"

#define MSG(str) "[Keystone SDK] " __FILE__ ":" BOOST_STRINGIZE(__LINE__) " : " str
#define ERROR(str, ...) fprintf(stderr, MSG(str) "\n", ##__VA_ARGS__)
#define PERROR(str) perror(MSG(str))

class Keystone;
typedef void (*OcallFunc)(Keystone*);

typedef enum {
  KEYSTONE_ERROR=-1,
  KEYSTONE_SUCCESS,
  KEYSTONE_NOT_IMPLEMENTED,
} keystone_status_t;

class Keystone
{
private:
  ELFFile* runtimeFile;
  ELFFile* enclaveFile;
  int eid;
  int fd;
  void* buffer;
  // TODO: static function table
  OcallFunc oFuncs[10];
  keystone_status_t mapUntrusted(size_t size);
public:
  Keystone();
  ~Keystone();
  void* getBuffer();
  keystone_status_t registerOcall(unsigned int request, OcallFunc func);
  keystone_status_t init(char* filepath, char* runtime, size_t mem_size, size_t untrusted_size, unsigned long usr_entry_ptrx);
  keystone_status_t destroy();
  keystone_status_t run(uintptr_t* retval);
  keystone_status_t initRuntime(const char* filename);
};

#endif
