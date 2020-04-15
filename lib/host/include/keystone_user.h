//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/types.h>
#include <linux/ioctl.h>
// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC  0xa4

// ioctl definition
#define KEYSTONE_IOC_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

#define MDSIZE 64

struct runtime_params_t {
  __u32 runtime_entry;
  __u32 user_entry;
  __u32 untrusted_ptr;
  __u32 untrusted_size;
};

struct keystone_ioctl_create_enclave {
  __u32 eid;

  //Min pages required
  __u32 min_pages;

  // virtual addresses
  __u32 runtime_vaddr;
  __u32 user_vaddr;

  __u32 pt_ptr;
  __u32 utm_free_ptr;

  //Used for hash
  __u32 epm_paddr;
  __u32 utm_paddr;
  __u32 runtime_paddr;
  __u32 user_paddr;
  __u32 free_paddr;

  __u32 epm_size;
  __u32 utm_size;

    // Runtime Parameters
  struct runtime_params_t params;
};

struct keystone_ioctl_run_enclave {
  __u32 eid;
  __u32 entry;
  __u32 args_ptr;
  __u32 args_size;
  __u32 ret;
};

struct keystone_hash_enclave {
  __u32 epm_paddr;
  __u32 epm_size;
  __u32 utm_paddr;
  __u32 utm_size;

  __u32 runtime_paddr;
  __u32 user_paddr;
  __u32 free_paddr;

  __u32 untrusted_ptr;
  __u32 untrusted_size;
};


#endif
