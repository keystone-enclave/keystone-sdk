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

#if __riscv_xlen == 64
typedef __u64 u_ptr_t; 
#elif __riscv_xlen == 32
typedef __u32 u_ptr_t;
#endif

struct runtime_params_t {
  u_ptr_t runtime_entry;
  u_ptr_t user_entry;
  u_ptr_t untrusted_ptr;
  u_ptr_t untrusted_size;
};

struct keystone_ioctl_create_enclave {
  u_ptr_t eid;

  //Min pages required
  u_ptr_t min_pages;

  // virtual addresses
  u_ptr_t runtime_vaddr;
  u_ptr_t user_vaddr;

  u_ptr_t pt_ptr;
  u_ptr_t utm_free_ptr;

  //Used for hash
  u_ptr_t epm_paddr;
  u_ptr_t utm_paddr;
  u_ptr_t runtime_paddr;
  u_ptr_t user_paddr;
  u_ptr_t free_paddr;

  u_ptr_t epm_size;
  u_ptr_t utm_size;

    // Runtime Parameters
  struct runtime_params_t params;
};

struct keystone_ioctl_run_enclave {
  u_ptr_t eid;
  u_ptr_t entry;
  u_ptr_t args_ptr;
  u_ptr_t args_size;
  u_ptr_t ret;
};

struct keystone_hash_enclave {
  u_ptr_t epm_paddr;
  u_ptr_t epm_size;
  u_ptr_t utm_paddr;
  u_ptr_t utm_size;

  u_ptr_t runtime_paddr;
  u_ptr_t user_paddr;
  u_ptr_t free_paddr;

  u_ptr_t untrusted_ptr;
  u_ptr_t untrusted_size;
};

#endif
