//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/ioctl.h>
#include <linux/types.h>
// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC 0xa4

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
#define KEYSTONE_IOC_CLONE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x08, struct keystone_ioctl_create_enclave_snapshot)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4

struct regs {
	uintptr_t sepc; // use this slot as sepc
	uintptr_t ra;
	uintptr_t sp;
	uintptr_t gp;
	uintptr_t tp;
	uintptr_t t0;
	uintptr_t t1;
	uintptr_t t2;
	uintptr_t s0;
	uintptr_t s1;
	uintptr_t a0;
	uintptr_t a1;
	uintptr_t a2;
	uintptr_t a3;
	uintptr_t a4;
	uintptr_t a5;
	uintptr_t a6;
	uintptr_t a7;
	uintptr_t s2;
	uintptr_t s3;
	uintptr_t s4;
	uintptr_t s5;
	uintptr_t s6;
	uintptr_t s7;
	uintptr_t s8;
	uintptr_t s9;
	uintptr_t s10;
	uintptr_t s11;
	uintptr_t t3;
	uintptr_t t4;
	uintptr_t t5;
	uintptr_t t6;
};

struct encl_ctx {
	struct regs regs;
  /* Supervisor CSRs */
	uintptr_t sstatus;//32
	uintptr_t sbadaddr;//33
	uintptr_t scause;//34
};

struct user_snapshot{
  uintptr_t freemem_pa_start;
  uintptr_t freemem_pa_end;
};

struct proc_snapshot{
    struct encl_ctx ctx; 
    uintptr_t user_pa_start;
    uintptr_t freemem_pa_start;
    uintptr_t freemem_pa_end;
    unsigned char tag_buf[16];
    const unsigned char initial_value[12];
    uintptr_t size; 
    char payload[0];
};

struct keystone_ioctl_create_enclave_snapshot {
  uintptr_t epm_paddr;
  uintptr_t utm_paddr;

  uintptr_t epm_size;
  uintptr_t utm_size;

  uintptr_t eid;
  uintptr_t snapshot_eid;
};

struct runtime_params_t {
  uintptr_t runtime_entry;
  uintptr_t user_entry;
  uintptr_t untrusted_ptr;
  uintptr_t untrusted_size;
  struct regs regs; 
};

struct keystone_ioctl_create_enclave {
  uintptr_t eid;

  // Min pages required
  uintptr_t min_pages;

  // virtual addresses
  uintptr_t runtime_vaddr;
  uintptr_t user_vaddr;

  uintptr_t pt_ptr;
  uintptr_t utm_free_ptr;

  // Used for hash
  uintptr_t epm_paddr;
  uintptr_t utm_paddr;
  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;

  uintptr_t epm_size;
  uintptr_t utm_size;

  uintptr_t is_clone;

  // Runtime Parameters
  struct runtime_params_t params;
};

struct keystone_ioctl_run_enclave {
  uintptr_t eid;
  uintptr_t child_eid; 
  uintptr_t resume_fork;
  uintptr_t error;
  uintptr_t value;
};

#endif
