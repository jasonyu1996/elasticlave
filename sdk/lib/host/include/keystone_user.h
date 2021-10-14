//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/types.h>
#include <linux/ioctl.h>
#include "performance.h"
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
#define KEYSTONE_IOC_GET_ENCLAVE_ID \
  _IOR(KEYSTONE_IOC_MAGIC, 0x08, unsigned long)
#define KEYSTONE_IOC_ELASTICLAVE_CHANGE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0a, struct keystone_ioctl_elasticlave_change)
#define KEYSTONE_IOC_SM_PRINT_STATS \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0d, struct keystone_ioctl_sm_stats)
#define KEYSTONE_IOC_SM_PRINT_RT_STATS \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0e, struct keystone_ioctl_rt_stats)
#define KEYSTONE_IOC_ELASTICLAVE_CREATE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x0f, struct keystone_ioctl_elasticlave_create)
#define KEYSTONE_IOC_ELASTICLAVE_DESTROY \
	_IOR(KEYSTONE_IOC_MAGIC, 0x10, uid_t)
#define KEYSTONE_IOC_ELASTICLAVE_MAP \
	_IOR(KEYSTONE_IOC_MAGIC, 0x11, struct keystone_ioctl_elasticlave_map)
#define KEYSTONE_IOC_ELASTICLAVE_UNMAP \
	_IOR(KEYSTONE_IOC_MAGIC, 0x12, struct keystone_ioctl_elasticlave_unmap) 
#define KEYSTONE_IOC_ELASTICLAVE_TRANSFER \
	_IOR(KEYSTONE_IOC_MAGIC, 0x13, struct keystone_ioctl_elasticlave_transfer) 
#define KEYSTONE_IOC_ELASTICLAVE_SHARE \
	_IOR(KEYSTONE_IOC_MAGIC, 0x14, struct keystone_ioctl_elasticlave_share) 


#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4
#define UTM_FULL_U 5

#define MDSIZE 64

struct runtime_params_t {
  __u64 runtime_entry;
  __u64 user_entry;
  __u64 untrusted_ptr;
  __u64 untrusted_size;
};

struct keystone_ioctl_create_enclave {
  __u64 eid;

  //Min pages required
  __u64 min_pages;

  // virtual addresses
  __u64 runtime_vaddr;
  __u64 user_vaddr;

  __u64 pt_ptr;
  __u64 utm_free_ptr;

  //Used for hash
  __u64 epm_paddr;
  __u64 utm_paddr;
  __u64 runtime_paddr;
  __u64 user_paddr;
  __u64 free_paddr;

  __u64 epm_size;
  __u64 utm_size;

    // Runtime Parameters
  struct runtime_params_t params;
};

struct keystone_ioctl_run_enclave {
  __u64 eid;
  __u64 entry;
  __u64 args_ptr;
  __u64 args_size;
  __u64 ret;
  __u64 dr_request_resp0;
  __u64 dr_request_resp1;
  __u64 dr_request_args;
};

struct keystone_hash_enclave {
  __u64 epm_paddr;
  __u64 epm_size;
  __u64 utm_paddr;
  __u64 utm_size;

  __u64 runtime_paddr;
  __u64 user_paddr;
  __u64 free_paddr;

  __u64 untrusted_ptr;
  __u64 untrusted_size;
};

struct keystone_ioctl_elasticlave_change {
  __u64 uid;
  __u64 perm; 
};

struct keystone_ioctl_sm_stats {
  __u64 eid;
  struct enclave_stats* stats;
};

struct keystone_ioctl_rt_stats {
  __u64 eid;
  struct enclave_rt_stats* rt_stats;
};

struct enclave_stats {
	struct performance_stats switch_to_enclave;
	struct performance_stats switch_to_host;
	struct performance_stats enclave_execution;
	struct performance_stats host_execution;
};

struct enclave_rt_stats {
	struct performance_stats args_copy_stats;
	struct performance_stats retval_copy_stats;
	struct performance_stats page_fault_stats;
	struct performance_stats stats_sbi;
	struct performance_stats stats_rt;
	struct performance_stats stats_boot_sbi;
	struct performance_stats stats_boot;
};

struct keystone_ioctl_elasticlave_create {
  __u64 size;
  uid_t* uid;
};

struct keystone_ioctl_elasticlave_map {
  uid_t uid;
  __u64 size;
};

struct keystone_ioctl_elasticlave_unmap {
  __u64 vaddr;
  __u64 size;
};

struct keystone_ioctl_elasticlave_share {
  uid_t uid;
  __u64 perm;
  __u64 eid;
};

struct keystone_ioctl_elasticlave_transfer {
  uid_t uid;
  __u64 eid;
};

#endif
