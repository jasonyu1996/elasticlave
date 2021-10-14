//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//-----------------------------------------------------------------------------;
#ifndef _KEYSTONE_SBI_H_
#define _KEYSTONE_SBI_H_

#include <stdint.h>
#include <stddef.h>
#include "sm_types.h"
#include "perm.h"

#define SM_REQUEST_ELASTICLAVE_CREATE 1000
#define SM_REQUEST_ELASTICLAVE_DESTROY 1001

typedef uintptr_t enclave_ret_code;

uintptr_t mcall_sm_create_enclave(uintptr_t create_args);

uintptr_t mcall_sm_destroy_enclave(unsigned long eid, uintptr_t shm_list);

uintptr_t mcall_sm_run_enclave(uintptr_t* regs, unsigned long eid);
uintptr_t mcall_sm_exit_enclave(uintptr_t* regs, unsigned long retval, uintptr_t rt_stats_ptr);
uintptr_t mcall_sm_not_implemented(uintptr_t* regs, unsigned long a0);
uintptr_t mcall_sm_stop_enclave(uintptr_t* regs, unsigned long request);
uintptr_t mcall_sm_resume_enclave(uintptr_t* host_regs, unsigned long eid,
  uintptr_t resp0, uintptr_t resp1);
uintptr_t mcall_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size);
uintptr_t mcall_sm_elasticlave_create(uintptr_t* encl_regs, uintptr_t size);
uintptr_t mcall_sm_elasticlave_host_create(uintptr_t pa, uintptr_t size, 
    uintptr_t uid_ret);
uintptr_t mcall_sm_elasticlave_change(uintptr_t uid, uintptr_t dyn_perm);
uintptr_t mcall_sm_elasticlave_share(uid_t uid, enclave_id eid, st_perm_t st_perm);
uintptr_t mcall_sm_elasticlave_map(uid_t uid, \
		uintptr_t* ret_paddr, 
		uintptr_t* ret_size);
uintptr_t mcall_sm_elasticlave_unmap(uid_t uid);
uintptr_t mcall_sm_elasticlave_transfer(uid_t uid, \
		enclave_id eid);
uintptr_t mcall_sm_elasticlave_region_events(uintptr_t event_buf, uintptr_t count_ptr, uintptr_t count_lim);
uintptr_t mcall_sm_elasticlave_destroy(uintptr_t* encl_regs, uid_t uid);
uintptr_t mcall_sm_print_stats(unsigned long eid, void* ret_ptr);
uintptr_t mcall_sm_print_rt_stats(unsigned long eid, void* ret_ptr);
uintptr_t mcall_sm_random();
uintptr_t mcall_sm_elasticlave_install_regev(uintptr_t regev_notify);

uintptr_t mcall_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1);

#endif
