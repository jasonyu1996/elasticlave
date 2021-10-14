//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include <errno.h>
#include "platform.h"
#include "plugins/plugins.h"
#include "enclave-request.h"
#include "performance.h"
#include "ipi.h"

extern struct enclave enclaves[];
extern spinlock_t encl_lock;

uintptr_t mcall_sm_create_enclave(uintptr_t create_args)
{
	struct keystone_sbi_create create_args_local;
	enclave_ret_code ret;

	/* an enclave cannot call this SBI */
	if (cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ipi_acquire_lock(&encl_lock);
	ret = copy_from_host((struct keystone_sbi_create*)create_args,
			&create_args_local,
			sizeof(struct keystone_sbi_create));
	ipi_release_lock(&encl_lock);

	if( ret != ENCLAVE_SUCCESS )
		return ret;

	ret = create_enclave(create_args_local);
	return ret;
}

uintptr_t mcall_sm_destroy_enclave(unsigned long eid, uintptr_t shm_list)
{
	enclave_ret_code ret;

	/* an enclave cannot call this SBI */
	if (cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	struct enclave_shm_list list;

	ret = destroy_enclave((unsigned int)eid, &list);

	if(ret != ENCLAVE_SUCCESS)
		return ret;

	ipi_acquire_lock(&encl_lock);
	ret = copy_to_host((void*)shm_list, &list, sizeof(struct enclave_shm_list));
	ipi_release_lock(&encl_lock);

	return ret;
}

uintptr_t mcall_sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
	enclave_ret_code ret;

	/* an enclave cannot call this SBI */
	if (cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ret = run_enclave(regs, (unsigned int) eid);

	return ret;
}

uintptr_t mcall_sm_resume_enclave(uintptr_t* host_regs, unsigned long eid,
		uintptr_t resp0, uintptr_t resp1)
{
	enclave_ret_code ret;

	/* an enclave cannot call this SBI */
	if (cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ret = resume_enclave(host_regs, (unsigned int) eid, resp0, resp1);
	return ret;
}

uintptr_t mcall_sm_exit_enclave(uintptr_t* encl_regs, unsigned long retval, uintptr_t rt_stats_ptr)
{
	enclave_ret_code ret;
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ret = exit_enclave(encl_regs, (unsigned long) retval, rt_stats_ptr, cpu_get_enclave_id());
	return ret;
}

uintptr_t mcall_sm_stop_enclave(uintptr_t* encl_regs, unsigned long request)
{
	uintptr_t mcause = read_csr(mcause);
	enclave_ret_code ret;
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ret = stop_enclave(encl_regs, (uint64_t)request, cpu_get_enclave_id());
	return ret;
}

uintptr_t mcall_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
	enclave_ret_code ret;
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	ret = attest_enclave(report, data, size, cpu_get_enclave_id());
	return ret;
}

uintptr_t mcall_sm_random()
{
	/* Anyone may call this interface. */

	return platform_random();
}

uintptr_t mcall_sm_elasticlave_change(uintptr_t uid, uintptr_t dyn_perm){
	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : EID_UNTRUSTED;
	return elasticlave_change(eid, (uid_t)uid, (dyn_perm_t)dyn_perm);
}

// for enclave
uintptr_t mcall_sm_elasticlave_create(uintptr_t* encl_regs, uintptr_t size){
	enclave_ret_code ret;
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	enclave_id eid = cpu_get_enclave_id();

	ret = stop_enclave(encl_regs, SM_REQUEST_ELASTICLAVE_CREATE, eid);
	if(ret == ENCLAVE_NOT_RUNNING) // did not successfully switch the context
		goto elasticlave_create_request_clean;

	uintptr_t* request_args = (uintptr_t*)encl_regs[11]; // arg1 would be pointer to the arg array
	setup_enclave_request(eid, REQUEST_ELASTICLAVE_CREATE, request_args, 1, size);

elasticlave_create_request_clean:
	return ret;
}

// for host
uintptr_t mcall_sm_elasticlave_host_create(uintptr_t pa, uintptr_t size, 
    uintptr_t uid_ret){
  enclave_ret_code ret;
  if(cpu_is_enclave_context())
    return ENCLAVE_SBI_PROHIBITED;

  ret = _elasticlave_create(NULL, pa, (void*)uid_ret, size);


  return ret;
}

uintptr_t mcall_sm_elasticlave_map(uid_t uid, \
		uintptr_t* ret_paddr, 
		uintptr_t* ret_size){
	enclave_ret_code ret;
	// both the untrusted code and other enclaves can call this

	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : EID_UNTRUSTED;

	uintptr_t paddr = 0, size = 0;
	ret = elasticlave_map(eid, uid, &paddr, &size);

	ipi_acquire_lock(&encl_lock);
	if(ret == ENCLAVE_SUCCESS){
		if(eid != EID_UNTRUSTED){
			struct enclave* encl = encl_get(eid);
			assert(!copy_to_enclave(encl, ret_paddr, &paddr, sizeof(paddr)));
			assert(!copy_to_enclave(encl, ret_size, &size, sizeof(size)));
		} else{
			assert(!copy_to_host(ret_paddr, &paddr, sizeof(paddr)));
			assert(!copy_to_host(ret_size, &size, sizeof(size)));
		}
	}
	ipi_release_lock(&encl_lock);

	return ret;
}

uintptr_t mcall_sm_elasticlave_unmap(uid_t uid){
	enclave_ret_code ret;
	enclave_id eid = cpu_is_enclave_context() ? cpu_get_enclave_id() : (enclave_id)EID_UNTRUSTED;
	ret = elasticlave_unmap(eid, uid);
	return ret;
}

uintptr_t mcall_sm_elasticlave_share(uid_t uid, \
		enclave_id eid,
		st_perm_t st_perm){
	return elasticlave_share(cpu_get_enclave_id(), uid, eid, st_perm);
}

uintptr_t mcall_sm_elasticlave_transfer(uid_t uid, \
		enclave_id eid){
	return elasticlave_transfer(cpu_get_enclave_id(), uid, eid);
}

uintptr_t mcall_sm_elasticlave_region_events(uintptr_t event_buf, 
		uintptr_t count_ptr, uintptr_t count_lim){
	return elasticlave_region_events(cpu_get_enclave_id(), event_buf, 
			count_ptr,
			(int)count_lim);
}

uintptr_t mcall_sm_elasticlave_install_regev(uintptr_t regev_notify){
  if(cpu_is_enclave_context())
    return ENCLAVE_SBI_PROHIBITED;
  return install_regev_notify(regev_notify) ? ENCLAVE_ILLEGAL_ARGUMENT : ENCLAVE_SUCCESS;
}

uintptr_t mcall_sm_elasticlave_destroy(uintptr_t* encl_regs, uid_t uid){
	enclave_id eid = cpu_get_enclave_id();

	uintptr_t paddr = 0;
	enclave_ret_code ret = elasticlave_destroy(eid, uid, &paddr);
	if(ret != ENCLAVE_SUCCESS)
		return ret;

	// notify the OS
  if(eid){
    ret = stop_enclave(encl_regs, SM_REQUEST_ELASTICLAVE_DESTROY, eid);
    if(ret == ENCLAVE_NOT_RUNNING) // did not successfully switch the context
      return ret;

    uintptr_t* request_args = (uintptr_t*)encl_regs[11]; // arg1 would be pointer to the arg array
    setup_enclave_request(eid, REQUEST_ELASTICLAVE_DESTROY, request_args, 1, paddr);
  }
	
	return ret;
}

uintptr_t mcall_sm_print_stats(unsigned long eid, void* ret_ptr){
	if(cpu_is_enclave_context()){
		return ENCLAVE_SBI_PROHIBITED;
	}
	struct enclave* encl = encl_get(eid);
	copy_to_host(ret_ptr, &encl->stats, sizeof(struct enclave_stats));
	return ENCLAVE_SUCCESS;
}

uintptr_t mcall_sm_print_rt_stats(unsigned long eid, void* ret_ptr){
	if(cpu_is_enclave_context()){
		return ENCLAVE_SBI_PROHIBITED;
	}
	struct enclave* encl = encl_get(eid);
	copy_to_host(ret_ptr, &encl->rt_stats, sizeof(struct enclave_rt_stats));
	return ENCLAVE_SUCCESS;
}

uintptr_t mcall_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
	if(!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}
	return call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
}

/* TODO: this should be removed in the future. */
uintptr_t mcall_sm_not_implemented(uintptr_t* encl_regs, unsigned long cause)
{
	/* only an enclave itself can call this SBI */
	if (!cpu_is_enclave_context()) {
		return ENCLAVE_SBI_PROHIBITED;
	}

	if((long)cause < 0)
	{
		// discard MSB
		cause = cause << 1;
		cause = cause >> 1;
		printm("the runtime could not handle interrupt %ld\r\n", cause );
		printm("mideleg: 0x%lx\r\n");

	}
	else
	{
		printm("the runtime could not handle exception %ld\r\n", cause);
		printm("medeleg: 0x%lx (expected? %ld)\r\n", read_csr(medeleg), read_csr(medeleg) & (1<<cause));
	}

	return exit_enclave(encl_regs, (uint64_t)-1UL, 0, cpu_get_enclave_id());
}
