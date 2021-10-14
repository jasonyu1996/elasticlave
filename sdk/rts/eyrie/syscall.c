//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include "syscall.h"
#include "string.h"
#include "edge_call.h"
#include "uaccess.h"
#include "mm.h"
#include "rt_util.h"

#include "syscall_nums.h"

#ifdef IO_SYSCALL_WRAPPING
#include "io_wrap.h"
#endif /* IO_SYSCALL_WRAPPING */

// io syscall without copying
#ifdef FAST_IO_SYSCALL_WRAPPING
#include "fast_io_wrap.h"
#endif

#ifdef LINUX_SYSCALL_WRAPPING
#include "linux_wrap.h"
#endif /* LINUX_SYSCALL_WRAPPING */

#include "performance.h"

#include "rpc.h"

#include "types.h"

#define REGION_NAME_MAX_LEN 16

struct shared_region shared_region;
extern int eid;

uintptr_t dispatch_edgecall_syscall(struct edge_syscall* syscall_data_ptr, size_t data_len){
  int ret;

  // Syscall data should already be at the edge_call_data section
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;

  edge_call->call_id = EDGECALL_SYSCALL;


  if(edge_call_setup_call(edge_call, (void*)syscall_data_ptr, data_len, &shared_region) != 0){
    return -1;
  }

  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 1);

  if (ret != 0) {
    return -1;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    return -1;
  }

  uintptr_t return_ptr;
  size_t return_len;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &return_len, &shared_region) != 0){
    return -1;
  }

  if(return_len < sizeof(uintptr_t)){
    return -1;
  }

  return *(uintptr_t*)return_ptr;
}

static uintptr_t stats_target_call_id;

static void print_stats(){
	rt_performance_stats_t l_stats = stats;

	performance_stats_print(&l_stats.args_copy_stats, "RT Args Copy");
	performance_stats_print_total(&l_stats.args_copy_stats, "RT Args Copy");
	performance_stats_print(&l_stats.retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&l_stats.retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&l_stats.page_fault_stats, "RT Page Fault");
	performance_stats_print_total(&l_stats.stats_sbi, "RT SBI");
	performance_stats_print_total(&l_stats.stats_rt, "RT Total");
	performance_stats_print_total(&l_stats.stats_boot_sbi, "RT Boot SBI");
	performance_stats_print_total(&l_stats.stats_boot, "RT Boot Total");
}

static void set_stats_target(uintptr_t target){
	stats_target_call_id = target;
}

uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len, int in_rt){

  uintptr_t ret;
  /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*)shared_buffer;

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  edge_call->call_id = call_id;
  uintptr_t buffer_data_start = edge_call_data_ptr(&shared_region);

  if(data_len > (shared_buffer_size - (buffer_data_start - shared_buffer))){
    goto ocall_error;
  }

  //TODO safety check on source

  if((stats_target_call_id >> call_id) & 1)
	  performance_check_start(&stats.args_copy_stats);
  if(in_rt)
	  memcpy((void*)buffer_data_start, (void*)data, data_len);
  else
	  copy_from_user((void*)buffer_data_start, (void*)data, data_len);
  if((stats_target_call_id >> call_id) & 1){
	  performance_check_end(&stats.args_copy_stats);
	  performance_count(&stats.args_copy_stats);
	  performance_count_data(&stats.args_copy_stats, data_len);
  }

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len, &shared_region) != 0){
    goto ocall_error;
  }

  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 1);

  if (ret != 0) {
    goto ocall_error;
  }

  if(edge_call->return_data.call_status != CALL_STATUS_OK){
    goto ocall_error;
  }

  if( return_len == 0 ){
    /* Done, no return */
    return (uintptr_t)NULL;
  }

  uintptr_t return_ptr;
  size_t ret_len_untrusted;
  if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted, &shared_region) != 0){
    goto ocall_error;
  }

  /* Done, there was a return value to copy out of shared mem */
  /* TODO This is currently assuming return_len is the length, not the
     value passed in the edge_call return data. We need to somehow
     validate these. The size in the edge_call return data is larger
     almost certainly.*/
  if((stats_target_call_id >> call_id) & 1)
	  performance_check_start(&stats.retval_copy_stats);
  if(in_rt)
	  memcpy(return_buffer, (void*)return_ptr, return_len);
  else
	  copy_to_user(return_buffer, (void*)return_ptr, return_len);
  if((stats_target_call_id >> call_id) & 1){
	  performance_check_end(&stats.retval_copy_stats);
	  performance_count(&stats.retval_copy_stats);
	  performance_count_data(&stats.retval_copy_stats, return_len);
  }

  return 0;

 ocall_error:
  /* TODO In the future, this should fault */
  return 1;
}

uintptr_t handle_copy_from_shared(void* dst, uintptr_t offset, size_t size){

  /* This is where we would handle cache side channels for a given
     platform */

  /* The only safety check we do is to confirm all data comes from the
   * shared region. */
  uintptr_t src_ptr;
  if(edge_call_get_ptr_from_offset(offset, size,
				   &src_ptr, &shared_region) != 0){
    return 1;
  }

  return copy_to_user(dst, (void*)src_ptr, size);
}

void init_edge_internals(){
  shared_region_init(shared_buffer, shared_buffer_size, &shared_region);
  performance_stats_init(&stats.args_copy_stats);
  performance_stats_init(&stats.retval_copy_stats);
  stats_target_call_id = 0;
}

static int handle_elasticlave_map(uid_t uid, uintptr_t* ret_vaddr){
	uintptr_t paddr, size;
	uintptr_t paddr_pa = kernel_va_to_pa(&paddr), size_pa = kernel_va_to_pa(&size);
    uintptr_t ret = SBI_CALL_3(SBI_SM_ELASTICLAVE_MAP, (uintptr_t)uid, paddr_pa, size_pa);
	if(ret)
		return 1;

	uintptr_t vaddr = find_va_range(size); // find virtual address range to map the region
	*ret_vaddr = vaddr;
	if(!vaddr)
		return 1;
	map_pages(vaddr, paddr, size, PAGE_MODE_USER_DATA, VMA_TYPE_SHARED, uid);
	return 0; // TODO: better error handling
}

static int handle_elasticlave_map_at(uid_t uid, uintptr_t va){
	uintptr_t paddr, size;
	uintptr_t paddr_pa = kernel_va_to_pa(&paddr), size_pa = kernel_va_to_pa(&size);
    uintptr_t ret = SBI_CALL_3(SBI_SM_ELASTICLAVE_MAP, (uintptr_t)uid, paddr_pa, size_pa);
	if(ret)
		return 1;

    if((va & 0xfff) || (size & 0xfff))
        return 1;

    if(test_va_range(va >> 12, size >> 12) != (size >> 12)){ // virtual address range unavailable
        return 1;
    }

	if(!va)
		return 1;
	map_pages(va, paddr, size, PAGE_MODE_USER_DATA, VMA_TYPE_SHARED, uid);
	return 0; // TODO: better error handling
}

static int handle_elasticlave_unmap(uintptr_t vaddr){
	struct vma* vma = get_vma_by_va(vaddr);
	if(vma == NULL || vma->type != VMA_TYPE_SHARED)
		return 1;

	uintptr_t ret = SBI_CALL_1(SBI_SM_ELASTICLAVE_UNMAP, vma->uid);
	if(ret)
		return 1;
	unmap_pages(vma);

	return 0;
}

uintptr_t handle_syscall(struct encl_ctx* ctx, unsigned long start_cycle)
{
  uintptr_t n = ctx->regs.a7;
  uintptr_t arg0 = ctx->regs.a0;
  uintptr_t arg1 = ctx->regs.a1;
  uintptr_t arg2 = ctx->regs.a2;
  uintptr_t arg3 = ctx->regs.a3;
  uintptr_t arg4 = ctx->regs.a4;

  // We only use arg5 in these for now, keep warnings happy.
#if defined(IO_SYSCALL_WRAPPING) || defined(LINUX_SYSCALL_WRAPPING)
  uintptr_t arg5 = ctx->regs.a5;
#endif /* IO_SYSCALL_WRAPPING */
  uintptr_t ret = 0, ret_val = 0;// ret_val2 = 0, ret_size = 0;
  uid_t ret_uid = 0;
  uintptr_t ret_uid_pa = kernel_va_to_pa(&ret_uid);

  ctx->regs.sepc += 4;
  int store_result = 1;

  switch (n) {
  case(RUNTIME_SYSCALL_EXIT):
    SBI_CALL_2(SBI_SM_EXIT_ENCLAVE, arg0, kernel_va_to_pa(&stats));
    break;
  case(RUNTIME_SYSCALL_OCALL):
    ret = dispatch_edgecall_ocall(arg0, (void*)arg1, arg2, (void*)arg3, arg4, 0);
    break;
  case(RUNTIME_SYSCALL_SHAREDCOPY):
    ret = handle_copy_from_shared((void*)arg0, arg1, arg2);
    break;
  case(RUNTIME_SYSCALL_ATTEST_ENCLAVE):;
    uintptr_t copy_buffer_1_pa = kernel_va_to_pa(rt_copy_buffer_1);
    uintptr_t copy_buffer_2_pa = kernel_va_to_pa(rt_copy_buffer_2);

    copy_from_user((void*)rt_copy_buffer_2, (void*)arg1, arg2);

    ret = SBI_CALL_3(SBI_SM_ATTEST_ENCLAVE, copy_buffer_1_pa, copy_buffer_2_pa, arg2);

    /* TODO we consistently don't have report size when we need it */
    copy_to_user((void*)arg0, (void*)rt_copy_buffer_1, 2048);
    //print_strace("[ATTEST] p1 0x%p->0x%p p2 0x%p->0x%p sz %lx = %lu\r\n",arg0,arg0_trans,arg1,arg1_trans,arg2,ret);
    break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_CREATE):
	/*copy_string_from_user(region_name, (char*)arg0, REGION_NAME_MAX_LEN);*/
    ret = SBI_CALL_2(SBI_SM_ELASTICLAVE_CREATE, arg0, ret_uid_pa); // necessary to do the address translation
	// arg0: name
	// arg1: size
	// ret_val: paddr
	// ret_val2: vaddr

	//TODO: some checks necessary
	/*map_pages(ret_val2, ret_val, arg1, PAGE_MODE_USER_DATA); // also add to vma list*/
	// delay mapping
	// TODO: doesn't store any information about shared memory region inside rt for now
	// might consider in the future for performance
    copy_to_user((void*)arg1, &ret_uid, sizeof(ret_uid));

    break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_CHANGE):
	// arg0: uid
	// arg1: eid
	ret = SBI_CALL_2(SBI_SM_ELASTICLAVE_CHANGE, arg0, arg1); 
    break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_MAP):
	// arg0: uid
	// arg1: *vaddr
	ret = handle_elasticlave_map((uid_t)arg0, &ret_val);
	copy_to_user((void*)arg1, &ret_val, sizeof(ret_val));
	// TODO: return the size to user?
	break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_MAP_AT):
	// arg0: uid
    // arg1: va
	ret = handle_elasticlave_map_at((uid_t)arg0, arg1);
	break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_UNMAP):
	// arg0: vaddr
	ret = handle_elasticlave_unmap(arg0);
	break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_SHARE):
	ret = SBI_CALL_3(SBI_SM_ELASTICLAVE_SHARE, arg0, arg1, arg2);
	break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_TRANSFER):
	// arg0: uid
	// arg1: oeid
	ret = SBI_CALL_2(SBI_SM_ELASTICLAVE_TRANSFER, arg0, arg1);
	break;
  case(RUNTIME_SYSCALL_ELASTICLAVE_DESTROY):
	// arg0: uid
	ret = SBI_CALL_1(SBI_SM_ELASTICLAVE_DESTROY, arg0);
	if(!ret){
		struct vma* vma;
		for(vma = get_vma_by_uid((uid_t)arg0); vma != NULL;
				vma = get_vma_by_uid((uid_t)arg0)){
			remove_vma(vma);
		}
	}
	break;
  case(RUNTIME_SYSCALL_YIELD):
    ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 3);
	break;
  case(RUNTIME_SYSCALL_CALL_RETURN):
	ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, 4);
	break;
  case(RUNTIME_SYSCALL_GET_SHARED_BUFFER):
	copy_to_user((void*)arg0, &shared_buffer, sizeof(uintptr_t));
	copy_to_user((void*)arg1, &shared_buffer_size, sizeof(uintptr_t));
	break;
  case(RUNTIME_SYSCALL_SET_STATS_TARGET):
	set_stats_target((uintptr_t)arg0);
	break;
  case(RUNTIME_SYSCALL_PRINT_STATS):
	print_stats();
	break;
  case(RUNTIME_SYSCALL_GET_MY_ID):
	ret = eid;
	break;
  case(RUNTIME_SYSCALL_MA_HANDLER_REGISTER):
	register_mem_handler(arg0);
	break;
  case(RUNTIME_SYSCALL_MA_HANDLER_RETURN):
	store_result = 0;
	mem_handler_return(arg0, &ctx->regs);
	break;
#ifdef PERFORMANCE_MEASURE
  case(RUNTIME_SYSCALL_RPC_PRINT_STATS):
	rpc_stats_print();
    break;	
#endif
#ifdef LINUX_SYSCALL_WRAPPING
  case(SYS_futex):
	ret = linux_futex((int*)arg0, (int)arg1, (int)arg2, (void*)arg3,
			(int*)arg4, (int)arg5); // only use the first three arguments for now
	break;
  case(SYS_clock_gettime):
    ret = linux_clock_gettime((__clockid_t)arg0, (struct timespec*)arg1);
    break;

  case(SYS_getrandom):
    ret = linux_getrandom((void*)arg0, (size_t)arg1, (unsigned int)arg2);
    break;

  case(SYS_rt_sigprocmask):
    ret = linux_rt_sigprocmask((int)arg0, (const sigset_t*)arg1, (sigset_t*)arg2);
    break;

  case(SYS_getpid):
    ret = linux_getpid();
    break;

  case(SYS_uname):
    ret = linux_uname((void*) arg0);
    break;

  case(SYS_rt_sigaction):
    ret = linux_RET_ZERO_wrap(n);
    break;

  case(SYS_set_tid_address):
    ret = linux_set_tid_address((int*) arg0);
    break;

  case(SYS_brk):
    ret = syscall_brk((void*) arg0);
    break;

  case(SYS_mmap):
    ret = syscall_mmap((void*) arg0, (size_t)arg1, (int)arg2,
                       (int)arg3, (int)arg4, (__off_t)arg5);
    break;

  case(SYS_munmap):
    ret = syscall_munmap((void*) arg0, (size_t)arg1);
    break;

  case(SYS_exit):
  case(SYS_exit_group):
    print_strace("[runtime] exit or exit_group (%lu)\r\n",n);
    SBI_CALL_2(SBI_SM_EXIT_ENCLAVE, arg0, kernel_va_to_pa(&stats));
    break;
#endif /* LINUX_SYSCALL_WRAPPING */

#ifdef IO_SYSCALL_WRAPPING
  case(SYS_faccessat):
    print_strace("[runtime] accessat\r\n");
	break;
  case(SYS_mprotect):
    print_strace("[runtime] mprotect\r\n");
	break;
/*
prlimit64
execve
set_robust_list
rt_sigprocmask
pread64j
*/
  case(SYS_read):
    ret = io_syscall_read((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_write):
    ret = io_syscall_write((int)arg0, (void*)arg1, (size_t)arg2);
    break;
  case(SYS_writev):
    ret = io_syscall_writev((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_readv):
    ret = io_syscall_readv((int)arg0, (const struct iovec*)arg1, (int)arg2);
    break;
  case(SYS_openat):
    ret = io_syscall_openat((int)arg0, (char*)arg1, (int)arg2, (mode_t)arg3);
    break;
  case(SYS_unlinkat):
    ret = io_syscall_unlinkat((int)arg0, (char*)arg1, (int)arg2);
    break;
  case(SYS_fstatat):
    ret = io_syscall_fstatat((int)arg0, (char*)arg1, (struct stat*)arg2, (int)arg3);
    break;
  case(SYS_lseek):
    ret = io_syscall_lseek((int)arg0, (off_t)arg1, (int)arg2);
    break;
  case(SYS_ftruncate):
    ret = io_syscall_ftruncate((int)arg0, (off_t)arg1);
    break;
  case(SYS_sync):
    ret = io_syscall_sync();
    break;
  case(SYS_fsync):
    ret = io_syscall_fsync((int)arg0);
    break;
  case(SYS_close):
    ret = io_syscall_close((int)arg0);
    break;
#endif /* IO_SYSCALL_WRAPPING */

#ifdef FAST_IO_SYSCALL_WRAPPING
  case(FAST_SYSCALL_ADD_BUF):
	ret = fast_syscall_add_buf((uid_t)arg0);
	break;
  case(SYS_read + FAST_SYSCALL_OFFSET):
    ret = fast_io_syscall_read((int)arg0, (uid_t)arg1, arg2, (size_t)arg3);
    break;
  case(SYS_write + FAST_SYSCALL_OFFSET):
    ret = fast_io_syscall_write((int)arg0, (uid_t)arg1, arg2, (size_t)arg3);
    break;
  /*case(SYS_writev + FAST_SYSCALL_OFFSET):*/
    /*ret = fast_io_syscall_writev((int)arg0, (const struct iovec*)arg1, (int)arg2);*/
    /*break;*/
  /*case(SYS_readv + FAST_SYSCALL_OFFSET):*/
    /*ret = fast_io_syscall_readv((int)arg0, (const struct iovec*)arg1, (int)arg2);*/
    /*break;*/
#endif

  case(RUNTIME_SYSCALL_UNKNOWN):
  default:
    print_strace("[runtime] syscall %ld not implemented\r\n", (unsigned long) n);
    ret = -1;
    break;
  }

  /* store the result in the stack */
  if(store_result)
	  ctx->regs.a0 = ret;
  performance_check_start_with(&stats.stats_rt, start_cycle);
  performance_count(&stats.stats_rt);
  return (uintptr_t)&stats.stats_rt.total_cycle;
}
