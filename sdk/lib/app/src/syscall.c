//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

#include "syscall.h"
#include "edge_call.h"
#include "ks_string.h"
#include "performance.h"
#include "types.h"

#define SYS_futex 98
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

/* this implementes basic system calls for the enclave */

int ocall(unsigned long call_id,
		void* data, size_t data_len,
		void* return_buffer, size_t return_len){
	return SYSCALL_5(SYSCALL_OCALL, call_id, data, data_len, return_buffer, return_len);
}

int copy_from_shared(void* dst,
		uintptr_t offset, size_t data_len){
	return SYSCALL_3(SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

#define FAST_SYSCALL_BUF_SIZE 

int fast_syscall_create_buf(struct fast_syscall_buf* buf, size_t size){
  int ret;
  buf->uid = elasticlave_create(size);
  if(!buf->uid){
    goto fast_syscall_create_buf_fail;
  }
  buf->data = elasticlave_map(buf->uid);
  if(!buf->data){
    goto fast_syscall_create_buf_map_fail;
  }
  if(elasticlave_change(buf->uid, 11)){
    goto fast_syscall_create_buf_change_fail;
  }
  if(elasticlave_share(buf->uid, 0, 11)){
    goto fast_syscall_create_buf_change_fail; // share with host
  }
  ret = SYSCALL_1(FAST_SYSCALL_ADD_BUF, (uintptr_t)buf->uid);
  if(ret){
    goto fast_syscall_create_buf_change_fail;
  }
  buf->size = size;

  return 0;
fast_syscall_create_buf_change_fail:
  elasticlave_unmap(buf->data);
  buf->data = NULL;
fast_syscall_create_buf_map_fail:
  elasticlave_destroy(buf->uid);
  buf->uid = UID_NULL;
fast_syscall_create_buf_fail:
  return -1;
}

int fast_syscall_destroy_buf(struct fast_syscall_buf* buf){
  return 0;
}

int attest_enclave(void* report, void* data, size_t size)
{
	return SYSCALL_3(SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

uid_t elasticlave_create(uintptr_t size){
	uid_t uid;
	uid_t* uid_ptr = &uid;
	int ret = SYSCALL_2(SYSCALL_ELASTICLAVE_CREATE, size, uid_ptr);
	if(ret)
		uid = UID_NULL;
	return uid;
}

int elasticlave_change(uid_t uid, dyn_perm_t dyn_perm){
	return SYSCALL_2(SYSCALL_ELASTICLAVE_CHANGE, uid, dyn_perm);
}

int print_rt_rpc_stats(){
	return SYSCALL_0(SYSCALL_RPC_PRINT_STATS);
}

void* elasticlave_map(uid_t uid){
	uintptr_t vaddr;
	uintptr_t* vaddr_ptr = &vaddr;
	int ret = SYSCALL_2(SYSCALL_ELASTICLAVE_MAP, uid, vaddr_ptr);
	if(ret)
		vaddr = 0;
	return (void*)vaddr;
}


void* elasticlave_map_at(uid_t uid, uintptr_t va){
	int ret = SYSCALL_2(SYSCALL_ELASTICLAVE_MAP_AT, uid, va);
	if(ret)
        return NULL;
    return (void*)va;
}


int elasticlave_unmap(void* addr){
	return SYSCALL_1(SYSCALL_ELASTICLAVE_UNMAP, (uintptr_t)addr);
}

int elasticlave_share(uid_t uid, eid_t eid, st_perm_t st_perm){
	return SYSCALL_3(SYSCALL_ELASTICLAVE_SHARE, uid, eid, st_perm);
}

int elasticlave_transfer(uid_t uid, eid_t eid){
	return SYSCALL_2(SYSCALL_ELASTICLAVE_TRANSFER, uid, eid);
}

int elasticlave_destroy(uid_t uid){
	return SYSCALL_1(SYSCALL_ELASTICLAVE_DESTROY, uid);
}

static mem_access_handler ma_handler;

static void __internal_ma_handler(uintptr_t event_no, uintptr_t uid, struct ma_context* ctx) __attribute__((noreturn));

static void __internal_ma_handler(uintptr_t event_no, uintptr_t uid, struct ma_context* ctx){
	ma_handler(event_no, uid, ctx);
	SYSCALL_1(SYSCALL_MA_HANDLER_RETURN, ctx);

	// should not be here
}

void register_mem_access_handler(mem_access_handler handler){
	ma_handler = handler;
	SYSCALL_1(SYSCALL_MA_HANDLER_REGISTER, __internal_ma_handler);
}


#define mb() asm volatile ("fence" ::: "memory")
#define atomic_set(ptr, val) (*(volatile typeof(*(ptr)) *)(ptr) = val)
#define atomic_read(ptr) (*(volatile typeof(*(ptr)) *)(ptr))

#ifdef __riscv_atomic
# define atomic_add(ptr, inc) __sync_fetch_and_add(ptr, inc)
# define atomic_or(ptr, inc) __sync_fetch_and_or(ptr, inc)
# define atomic_swap(ptr, swp) __sync_lock_test_and_set(ptr, swp)
# define atomic_cas(ptr, cmp, swp) __sync_val_compare_and_swap(ptr, cmp, swp)
#else
# define atomic_binop(ptr, inc, op) ({     typeof(*(ptr)) res = atomic_read(ptr);   atomic_set(ptr, op);   res; })
# define atomic_add(ptr, inc) atomic_binop(ptr, inc, res + (inc))
# define atomic_or(ptr, inc) atomic_binop(ptr, inc, res | (inc))
# define atomic_swap(ptr, inc) atomic_binop(ptr, inc, (inc))
# define atomic_cas(ptr, cmp, swp) ({  typeof(*(ptr)) res = *(volatile typeof(*(ptr)) *)(ptr);   if (res == (cmp)) *(volatile typeof(ptr))(ptr) = (swp);     res; })
#endif

#define LOCK_FREE 0
#define LOCK_TAKEN 1
#define LOCK_CONTENDED 2

static inline long futex_wait(int* uaddr, int val){
	SYSCALL_6(SYS_futex, uaddr, FUTEX_WAIT, val, 0, 0, 0);
}

static inline long futex_wake(int* uaddr, int num){
	SYSCALL_6(SYS_futex, uaddr, FUTEX_WAKE, num, 0, 0, 0);
}

void simple_futex_init(simple_futex_t* sfutex){
	sfutex->lock = LOCK_FREE;
}

#define FUTEX_TRYLOCK_N 10

void simple_futex_lock(simple_futex_t* sfutex){
	int i;
	for(i = 0; i < FUTEX_TRYLOCK_N; i ++){
		mb();
		if(atomic_cas(&sfutex->lock, LOCK_FREE, LOCK_TAKEN) == LOCK_FREE)
			return;
	}
	while(atomic_swap(&sfutex->lock, LOCK_CONTENDED) != LOCK_FREE){
		mb();
		futex_wait(&sfutex->lock, LOCK_CONTENDED);
	}
}

void simple_futex_unlock(simple_futex_t* sfutex){
	int old_lock = atomic_swap(&sfutex->lock, LOCK_FREE);
	mb();
	if(old_lock == LOCK_CONTENDED)
		futex_wake(&sfutex->lock, 1);
}

// futex


