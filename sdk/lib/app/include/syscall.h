//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include <stdint.h>
#include <stddef.h>
#include "types.h"

/* TODO We should be syncing these more explictly with the runtime
   defs */
#define SYSCALL_OCALL 1001
#define SYSCALL_SHAREDCOPY  1002
#define SYSCALL_ATTEST_ENCLAVE  1003
#define SYSCALL_EXIT  1101
#define SYSCALL_ELASTICLAVE_CHANGE	1004
#define SYSCALL_ELASTICLAVE_CREATE   1005
#define SYSCALL_ELASTICLAVE_MAP	1007
#define SYSCALL_ELASTICLAVE_MAP_AT	1024
#define SYSCALL_YIELD			1008
#define SYSCALL_GET_SHARED_BUFFER 1010
#define SYSCALL_CALL_RETURN		1011
#define SYSCALL_SET_STATS_TARGET 1012
#define SYSCALL_PRINT_STATS     1013
#define SYSCALL_SHCLAIM     1014
#define SYSCALL_SHSC     1015
#define SYSCALL_GET_MY_ID  1016
#define SYSCALL_RPC_PRINT_STATS  1017
#define SYSCALL_ELASTICLAVE_SHARE 1018
#define SYSCALL_ELASTICLAVE_UNMAP	1019
#define SYSCALL_ELASTICLAVE_TRANSFER 1020
#define SYSCALL_ELASTICLAVE_DESTROY 1021
#define SYSCALL_MA_HANDLER_REGISTER 1022
#define SYSCALL_MA_HANDLER_RETURN 1023

#define FAST_SYSCALL_ADD_BUF      499
#define FAST_SYSCALL_OFFSET 500

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4, arg5) ( {	\
	register uintptr_t a0 asm ("a0") = (uintptr_t)(arg0);	\
	register uintptr_t a1 asm ("a1") = (uintptr_t)(arg1);	\
	register uintptr_t a2 asm ("a2") = (uintptr_t)(arg2);	\
	register uintptr_t a3 asm ("a3") = (uintptr_t)(arg3);	\
	register uintptr_t a4 asm ("a4") = (uintptr_t)(arg4);	\
	register uintptr_t a5 asm ("a5") = (uintptr_t)(arg5);	\
	register uintptr_t a7 asm ("a7") = (uintptr_t)(which);	\
	asm volatile ("ecall"					\
		      : "+r" (a0)				\
		      : "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a7)\
		      : "memory");				\
	a0;							\
})


#define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0, 0)
#define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0, 0)
#define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0, 0)
#define SYSCALL_3(which, arg0, arg1, arg2) SYSCALL(which, arg0, arg1, arg2, 0, 0, 0)
#define SYSCALL_4(which, arg0, arg1, arg2, arg3) SYSCALL(which, arg0, arg1, arg2, arg3, 0, 0)
#define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) SYSCALL(which, arg0, arg1, arg2, arg3, arg4, 0)
#define SYSCALL_6(which, arg0, arg1, arg2, arg3, arg4, arg5) SYSCALL(which, arg0, arg1, arg2, arg3, arg4, arg5)

struct ma_context {
	uintptr_t epc;
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

typedef void (*mem_access_handler)(uintptr_t, uintptr_t, struct ma_context*);
typedef uint32_t uid_t;

#define UID_NULL 0


struct fast_syscall_buf {
  uid_t uid;
  void* data;
  size_t size;
};

int fast_syscall_create_buf(struct fast_syscall_buf* buf, size_t size);
int fast_syscall_destroy_buf(struct fast_syscall_buf* buf);

static inline uintptr_t fast_syscall(uintptr_t which, uintptr_t arg0, \
		uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {
	uintptr_t real_which = which + FAST_SYSCALL_OFFSET;
	return SYSCALL(real_which, arg0, arg1, arg2, arg3, arg4, arg5);
}

int copy_from_shared(void* dst,
		     uintptr_t offset, size_t data_len);

int ocall(unsigned long call_id,
	  void* data, size_t data_len,
	  void* return_buffer, size_t return_len);
uintptr_t untrusted_mmap();
int attest_enclave(void* report, void* data, size_t size);
uid_t elasticlave_create(uintptr_t size);
int elasticlave_change(uid_t uid, dyn_perm_t dyn_perm);
void* elasticlave_map(uid_t uid);
void* elasticlave_map_at(uid_t uid, uintptr_t va);
int elasticlave_unmap(void* addr);
int elasticlave_share(uid_t uid, 
		eid_t eid,
	   	st_perm_t st_perm);
int elasticlave_transfer(uid_t uid, eid_t eid);
int elasticlave_destroy(uid_t uid);
void register_mem_access_handler(mem_access_handler handler);

// futex
typedef struct {
	int lock;
} simple_futex_t;

void simple_futex_init(simple_futex_t* sfutex);
void simple_futex_lock(simple_futex_t* sfutex);
void simple_futex_unlock(simple_futex_t* sfutex);


#endif /* syscall.h */
