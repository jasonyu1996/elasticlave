//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#include "printf.h"
#include "regs.h"
#include "edge_syscall.h"
#include "vm.h"

// syscall without copy
#define RUNTIME_SYSCALL_UNKNOWN         1000
#define RUNTIME_SYSCALL_OCALL           1001
#define RUNTIME_SYSCALL_SHAREDCOPY      1002
#define RUNTIME_SYSCALL_ATTEST_ENCLAVE  1003
#define RUNTIME_SYSCALL_ELASTICLAVE_CHANGE           1004
#define RUNTIME_SYSCALL_ELASTICLAVE_CREATE        1005
#define RUNTIME_SYSCALL_ELASTICLAVE_MAP     1007
#define RUNTIME_SYSCALL_ELASTICLAVE_MAP_AT     1024
#define RUNTIME_SYSCALL_YIELD			1008
#define RUNTIME_SYSCALL_GET_SHARED_BUFFER 1010
#define RUNTIME_SYSCALL_CALL_RETURN     1011
#define RUNTIME_SYSCALL_SET_STATS_TARGET 1012
#define RUNTIME_SYSCALL_PRINT_STATS     1013
#define RUNTIME_SYSCALL_GET_MY_ID		1016
#define RUNTIME_SYSCALL_RPC_PRINT_STATS		1017
#define RUNTIME_SYSCALL_ELASTICLAVE_SHARE		1018
#define RUNTIME_SYSCALL_ELASTICLAVE_UNMAP     1019
#define RUNTIME_SYSCALL_ELASTICLAVE_TRANSFER     1020
#define RUNTIME_SYSCALL_ELASTICLAVE_DESTROY     1021
#define RUNTIME_SYSCALL_MA_HANDLER_REGISTER		1022
#define RUNTIME_SYSCALL_MA_HANDLER_RETURN		1023
#define RUNTIME_SYSCALL_EXIT            1101

uintptr_t handle_syscall(struct encl_ctx* ctx, unsigned long start_cycle);
void init_edge_internals(void);
uintptr_t dispatch_edgecall_syscall(struct edge_syscall* syscall_data_ptr,
                                    size_t data_len);
uintptr_t dispatch_edgecall_ocall( unsigned long call_id,
				   void* data, size_t data_len,
				   void* return_buffer, size_t return_len, int in_rt);

// Define this to enable printing of a large amount of syscall information
//#define INTERNAL_STRACE 1

#ifdef INTERNAL_STRACE
#define print_strace printf
#else
#define print_strace(...)
#endif

#endif /* syscall.h */
