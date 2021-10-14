//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h" #include "string.h"
#include "syscall.h"
#include "edge_wrapper.h"
#include "edge_call.h"
#include "edge_dispatch_inter.h"
#include "performance.h"
#include<stdio.h>

static struct performance_stats interface_stats, args_copy_stats, retval_copy_stats;

void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
	performance_stats_init(&interface_stats);
	performance_stats_init(&args_copy_stats);
   	performance_stats_init(&retval_copy_stats);
}

#define ICALL_OPEN_REGIONS 1
#define ICALL_WORK_BUFFER 2
#define OCALL_GET_RECORD_SIZE 4
#define OCALL_GET_OTHER_ENCLAVE 5
#define ICALL_END 3
#define ICALL_PRINT_STATS 4

int ocall_get_other_enclave(){
   int retval;
   ocall(OCALL_GET_OTHER_ENCLAVE, NULL, 0, &retval, sizeof(retval));
   return retval;
}

size_t ocall_get_record_size(){
	size_t retval;
	ocall(OCALL_GET_RECORD_SIZE, NULL, 0, &retval, sizeof(retval));
	return retval;
}

void icall_open_regions(uintptr_t enclave_id){
   icall_async(enclave_id, ICALL_OPEN_REGIONS, &enclave_id, sizeof(enclave_id), NULL, 0);
}

void icall_work_buffer(uintptr_t enclave_id, void* out_buf, size_t record_size){
	performance_check_start(&interface_stats);
	shsc((uintptr_t)out_buf, enclave_id, 3, 0);
	performance_check_end(&interface_stats);

	icall_async(enclave_id, ICALL_WORK_BUFFER, NULL, 0, NULL, 0);

	performance_check_start(&interface_stats);
	shsc((uintptr_t)out_buf, enclave_id, 1, 1);
	performance_check_end(&interface_stats);

	performance_count(&interface_stats);
}

void icall_end(uintptr_t enclave_id){
	icall_async(enclave_id, ICALL_END, NULL, 0, NULL, 0);
}

void icall_print_stats(uintptr_t enclave_id){
	performance_stats_print(&interface_stats, "Client interface");
	performance_stats_print(&args_copy_stats, "Client args copy");
	performance_stats_print(&retval_copy_stats, "Client retval copy");
	icall_async(enclave_id, ICALL_PRINT_STATS, NULL, 0, NULL, 0);
	icall_print_client_stats();
}

void icall_init(uintptr_t enclave_id){
  icall_connect(enclave_id);
  icall_set_target(ICALL_WORK_BUFFER);
}

