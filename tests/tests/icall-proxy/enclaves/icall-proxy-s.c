//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include<stdio.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"
#include "edge_dispatch_inter.h"
#include "performance.h"

void *out_buf;
size_t out_buf_size;
size_t record_size;

static struct performance_stats interface_stats, args_copy_stats, retval_copy_stats;

void open_regions_handler(int eid, void* buffer, struct shared_region* shared_region){
  struct edge_call* edge_call = (struct edge_call*)buffer;

  out_buf = elasticlave_map(eid, "out_buf", &out_buf_size);
  shclaim((uintptr_t)out_buf, eid, 1, 1);

  edge_call->return_data.call_status = CALL_STATUS_OK;
}

void work_buffer_handler(int eid, void* buffer, struct shared_region* shared_region){
  struct edge_call* edge_call = (struct edge_call*)buffer;

  performance_check_start(&interface_stats);
  shclaim((uintptr_t)out_buf, eid, 3, 1);

  // dumb

  shclaim((uintptr_t)out_buf, eid, 1, 1);
  performance_check_end(&interface_stats);
  performance_count(&interface_stats);
  
  edge_call->return_data.call_status = CALL_STATUS_OK;
}

void print_stats_handler(int eid, void* buffer, struct shared_region* shared_region){
	struct edge_call* edge_call = (struct edge_call*)buffer;
	performance_stats_print(&interface_stats, "Server interface");
	performance_stats_print(&args_copy_stats, "Server args copy");
	performance_stats_print(&retval_copy_stats, "Server retval copy");
	edge_call->return_data.call_status = CALL_STATUS_OK;
}

void end_handler(int eid, void* buffer, struct shared_region* shared_region)
{
  struct edge_call* edge_call = (struct edge_call*)buffer;
  icall_server_stop(); 
  edge_call->return_data.call_status = CALL_STATUS_OK;
  return;
}


//void EAPP_ENTRY eapp_entry(uintptr_t eid){
int main(){
  edge_init();

  performance_stats_init(&interface_stats);
  performance_stats_init(&args_copy_stats);
  performance_stats_init(&retval_copy_stats);

  int eid = get_my_id();

  icall_server_init((unsigned long)eid);

  int oeid = ocall_get_other_enclave();
  record_size = ocall_get_record_size();

  icall_server_connect(oeid);
  icall_server_register_handler(ICALL_OPEN_REGIONS, open_regions_handler);
  icall_server_register_handler(ICALL_WORK_BUFFER, work_buffer_handler);
  icall_server_register_handler(ICALL_PRINT_STATS, print_stats_handler);
  icall_server_register_handler(ICALL_END, end_handler);

  printf("Server launched\n");
  icall_server_launch_async();

  return 0;
}

