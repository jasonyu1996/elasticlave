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
#include "performance.h"

#define BUFFER_SIZE (1<<20)
#define ROUND_N 1000

void *out_buf;
size_t record_size;
static int oeid;
static struct performance_stats stats;

int main(){
  edge_init();

  int eid = get_my_id();

  oeid = ocall_get_other_enclave();
  record_size = ocall_get_record_size();
  printf("Record size = %d\n", record_size);

  icall_init(oeid);

  out_buf = elasticlave_create("out_buf", BUFFER_SIZE, 1);
  shsc((uintptr_t)out_buf, oeid, 1, 1);

  icall_open_regions(oeid);

  performance_stats_init(&stats);
  
  int t;
  for(t = 0; t < ROUND_N; t ++){
	  performance_check_start(&stats);
	  icall_work_buffer(oeid, out_buf, record_size);
	  performance_check_end(&stats);
	  performance_count(&stats);
  }
  
  performance_stats_print(&stats, "Total");
  icall_print_stats(oeid);

  icall_end(oeid);

  return 0;
}

