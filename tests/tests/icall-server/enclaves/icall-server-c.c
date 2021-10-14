//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include<stdio.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "performance.h"
#include "callnums.h"

#define BUFFER_SIZE (1<<20)
#define ROUND_N 1000


static uintptr_t server_eid;
static void *in_buf, *out_buf;
static uid_t in_uid, out_uid;
static struct performance_stats stats;
static size_t record_size;

static uid_t ocall_get_server_eid(){
	uintptr_t uid;
	ocall(OCALL_GET_SERVER_EID, NULL, 0, &uid, sizeof(uintptr_t));
	return uid;
}

static size_t ocall_get_record_size(){
  size_t rs;
  ocall(OCALL_GET_RECORD_SIZE, NULL, 0, &rs, sizeof(size_t));
  return rs;
}

static void icall_quit(){
	icall_async((uintptr_t)server_eid, ICALL_QUIT, NULL, 0, NULL, 0);
}

static void icall_set_buffer(uid_t uid, int buffer_type){
  struct buffer_info pk = {
    .uid = uid,
    .buffer_type = buffer_type
  };
  icall_async((uintptr_t)server_eid, ICALL_SET_BUFFER, 
      &pk, sizeof(struct buffer_info),
      NULL, 0);
}

static void icall_work_buffer(){
  elasticlave_change(in_uid, 0);
  elasticlave_change(out_uid, 0);
  icall_async((uintptr_t)server_eid, ICALL_WORK_BUFFER, NULL, 0, NULL, 0);
  elasticlave_change(out_uid, 11);
  elasticlave_change(in_uid, 11);
}

int main(){
	server_eid = ocall_get_server_eid();
	icall_connect((uintptr_t)server_eid);

  record_size = ocall_get_record_size();

  in_uid = elasticlave_create(BUFFER_SIZE);
  out_uid = elasticlave_create(BUFFER_SIZE);
  
  in_buf = elasticlave_map(in_uid);
  out_buf = elasticlave_map(out_uid);

  elasticlave_change(in_uid, 11);
  elasticlave_change(out_uid, 11);

  elasticlave_share(in_uid, server_eid, 11);
  elasticlave_share(out_uid, server_eid, 9); // exclusive read-only

  icall_set_buffer(in_uid, BUFFER_IN);
  icall_set_buffer(out_uid, BUFFER_OUT);


  performance_stats_init(&stats);
  
  int t;
  for(t = 0; t < ROUND_N; t ++){
	  performance_check_start(&stats);
	  icall_work_buffer();
	  performance_check_end(&stats);
	  performance_count(&stats);
  }
  
  /*performance_stats_print(&stats, "Total");*/
  /*icall_print_stats(oeid);*/

	icall_quit();

  printf("Client about to exit!\n");
  _exit(0);

  return 0;
}

