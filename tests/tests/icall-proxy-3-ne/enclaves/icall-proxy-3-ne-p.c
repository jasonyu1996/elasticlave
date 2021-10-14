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
#include "icall.h"
#include "callnums.h"

#define BUFFER_SIZE (1<<20)
#define ROUND_N 1000

uid_t in_uid, out_uid;
void *in_buf, *out_buf;
size_t in_buf_size;
size_t record_size;

static struct performance_stats interface_stats, args_copy_stats, retval_copy_stats;
static int server_eid, client_eid;
static char secure_storage[BUFFER_SIZE];

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
  memcpy(out_buf, secure_storage, record_size);
  icall_async((uintptr_t)server_eid, ICALL_WORK_BUFFER, NULL, 0, NULL, 0);
}

static size_t ocall_get_record_size(){
  size_t rs;
  ocall(OCALL_GET_RECORD_SIZE, NULL, 0, &rs, sizeof(size_t));
  return rs;
}

static int set_buffer_handler(int eid, void* buffer, struct shared_region* shared_region){
	struct edge_call* edge_call = (struct edge_call*)buffer;

	uintptr_t call_args;
	size_t args_len;
	if(edge_call_args_ptr(edge_call, &call_args, &args_len, shared_region) != 0){
		edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
		return;
	}

  struct buffer_info* pk = (struct buffer_info*)call_args;
  if(!pk){
  }
  uid_t uid = pk->uid;
  client_eid = eid;
  void* buf = elasticlave_map(uid);
  if(!buf)
    goto set_buffer_failed;
  if(elasticlave_change(uid, 1))
    goto set_buffer_type_failed;

  switch(pk->buffer_type){
    case BUFFER_IN:
      in_uid = uid;
      in_buf = buf;
      break;
    default:
      printf("Set buffer failed with type %d\n", pk->buffer_type);
      goto set_buffer_type_failed;
  }

  return 0;

set_buffer_type_failed:
  elasticlave_unmap(buf);
set_buffer_failed:
  return 0;
}

static int work_buffer_handler(int eid, void* buffer, struct shared_region* shared_region){
  struct edge_call* edge_call = (struct edge_call*)buffer;

  memcpy(secure_storage, in_buf, record_size);

  icall_work_buffer();

  if(!edge_call){
  }
  
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return 0;
}

static int quit_handler(int eid, void* buffer, struct shared_region* shared_region)
{
	struct edge_call* edge_call = (struct edge_call*)buffer;
	edge_call->return_data.call_status = CALL_STATUS_OK;

  icall_quit();  

	icall_server_stop();

	return 0;
}

static uid_t ocall_get_server_eid(){
	uintptr_t uid;
	ocall(OCALL_GET_SERVER_EID, NULL, 0, &uid, sizeof(uintptr_t));
	return uid;
}


//void EAPP_ENTRY eapp_entry(uintptr_t eid){
int main(){
  record_size = ocall_get_record_size();

	server_eid = ocall_get_server_eid();
	icall_connect((uintptr_t)server_eid);

  out_uid = elasticlave_create(BUFFER_SIZE);
  out_buf = elasticlave_map(out_uid);
  elasticlave_change(out_uid, 3);
  elasticlave_share(out_uid, server_eid, 1);

  icall_set_buffer(out_uid, BUFFER_IN);
	icall_server_init();

	icall_server_register_handler(ICALL_QUIT, quit_handler);
  icall_server_register_handler(ICALL_WORK_BUFFER, work_buffer_handler);
  icall_server_register_handler(ICALL_SET_BUFFER, set_buffer_handler);


	icall_server_launch_async();

  printf("Proxy about to exit!\n");


  _exit(0);

  return 0;
}

