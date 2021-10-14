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
#include "edge_common.h"
#include "callnums.h"

#define BUFFER_SIZE (1<<20)


static uid_t in_uid;
static void *in_buf;
static size_t in_buf_size;
static size_t record_size;
static char secure_storage[BUFFER_SIZE];


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

  if(!edge_call){
  }
  
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return 0;
}

static int quit_handler(int eid, void* buffer, struct shared_region* shared_region)
{
	struct edge_call* edge_call = (struct edge_call*)buffer;
	edge_call->return_data.call_status = CALL_STATUS_OK;

	icall_server_stop();

	return 0;
}



//void EAPP_ENTRY eapp_entry(uintptr_t eid){
int main(){
  record_size = ocall_get_record_size();

	icall_server_init();

	icall_server_register_handler(ICALL_QUIT, quit_handler);
  icall_server_register_handler(ICALL_WORK_BUFFER, work_buffer_handler);
  icall_server_register_handler(ICALL_SET_BUFFER, set_buffer_handler);


	icall_server_launch_async();

  printf("Server about to exit!\n");


  _exit(0);

  return 0;
}

