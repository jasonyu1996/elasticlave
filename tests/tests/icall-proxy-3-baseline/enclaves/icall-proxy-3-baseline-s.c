//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include<stdio.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "rpc.h"
#include "callnums.h"

#define SECURE_STORAGE_SIZE (1<<20)

static int num_workers;
static size_t record_size;
static char secure_storage[SECURE_STORAGE_SIZE];

static size_t rpc_write_handler(int source, void* args_data, size_t args_size, 
    void* ret_data, size_t ret_size_lim, int* quit){
  *quit = 0;
	if(sizeof(struct write_args) > args_size || sizeof(struct write_ret) > ret_size_lim)
		return 0;
	struct write_args* write_args = (struct write_args*)args_data;
	uintptr_t addr = write_args->addr;
	size_t size = write_args->size;

	size_t write_size;
	if(addr >= SECURE_STORAGE_SIZE || (addr + (uintptr_t)size) >= SECURE_STORAGE_SIZE ||
		size + sizeof(struct write_ret) > args_size)
		write_size = 0;
	else{
		write_size = size;
	}

	struct write_ret* write_ret = (struct write_ret*)ret_data;
	write_ret->size = write_size;
	memcpy(secure_storage + addr, write_args->data, write_size);

	return sizeof(struct write_ret);
}


static size_t rpc_quit_handler(int source, void* args_data, size_t args_size,
    void* ret_data, size_t ret_size_lim, int* quit){
	-- num_workers;
  if(!num_workers)
    *quit = 1;
  else
    *quit = 0;
	return 0;
}

int main(){
  num_workers = 1;
  rpc_server_init(0);
  rpc_server_handler_register(RPC_WRITE, rpc_write_handler);
  rpc_server_handler_register(RPC_QUIT, rpc_quit_handler);

  rpc_serve();


  _exit(0);
	return 0;
}

