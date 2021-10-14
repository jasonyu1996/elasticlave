
#include<stdio.h>
#include<assert.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "rpc.h"
#include "performance.h"
#include "callnums.h"

#define SECURE_STORAGE_SIZE (1<<20)
#define ROUND_N 1000

static int server_eid;
static struct performance_stats stats;
static size_t record_size;
static char secure_storage[SECURE_STORAGE_SIZE];
static int num_workers;


static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data;


static size_t __rpc_write(uintptr_t addr, size_t size, void* buffer, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct write_args* write_args = (struct write_args*)args->args;
	write_args->addr = addr;
	write_args->size = size;

	memcpy(write_args->data, buffer, size);

	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct write_args) + size);
  setup_parcel_target(&rpc_data.ecall_parcel, server_eid);
	args->ecall_num = RPC_WRITE;

	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);

	struct write_ret* write_ret = (struct write_ret*)rpc_data.retval.retval;
	return write_ret->size;
}

size_t rpc_write(uintptr_t addr, size_t size, void* buffer){
	return __rpc_write(addr, size, buffer, 0);
}

size_t rpc_secure_write(uintptr_t addr, size_t size, void* buffer){
	return __rpc_write(addr, size, buffer, 1);
}

static size_t __rpc_read(uintptr_t addr, size_t size, void* buffer, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct read_args* read_args = (struct read_args*)args->args;
	read_args->addr = addr;
	read_args->size = size;

	args->ecall_num = RPC_READ;
	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct read_args));
  setup_parcel_target(&rpc_data.ecall_parcel, server_eid);

	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);

	struct read_ret* read_ret = (struct read_ret*)rpc_data.retval.retval;
	memcpy(buffer, read_ret->data, read_ret->size);
	return read_ret->size;
}

size_t rpc_read(uintptr_t addr, size_t size, void* buffer){
	return __rpc_read(addr, size, buffer, 0);
}

size_t rpc_secure_read(uintptr_t addr, size_t size, void* buffer){
	return __rpc_read(addr, size, buffer, 1);
}


static void __rpc_quit(int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);

	args->ecall_num = RPC_QUIT;
	setup_parcel_size(&rpc_data.ecall_parcel, 0);
  setup_parcel_target(&rpc_data.ecall_parcel, server_eid);

	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
}

void rpc_quit(){
	return __rpc_quit(0);
}

void rpc_quit_secure(){
	return __rpc_quit(1);
}

static eid_t ocall_get_server_eid(){
	uintptr_t eid;
	ocall(OCALL_GET_SERVER_EID, NULL, 0, &eid, sizeof(uintptr_t));
	return eid;
}

static size_t ocall_get_record_size(){
  size_t rs;
  ocall(OCALL_GET_RECORD_SIZE, NULL, 0, &rs, sizeof(size_t));
  return rs;
}

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

  rpc_write(0, write_size, secure_storage);

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
  record_size = ocall_get_record_size();

  server_eid = ocall_get_server_eid();


  rpc_client_init(0);
  num_workers = 1;
  rpc_server_init(0);
  rpc_server_handler_register(RPC_WRITE, rpc_write_handler);
  rpc_server_handler_register(RPC_QUIT, rpc_quit_handler);

	performance_stats_init(&stats);

  rpc_serve();
	//rpc_write(0, sizeof(int), &val);
	/*printf(" ==== Proxy ==== \n");*/
	/*print_stats();*/
	/*performance_stats_print(&stats, "Total");*/
	/*rpc_stats_print(RPC_WRITE);*/
  rpc_quit();


  _exit(0);

	return 0;
}

