
#include<stdio.h>
#include<assert.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "rpc.h"
#include "performance.h"
#include "callnums.h"

#define ROUND_N 1000

char local_buffer[1 << 20];

static int proxy_eid;
static struct performance_stats stats;
static size_t record_size;


static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data;

static size_t __rpc_write(uintptr_t addr, size_t size, void* buffer, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct write_args* write_args = (struct write_args*)args->args;
	write_args->addr = addr;
	write_args->size = size;

	memcpy(write_args->data, buffer, size);

	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct write_args) + size);
  setup_parcel_target(&rpc_data.ecall_parcel, proxy_eid);
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


static void __rpc_quit(int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);

	args->ecall_num = RPC_QUIT;
	setup_parcel_size(&rpc_data.ecall_parcel, 0);
  setup_parcel_target(&rpc_data.ecall_parcel, proxy_eid);

	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
}

void rpc_quit(){
	return __rpc_quit(0);
}

void rpc_quit_secure(){
	return __rpc_quit(1);
}

static eid_t ocall_get_proxy_eid(){
	uintptr_t eid;
	ocall(OCALL_GET_PROXY_EID, NULL, 0, &eid, sizeof(uintptr_t));
	return eid;
}

static size_t ocall_get_record_size(){
  size_t rs;
  ocall(OCALL_GET_RECORD_SIZE, NULL, 0, &rs, sizeof(size_t));
  return rs;
}

int main(){
  record_size = ocall_get_record_size();

  proxy_eid = ocall_get_proxy_eid();


  rpc_client_init(0);

	performance_stats_init(&stats);
	//rpc_write(0, sizeof(int), &val);
	int i;
	for(i = 0; i < ROUND_N; i ++){
		performance_check_start(&stats);
		rpc_write(0, record_size, local_buffer);
		performance_check_end(&stats);
		performance_count(&stats);
	}

	/*printf(" ==== Client ==== \n");*/
	/*print_stats();*/
	/*performance_stats_print(&stats, "Total");*/
	/*rpc_stats_print(RPC_WRITE);*/

  rpc_quit();
  _exit(0);

	return 0;
}

