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

char local_buffer_out[1 << 20];
char local_buffer_in[1 << 20];

static int server_eid;
static struct performance_stats stats;
static size_t record_size;


static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data;

static size_t __rpc_rw(uintptr_t addr, size_t size, void* in_buf, void* out_buf, int secure){
    struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
    struct write_args* write_args = (struct write_args*)args->args;
    write_args->addr = addr;
    write_args->size = size;

    memcpy(write_args->data, in_buf, size);

    args->ecall_num = RPC_RW;

    setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct write_args) + size);

    setup_parcel_target(&rpc_data.ecall_parcel, server_eid);
    rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);

    struct read_ret* read_ret = (struct read_ret*)rpc_data.retval.retval;

    memcpy(out_buf, read_ret->data, read_ret->size);

    return read_ret->size;
}

size_t rpc_rw(uintptr_t addr, size_t size, void* in_buf, void* out_buf){
    return __rpc_rw(addr, size, in_buf, out_buf, 0);
}

size_t rpc_secure_rw(uintptr_t addr, size_t size, void* in_buf, void* out_buf){
    return __rpc_rw(addr, size, in_buf, out_buf, 1);
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


int main(){
    record_size = ocall_get_record_size();

    server_eid = ocall_get_server_eid();


    rpc_client_init(0);

    performance_stats_init(&stats);
    //rpc_write(0, sizeof(int), &val);
    int i;
    for(i = 0; i < ROUND_N; i ++){
        performance_check_start(&stats);
        rpc_rw(0, record_size, local_buffer_out, local_buffer_in);
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


