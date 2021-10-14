//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include<stdio.h>
#include "edge_common.h"
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "performance.h"
#include "rpc.h"
#include "callnums.h"

#define N 1000

static int server_eid;
static struct performance_stats stats;
static size_t record_size;

static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data;

/*int ocall_wait4(enclave_t* enclave){*/
/*int ret_val;*/

/*ocall(OCALL_WAIT4, &enclave->sid, sizeof(unsigned long), &ret_val, sizeof(ret_val));*/

/*return ret_val;*/
/*}*/

static int __rpc_lock_access(unsigned int lock_index, 
        int to_lock, int secure){
    struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
    struct lock_args* lock_args = (struct lock_args*)args->args;
    lock_args->to_lock = to_lock;
    lock_args->lock_index = lock_index;

    setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct lock_args));
    setup_parcel_target(&rpc_data.ecall_parcel, server_eid);
    args->ecall_num = RPC_LOCK;

    rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
    struct lock_ret* lock_ret = (struct lock_ret*)rpc_data.retval.retval;
    return lock_ret->success;
}

static int rpc_lock(unsigned int lock_index){
    return __rpc_lock_access(lock_index, 1, 0);
}

static int rpc_secure_lock(unsigned int lock_index){
    return __rpc_lock_access(lock_index, 1, 1);
}

static int rpc_unlock(unsigned int lock_index){
    return __rpc_lock_access(lock_index, 0, 0);
}

static int rpc_secure_unlock(unsigned int lock_index){
    return __rpc_lock_access(lock_index, 0, 1);
}

static void __rpc_quit(int secure){
    struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);

    args->ecall_num = RPC_QUIT;
    setup_parcel_size(&rpc_data.ecall_parcel, 0);
    setup_parcel_target(&rpc_data.ecall_parcel, server_eid);

    rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
}

static void rpc_quit(){
    return __rpc_quit(0);
}

static void rpc_quit_secure(){
    return __rpc_quit(1);
}

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

static size_t rpc_write(uintptr_t addr, size_t size, void* buffer){
    return __rpc_write(addr, size, buffer, 0);
}

static size_t rpc_secure_write(uintptr_t addr, size_t size, void* buffer){
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

static size_t rpc_read(uintptr_t addr, size_t size, void* buffer){
    return __rpc_read(addr, size, buffer, 0);
}

static size_t rpc_secure_read(uintptr_t addr, size_t size, void* buffer){
    return __rpc_read(addr, size, buffer, 1);
}

static eid_t ocall_get_server_eid(){
    uintptr_t eid;
    ocall(OCALL_GET_SERVER_EID, NULL, 0, &eid, sizeof(uintptr_t));
    return eid;
}

static int ocall_get_thread_count(){
    int ret;
    ocall(OCALL_GET_THREAD_COUNT, NULL, 0, &ret, sizeof(int));
    return ret;
}

static int ocall_get_contention(){
    int ret;
    ocall(OCALL_GET_CONTENTION, NULL, 0, &ret, sizeof(int));
    return ret;
}

static int locpass = 0;

#define BARRIER_LOCK 0
#define P_COUNTER 0
#define P_PASS sizeof(int)

inline static void barrier_wait(int n){
    int c_counter;
    locpass ^= 1;
    while(!rpc_lock(BARRIER_LOCK));
    rpc_read(P_COUNTER, sizeof(int), &c_counter);
    ++ c_counter;
    if(c_counter == n) {
        c_counter = 0;
        rpc_write(P_COUNTER, sizeof(int), &c_counter);
        rpc_write(P_PASS, sizeof(int), &locpass);
    } else
        rpc_write(P_COUNTER, sizeof(int), &c_counter);
    rpc_unlock(BARRIER_LOCK);

    int lpass;
    do{
        rpc_read(P_PASS, sizeof(int), &lpass);
    } while(lpass != locpass);
}

int main(){
    server_eid = ocall_get_server_eid();
    int n = ocall_get_thread_count();
    int CONTENTION = ocall_get_contention();

    rpc_client_init(0);

    struct performance_stats stats;
    performance_stats_init(&stats);


    int i, j;

    barrier_wait(n);
    performance_check_start(&stats);


    for(i = 0; i < N; i ++){
        while(!rpc_lock(1));
        for(j = 0; j < CONTENTION; j ++);
        rpc_unlock(1);
    }

    // waiting for the other enclave to stop
    barrier_wait(n);
    performance_check_end(&stats);

    printf("******* EAPP ********\n");
    performance_stats_print_total(&stats, "Total Running");

    rpc_quit();
    _exit(0);

    return 0;
}

