//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include<stdio.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "spinlock.h"
#include "performance.h"
#include "sync.h"
#include "edge_common.h"
#include "callnums.h"

#define N 1000
#define BUFFER_SIZE (4096*8)


static int thread_count, connected_count;
static uid_t uid;
static void* buf;
static struct shared_buffer* shared;
static int contention;

static int ocall_get_thread_count(){
    int retval;
    ocall(OCALL_GET_THREAD_COUNT, NULL, 0, &retval, sizeof(retval));
    return retval;
}

static int get_buffer_handler(int eid, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t data_section = edge_call_data_ptr(shared_region);

    *(uid_t*)data_section = (uid_t)uid;
    if(edge_call_setup_ret(edge_call,
                (void*)data_section, sizeof(uid_t), shared_region)){
        edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    } else{
        edge_call->return_data.call_status = CALL_STATUS_OK;
        elasticlave_share(uid, eid, 3);
        ++ connected_count;
        if(connected_count == thread_count){
            icall_server_stop();
        }
    }
    return 0;
}


int ocall_get_contention(){
    int val;
    ocall(OCALL_GET_CONTENTION, NULL, 0, &val, sizeof(int));
    return val;
}

int main(){
    int i, j;

    thread_count = ocall_get_thread_count();
    connected_count = 1;

    uid = elasticlave_create(BUFFER_SIZE);
    buf = elasticlave_map(uid);
    elasticlave_change(uid, 3);

    shared = (struct shared_buffer*)buf;
    contention = ocall_get_contention();
    barrier_t bar;
    bar.shared_data = &shared->bar_shared;
    bar_init(&bar, 1);
    spinlock_init(&shared->spinlock);

    struct performance_stats stats;
    performance_stats_init(&stats);

    icall_server_init();
    icall_server_register_handler(ICALL_GET_BUFFER, get_buffer_handler);
    icall_server_expect_conn(thread_count - 1);
    icall_server_launch_async();

    barrier_wait(&bar, thread_count);
    performance_check_start(&stats);

    for(i = 0; i < N; i ++){
        spinlock_acquire(&shared->spinlock);
        for(j = 0; j < contention; j ++);
        spinlock_release(&shared->spinlock);
    }

    // waiting for the other enclave to stop
    barrier_wait(&bar, thread_count);
    performance_check_end(&stats);

    printf("******* EAPP ********\n");
    performance_stats_print_total(&stats, "Total Running");

    _exit(0);

    return 0;
}

