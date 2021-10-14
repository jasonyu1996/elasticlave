//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "spinlock.h"
#include "sync.h"
#include "performance.h"
#include "edge_common.h"
#include "callnums.h"

#define N 1000


static int master_eid;
static uid_t uid;
static void* buf;
static struct shared_buffer* shared;
static int thread_count;
static int contention;

static int ocall_get_master_eid(){
    int retval;
    ocall(OCALL_GET_MASTER_EID, NULL, 0, &retval, sizeof(retval));
    return retval;
}

int ocall_get_contention(){
    int val;
    ocall(OCALL_GET_CONTENTION, NULL, 0, &val, sizeof(int));
    return val;
}

static uid_t icall_get_buffer(){
    uid_t ret = 0;
    icall_async((uintptr_t)master_eid, ICALL_GET_BUFFER, 
            NULL, 0,
            &ret, sizeof(uid_t));
    return ret;
}

static int ocall_get_thread_count(){
    int retval;
    ocall(OCALL_GET_THREAD_COUNT, NULL, 0, &retval, sizeof(retval));
    return retval;
}

int main(){
    int i, j;
    thread_count = ocall_get_thread_count();
    contention = ocall_get_contention();
    master_eid = ocall_get_master_eid();

    icall_connect((uintptr_t)master_eid);
    uid = icall_get_buffer();
    buf = elasticlave_map(uid);
    elasticlave_change(uid, 3);

    shared = (struct shared_buffer*)buf;
    barrier_t bar;
    bar.shared_data = &shared->bar_shared;
    bar_init(&bar, 0);

    barrier_wait(&bar, thread_count);

    for(i = 0; i < N; i ++){
        spinlock_acquire(&shared->spinlock);
        for(j = 0; j < contention; j ++);
        spinlock_release(&shared->spinlock);
    }

    barrier_wait(&bar, thread_count);

    elasticlave_change(uid, 0);

    _exit(0);

    return 0;
}

