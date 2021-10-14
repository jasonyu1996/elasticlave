//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include "keystone.h"
#include "test_dev_key.h"
#include "edge_dispatch.h"
#include "rpc.h"
#include <sys/times.h>

#define OCALL_GET_THREAD_COUNT 7
#define OCALL_GET_SERVER_EID 8
#define OCALL_GET_CONTENTION 9

static Keystone* enclaves[16];
static int enclave_n;
static pid_t pid;
static void* shared_buffer;
static int thread_enclave[16];
static pthread_t threads[16];
static struct performance_stats run_stats[16], all_stats;
static DefaultEdgeCallDispatcher dispatchers[16];
static int contention;

static int get_server_eid_handler(Keystone* enclave, 
        void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t data_section = edge_call_data_ptr(shared_region);

    *(int*)data_section = (int)enclaves[0]->getSID();

    if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(int), shared_region)){
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    }
    else{
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return 0;
}

static int get_contention_handler(Keystone* enclave, 
        void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t data_section = edge_call_data_ptr(shared_region);

    *(int*)data_section = contention;

    if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(int), shared_region)){
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    }
    else{
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return 0;
}

static int get_thread_count_handler(Keystone* enclave, 
        void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t data_section = edge_call_data_ptr(shared_region);

    *(int*)data_section = enclave_n - 1;

    if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(int), shared_region)){
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    }
    else{
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return 0;
}

void* run_thread(void* args){
    int eid = *(int*)args;

    //cpu_set_t cpuset;
    //pthread_t thread = pthread_self();

    //CPU_ZERO(&cpuset);
    //CPU_SET(eid, &cpuset);

    //int r;
    //if(r = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)){
    //fprintf(stderr, "Set affinity failed (%d)!\n", r);
    //}

    performance_check_start(run_stats + eid);
    enclaves[eid]->run();
    performance_check_end(run_stats + eid);
}

int main(int argc, char* argv[])
{
    int self_timing = 0;
    int load_only = 0;

    size_t untrusted_size = 2*1024*1024;
    size_t freemem_size = 48*1024*1024;
    uintptr_t utm_ptr = (uintptr_t)DEFAULT_UNTRUSTED_PTR;

    if(argc < 3)
        return -1;

    enclave_n = atoi(argv[1]) + 1;
    contention = atoi(argv[2]);

    printf("Contention = %d, N = %d\n", contention, enclave_n - 1);
    fflush(stdout);

    Params params;

    params.setFreeMemSize(freemem_size);
    params.setUntrustedMem(utm_ptr, untrusted_size);

    int i;
    for(i = 0; i < enclave_n; i ++){
        enclaves[i] = new Keystone();
        dispatchers[i].register_call(OCALL_GET_SERVER_EID, get_server_eid_handler, NULL);
        dispatchers[i].register_call(OCALL_GET_THREAD_COUNT, get_thread_count_handler, NULL);
        dispatchers[i].register_call(OCALL_GET_CONTENTION, get_contention_handler, NULL);
        if(i){
            enclaves[i]->init("lock-spatial-c.eapp_riscv", "eyrie-rt", params);
            enclaves[i]->registerOcallDispatch(dispatchers + i);
            RPCClientInit(dispatchers + i, enclaves[i]);
        } else{
            enclaves[i]->init("lock-spatial-s.eapp_riscv", "eyrie-rt", params);
            enclaves[i]->registerOcallDispatch(dispatchers + i);
            RPCServerInit(dispatchers + i, enclaves[i]);
        }
    }

    struct tms tms_start, tms_end;

    clock_t clock_start = times(&tms_start);
    performance_check_start(&all_stats);
    for(i = 1; i < enclave_n; i ++){
        thread_enclave[i] = i;
        pthread_create(threads + i, NULL, run_thread, thread_enclave + i);
    }

    printf("The other threads started!\n"); fflush(stdout);

    thread_enclave[0] = 0;
    run_thread(thread_enclave);

    for(i = 1; i < enclave_n; i ++){
        pthread_join(threads[i], NULL);
    }
    performance_check_end(&all_stats);
    clock_t clock_end = times(&tms_end);

    for(i = 0; i < enclave_n; i ++){
        printf("******** Enclave %d ********\n", i);
        struct performance_stats enclave_stats = enclaves[i]->get_run_stats();
        performance_stats_print_total(&enclave_stats, "Enclave Running");
        performance_stats_print_total(run_stats + i, "Total Running");
        fflush(stdout);
    }
    printf("****** GLOBAL ******\n");
    performance_stats_print_total(&all_stats, "Total GLOBAL Running");

    unsigned long tot_time = (clock_end - clock_start);
    unsigned long sys_time = (tms_end.tms_stime - tms_start.tms_stime) + (tms_end.tms_cstime - tms_start.tms_cstime);
    unsigned long user_time = (tms_end.tms_utime - tms_start.tms_utime) + (tms_end.tms_cutime - tms_start.tms_cutime);
    unsigned long clock_per_sec = sysconf(_SC_CLK_TCK);
    printf("TIME = %.5f, U=%.5f, S=%.5f\n", (double)tot_time / clock_per_sec,
            (double)user_time / clock_per_sec, (double)sys_time / clock_per_sec);
    fflush(stdout);

    for(i = 0; i < enclave_n; i ++)
        delete enclaves[i];
    return 0;

}
