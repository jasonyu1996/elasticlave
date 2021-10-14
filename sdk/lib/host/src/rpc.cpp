#include <string.h>
#include <stdio.h>
#include "edge_call.h"
#include "edge_dispatch.h"
#include "keystone.h"
#include "rpc.h"
#ifdef HOST_ASYNC
#include "pthread.h"
#endif
#include "performance.h"

#define OCALL_ECALL_SERVE 0
#define OCALL_ECALL_DONE_CONT 1
#define OCALL_ECALL_DONE	2
#define OCALL_RPC_ISSUE 3
#define OCALL_GET_ENCLAVE_COUNT 4
#define OCALL_GET_MY_ID 5
#define OCALL_GET_RECORD_SIZE 6
#define ENCLAVE_MAX_COUNT 8


typedef unsigned char byte;

/**
 * OCALL interfaces
 *						Args				Ret
 * serve_ecall			none				ecall_args
 * ecall_done			ecall_ret			none
 * ecall_done_cont		ecall_ret			ecall_args
 * read					read_args			read_ret
 * write				write_args			write_ret
 * */


struct ecall_parcel {
    int secure;
    int source, target;
    size_t size;
    byte data[];
};

struct ecall_ret {
    size_t ret_size;
    byte retval[];
};

enum RPCStatus {
    RPC_NONE,
    RPC_ARRIVED,
    RPC_DISPATCHED,
};

struct rpc_task {
    Keystone* source_enclave;
    struct ecall_parcel* parcel;
    struct edge_call* edge_call;
    struct shared_region* shared_region;
    struct performance_stats stats;
};

class RPCDispatcher {
    private:
        struct rpc_task* rpc_queue;
        int current_in_server, server_capacity;
        int size, queue_head, queue_tail;
        int rpc_cnt;
        Keystone* enclave;
#ifdef HOST_ASYNC
        pthread_mutex_t lock;
#endif
        struct performance_stats delay_stats;
    public:
        RPCDispatcher(int enclave_n, int capacity, Keystone* encl);
        ~RPCDispatcher();
        struct rpc_task nextRPC();
        static void setupData(Keystone* enclave);
        bool addRPC(Keystone* enclave, struct ecall_parcel* parcel,
                struct edge_call* edge_call, struct shared_region* shared_region);
        static bool blockingForRPC(Keystone* enclave){
            enum RPCStatus status = *(enum RPCStatus*)enclave->custom;
            return status == RPC_ARRIVED || 
                status == RPC_DISPATCHED;
        }
        void finishServing(Keystone* enclave){
            *(enum RPCStatus*)enclave->custom = RPC_NONE;
            -- current_in_server;
        }
        void printStats();
        struct rpc_task current_serving;
        Keystone* getEnclave() const {
            return enclave;
        }
};

static RPCDispatcher* rpc_dispatchers[ENCLAVE_MAX_COUNT];
static int rpc_dispatcher_n;

static RPCDispatcher* rpc_dispatcher_by_eid(int target_eid){
    int i;
    for(i = 0; i < rpc_dispatcher_n && target_eid != rpc_dispatchers[i]->getEnclave()->getSID(); i ++);
    if(i < rpc_dispatcher_n)
        return rpc_dispatchers[i];
    return NULL;
}

static RPCDispatcher* rpc_dispatcher_by_encl(Keystone* target_encl){
    int i;
    for(i = 0; i < rpc_dispatcher_n && target_encl != rpc_dispatchers[i]->getEnclave(); i ++);
    if(i < rpc_dispatcher_n)
        return rpc_dispatchers[i];
    return NULL;
}

// will only be invoked in one thread
static bool dispatch_rpc(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    RPCDispatcher* dispatcher = rpc_dispatcher_by_encl(enclave);
    assert(dispatcher != NULL);
    struct rpc_task next_rpc = dispatcher->nextRPC();
    if(next_rpc.source_enclave == NULL)
        return false;

    dispatcher->current_serving = next_rpc;

    struct edge_call* edge_call = (struct edge_call*)buffer;

    size_t rpc_size = sizeof(struct ecall_parcel) + next_rpc.parcel->size;

    void* data = (void*)edge_call_data_ptr(shared_region);
    memcpy(data, (void*)next_rpc.parcel, rpc_size);

    if(edge_call_setup_ret(edge_call, data, rpc_size, shared_region)){
        printf("Bad!\n");
    }

    return true;
}

static int serve_ecall_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    if(dispatch_rpc(enclave, buffer, shared_region))
        return 0;
    return 1; // block to wait for requests
}

static void finish_ecall(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    size_t args_len;
    if(edge_call_args_ptr(edge_call, &call_args, &args_len, shared_region) != 0){
        printf("BAD get args ptr!\n");
    }

    struct ecall_ret* retval = (struct ecall_ret*)call_args;
    size_t ret_size = sizeof(struct ecall_ret) + retval->ret_size;

    RPCDispatcher* dispatcher = rpc_dispatcher_by_encl(enclave);
    assert(dispatcher != NULL);
    void* data = (void*)edge_call_data_ptr(dispatcher->current_serving.shared_region);
    memcpy(data, (void*)retval, ret_size);

    if(edge_call_setup_ret(dispatcher->current_serving.edge_call, data, ret_size, dispatcher->current_serving.shared_region)){
        printf("BAD setup ret!\n");
    }

    dispatcher->finishServing(dispatcher->current_serving.source_enclave);
}

static int ecall_done_cont_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    finish_ecall(enclave, buffer, shared_region);
    if(dispatch_rpc(enclave, buffer, shared_region))
        return 0;
    return 1;
}

static int ecall_done_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    finish_ecall(enclave, buffer, shared_region);
    struct edge_call* edge_call = (struct edge_call*)buffer;
    edge_call->return_data.call_status = CALL_STATUS_OK;

    return 0;
}

static int rpc_issue_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    uintptr_t call_args;
    size_t args_len;

    if(edge_call_args_ptr(edge_call, &call_args, &args_len, shared_region) != 0){
    }

    struct ecall_parcel* ecall_parcel = (struct ecall_parcel*)call_args;
    ecall_parcel->source = enclave->getSID();
    RPCDispatcher* dispatcher = rpc_dispatcher_by_eid(ecall_parcel->target);
    assert(dispatcher != NULL);
    dispatcher->addRPC(enclave, ecall_parcel, edge_call, shared_region);
    return 1; // blocking to wait for being served
}

static int rpc_issue_blocking_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    if(RPCDispatcher::blockingForRPC(enclave))
        return 1; // continue blocking as the results are not ready
    struct edge_call* edge_call = (struct edge_call*)buffer;
    edge_call->return_data.call_status = CALL_STATUS_OK;
    return 0;
}

static int get_my_id_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;

    int* data_section = (int*)edge_call_data_ptr(shared_region);
    *data_section = enclave->getSID();

    if( edge_call_setup_ret(edge_call, (void*) data_section, \
                sizeof(int), shared_region)){
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    }
    else{
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }

    return 0;
}


int RPCServerInit(DefaultEdgeCallDispatcher* dispatcher, Keystone* enclave){
    rpc_dispatchers[rpc_dispatcher_n ++] = new RPCDispatcher(ENCLAVE_MAX_COUNT, 1, enclave); // FIXME: memleak

    dispatcher->register_call(OCALL_ECALL_SERVE, serve_ecall_wrapper, serve_ecall_wrapper);

    dispatcher->register_call(OCALL_ECALL_DONE_CONT, ecall_done_cont_wrapper, serve_ecall_wrapper);

    dispatcher->register_call(OCALL_ECALL_DONE, ecall_done_wrapper, NULL);

    return 0;
}

int RPCClientInit(DefaultEdgeCallDispatcher* dispatcher, Keystone* enclave){
    dispatcher->register_call(OCALL_RPC_ISSUE, rpc_issue_wrapper, rpc_issue_blocking_wrapper);
    RPCDispatcher::setupData(enclave);
    return 0;
}

void print_edge_wrapper_stats(){
    //FIXME: rpc print stats rewrite
    //printf("==== Dispatcher stats ====\n");
    //rpc_dispatcher.printStats();
}

RPCDispatcher::RPCDispatcher(int enclave_n, int capacity, Keystone* enclave){
    this->enclave = enclave;
    size = enclave_n;
    server_capacity = capacity;
    rpc_queue = new struct rpc_task[enclave_n + 1];
    queue_head = queue_tail = 0;
    rpc_cnt = 0;
    current_in_server = 0;
#ifdef HOST_ASYNC
    pthread_mutex_init(&lock, NULL);
#endif
    performance_stats_init(&delay_stats);
}

RPCDispatcher::~RPCDispatcher(){
    delete[] rpc_queue;
}

struct rpc_task RPCDispatcher::nextRPC(){
#ifdef HOST_ASYNC
    pthread_mutex_lock(&lock);
#endif
    if(queue_head == queue_tail || current_in_server == server_capacity){
#ifdef HOST_ASYNC
        pthread_mutex_unlock(&lock);
#endif
        return {NULL, NULL, NULL};
    }
    struct rpc_task next_rpc = rpc_queue[queue_head ++];
    performance_check_end(&next_rpc.stats);
    performance_count(&next_rpc.stats);
    performance_stats_merge(&delay_stats, &next_rpc.stats);
    if(queue_head == size + 1)
        queue_head = 0;
    *(enum RPCStatus*)next_rpc.source_enclave->custom = RPC_DISPATCHED;
    -- rpc_cnt;
    ++ current_in_server;
#ifdef HOST_ASYNC
    pthread_mutex_unlock(&lock);
#endif
    return next_rpc;
}

void RPCDispatcher::setupData(Keystone* enclave){
    enclave->custom = malloc(sizeof(enum RPCStatus));
    *(enum RPCStatus*)enclave->custom = RPC_NONE;
}

bool RPCDispatcher::addRPC(Keystone* enclave, struct ecall_parcel* parcel,
        struct edge_call* edge_call, struct shared_region* shared_region){
#ifdef HOST_ASYNC
    pthread_mutex_lock(&lock);
#endif
    if(rpc_cnt == size){
#ifdef HOST_ASYNC
        pthread_mutex_unlock(&lock);
#endif
        return false;	
    }
    *(enum RPCStatus*)enclave->custom = RPC_ARRIVED;
    rpc_queue[queue_tail].source_enclave = enclave;
    rpc_queue[queue_tail].parcel = parcel;
    rpc_queue[queue_tail].edge_call = edge_call;
    rpc_queue[queue_tail].shared_region = shared_region;
    performance_stats_init(&rpc_queue[queue_tail].stats);
    performance_check_start(&rpc_queue[queue_tail].stats);
    ++ queue_tail;
    if(queue_tail == size + 1)
        queue_tail = 0;
    ++ rpc_cnt;
#ifdef HOST_ASYNC
    pthread_mutex_unlock(&lock);
#endif
    return true;
}

void RPCDispatcher::printStats(){
    performance_stats_print(&delay_stats, "Delay");
}

void RPCServerClose(Keystone* enclave){
    int i;
    for(i = 0; i < rpc_dispatcher_n && rpc_dispatchers[i]->getEnclave() != enclave; i ++);
    if(i < rpc_dispatcher_n){
        delete rpc_dispatchers[i];
        -- rpc_dispatcher_n;
        for(; i < rpc_dispatcher_n; i ++)
            rpc_dispatchers[i] = rpc_dispatchers[i + 1];
    }
}

