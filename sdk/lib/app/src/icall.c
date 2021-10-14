#include "ks_string.h"
#include "icall.h"
#include "rpc.h"
#include "syscall.h"
#include "edge_common.h"


#define BUFFER_SIZE 8192
#define MAX_BUFFER_NAME 32
#define MAX_ENCLAVES_N 16

#define RPC_ICALL_REQUEST 1

#define PERM_R 1
#define PERM_W 2

// TODO: currently only supports one client

// server
static int launched;
static edgecallwrapper handlers[MAX_EDGE_CALL];

// connection data for server
static struct shared_region server_buffers[MAX_ENCLAVES_N];
static int server_connected_eid[MAX_ENCLAVES_N];
static int server_connected_n, server_expected_conn;
static icall_request_handler server_request_handler;

// connection data for client
static struct shared_region client_buffers[MAX_ENCLAVES_N];
static int client_connected_eid[MAX_ENCLAVES_N];
static int client_connected_n;


struct icall_request_ret {
    uid_t uid;
};

static size_t rpc_icall_request_handler(int source, void* args_data,
        size_t args_size, void* ret_data,
        size_t ret_size_lim, int* exit){
    // requester doesn't actually need to send any data

    if(ret_size_lim < sizeof(struct icall_request_ret))
        goto icall_request_failed;

    if(server_request_handler && !server_request_handler(source))
        goto icall_request_failed;

    uid_t uid = elasticlave_create(BUFFER_SIZE);
    void* buf = elasticlave_map(uid);
    if(buf == NULL)
        goto icall_request_failed_map_buf;

    if(elasticlave_change(uid, PERM_R | PERM_W)){
        goto icall_request_failed_change_buf;
    }
    struct edge_call* edge_call = (struct edge_call*)buf;
    edge_call->call_id = (unsigned long)-1;

    if(elasticlave_share(uid, source, PERM_R | PERM_W)){
        goto icall_request_failed_change_buf;
    }

    shared_region_init((uintptr_t)buf, BUFFER_SIZE, server_buffers + server_connected_n);
    server_buffers[server_connected_n].uid = uid;
    server_connected_eid[server_connected_n] = source;
    ++ server_connected_n;
    struct icall_request_ret* ret = (struct icall_request_ret*)ret_data;
    ret->uid = uid;

    /**exit = 1; // break rpc serve*/
    *exit = server_connected_n >= server_expected_conn;
    return sizeof(struct icall_request_ret);

icall_request_failed_change_buf:
    elasticlave_unmap(buf);
icall_request_failed_map_buf:
    elasticlave_destroy(uid);
icall_request_failed:
    return 0;
}

void icall_server_expect_conn(int expect_conn){
    server_expected_conn = expect_conn;
}


void icall_set_request_handler(icall_request_handler handler){
    server_request_handler = handler;
}


void icall_server_init(){
    server_connected_n = 0;
    ks_memset(handlers, 0, sizeof(handlers));

    rpc_server_init(0);
    rpc_server_handler_register(RPC_ICALL_REQUEST, rpc_icall_request_handler);
}

// All the eids here would be SID
void icall_connect(uintptr_t oeid){
    rpc_client_init(0); 

    static RPC_DATA(256) rpc_data;
    struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
    args->ecall_num = RPC_ICALL_REQUEST;
    setup_parcel_size(&rpc_data.ecall_parcel, 0);
    setup_parcel_target(&rpc_data.ecall_parcel, (int)oeid);

    rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, 256, 0);

    struct icall_request_ret* ret = (struct icall_request_ret*)rpc_data.retval.retval;
    uid_t uid = ret->uid;
    void* buf = elasticlave_map(uid);
    elasticlave_change(uid, PERM_R | PERM_W);

    shared_region_init((uintptr_t)buf, BUFFER_SIZE, client_buffers + client_connected_n);
    client_buffers[client_connected_n].uid = uid;
    client_connected_eid[client_connected_n] = oeid;
    ++ client_connected_n;
}


int icall_server_register_handler(unsigned long call_id, edgecallwrapper func){
    if(call_id >= MAX_EDGE_CALL || handlers[call_id])
        return -1;
    handlers[call_id] = func;

    return 0;
}

static void _icall_dispatch(int connected_i, int sync){
    struct edge_call* edge_call = (struct edge_call*)server_buffers[connected_i].shared_start;
    unsigned long call_id = edge_call->call_id;
    if(call_id < MAX_EDGE_CALL && handlers[call_id]){
        handlers[call_id](server_connected_eid[connected_i], (void*)server_buffers[connected_i].shared_start, server_buffers + connected_i);
        edge_call->call_id = (unsigned long)-1; // remove the pending state
        if(sync && server_connected_eid[connected_i] == -1){
            // return if call id is -1
            while(1); // TODO: gracefully return to host
            /*ecall_return();*/
        }
    }
}

static inline void _icall_server_launch_internal(int sync){
    rpc_serve(); // serve RPC to accept a connection

    int i;
    launched = 1;
    while(launched){
        for(i = 0; i < server_connected_n; i ++){
            _icall_dispatch(i, sync);
        }
    }
}

void icall_server_launch(){
    _icall_server_launch_internal(1);
}

void icall_server_launch_async(){
    _icall_server_launch_internal(0);
}

void icall_server_stop(){
    launched = 0;
}


// client

static uintptr_t __icall_internal(uintptr_t enclave_id, unsigned long call_id,
        void* data, size_t data_len,
        void* return_buffer, size_t return_len, int sync){
    int connection_id;
    for(connection_id = 0; connection_id < client_connected_n &&
            client_connected_eid[connection_id] != enclave_id; connection_id ++);
    if(connection_id >= client_connected_n)
        return -1;

    struct shared_region* shared_region = client_buffers + connection_id;
    void* shared_buffer = (void*)(shared_region->shared_start);
    size_t shared_buffer_size = shared_region->shared_len;

    uintptr_t ret = CALL_STATUS_OK;
    /* For now we assume by convention that the start of the buffer is
     * the right place to put calls */
    struct edge_call* edge_call = (struct edge_call*)shared_buffer;

    /* We encode the call id, copy the argument data into the shared
     * region, calculate the offsets to the argument data, and then
     * dispatch the ocall to host */

    uintptr_t buffer_data_start = edge_call_data_ptr(shared_region);

    if(data_len > (shared_buffer_size - (buffer_data_start - (uintptr_t)shared_buffer))){
        goto inter_encl_error;
    }

    ks_memcpy((void*)buffer_data_start, (void*)data, data_len);

    if(edge_call_setup_call(edge_call, (void*)buffer_data_start, data_len, shared_region) != 0){
        goto inter_encl_error;
    }

    edge_call->call_id = call_id; // only finally set the call_id

    if(sync){
        do{
            ret = SYSCALL_0(SYSCALL_YIELD);
        } while(edge_call->call_id != (unsigned long)-1);
    } else{
        while(edge_call->call_id != (unsigned long)-1);
    }

    if (ret != 0) {
        goto inter_encl_error;
    }

    if(edge_call->return_data.call_status != CALL_STATUS_OK){
        goto inter_encl_error;
    }

    if( return_len == 0 ){
        /* Done, no return */
        return 0;
    }

    uintptr_t return_ptr;
    size_t ret_len_untrusted;
    if(edge_call_ret_ptr(edge_call, &return_ptr, &ret_len_untrusted, shared_region) != 0){
        goto inter_encl_error;
    }

    ks_memcpy(return_buffer, (void*)return_ptr, return_len);

    return 0;

inter_encl_error:
    return -2;
}

uintptr_t icall(uintptr_t enclave_id, unsigned long call_id,
        void* data, size_t data_len,
        void* return_buffer, size_t return_len){
    return __icall_internal(enclave_id, call_id, \
            data, data_len, \
            return_buffer, return_len, 1);
}

uintptr_t icall_async(uintptr_t enclave_id, unsigned long call_id,
        void* data, size_t data_len,
        void* return_buffer, size_t return_len){
    return __icall_internal(enclave_id, call_id, \
            data, data_len, \
            return_buffer, return_len, 0);
}

int get_my_id(){
    return SYSCALL_0(SYSCALL_GET_MY_ID);
}

void* get_shared_buffer(size_t* size){
    uintptr_t shared_buffer;
    int ret = SYSCALL_2(SYSCALL_GET_SHARED_BUFFER, &shared_buffer, size);
    if(ret)
        shared_buffer = 0;
    return (void*)shared_buffer;
}

