#include<stdio.h>
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_common.h"
#include "rpc.h"
#include "callnums.h"

#define SECURE_LOCK_NUM 64
#define SECURE_STORAGE_SIZE (1<<20)

static int num_active_workers;

static int secure_locks[SECURE_LOCK_NUM];
static char secure_storage[SECURE_STORAGE_SIZE];

static size_t rpc_read_handler(int source, void* args_data, size_t args_size, 
        void* ret_data, size_t ret_size_lim, int* quit){
    static unsigned long start_cycle;
    *quit = 0;
    if(sizeof(struct read_args) > args_size || sizeof(struct read_ret) > ret_size_lim)
        return 0;
    struct read_args* read_args = (struct read_args*)args_data;
    uintptr_t addr = read_args->addr;
    size_t size = read_args->size;

    size_t read_size;
    if(addr >= SECURE_STORAGE_SIZE || (addr + (uintptr_t)size) >= SECURE_STORAGE_SIZE ||
            size + sizeof(struct read_ret) > ret_size_lim)
        read_size = 0;
    else{
        read_size = size;
    }
    struct read_ret* read_ret = (struct read_ret*)ret_data;
    read_ret->size = read_size;

    memcpy(read_ret->data, secure_storage + addr, read_size);

    return sizeof(struct read_ret) + read_size;
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

    return sizeof(struct write_ret);
}

static size_t rpc_lock_handler(int source, void* args_data,
        size_t args_size, void* ret_data, size_t ret_size_lim, int* quit){
    *quit = 0;
    if(sizeof(struct lock_args) > args_size || sizeof(struct lock_ret) > ret_size_lim)
        return 0;
    struct lock_args* lock_args = (struct lock_args*)args_data;
    unsigned int lock_index = lock_args->lock_index;
    int to_lock = lock_args->to_lock;

    int success;
    if(lock_index >= SECURE_LOCK_NUM || to_lock == secure_locks[lock_index]){
        success = 0;
    } else{
        success = 1;
        secure_locks[lock_index] = to_lock;
    }
    //printf("Lock %d %d %d %d\n", source, lock_index, to_lock, success);

    struct lock_ret* lock_ret = (struct lock_ret*)ret_data;
    lock_ret->success = success;

    return sizeof(struct lock_ret);
}

static size_t rpc_quit_handler(int source, void* args_data, 
        size_t args_size, void* ret_data, size_t ret_size_lim, int* quit){
    -- num_active_workers;
    if(num_active_workers == 0){
        *quit = 1;
    } else{
        *quit = 0;
    }
    return 0;
}

static int ocall_get_thread_count(){
    int ret;
    ocall(OCALL_GET_THREAD_COUNT, NULL, 0, &ret, sizeof(int));
    return ret;
}

int main(){
    num_active_workers = ocall_get_thread_count();
    rpc_server_init(0);
    rpc_server_handler_register(RPC_LOCK, rpc_lock_handler);
    rpc_server_handler_register(RPC_READ, rpc_read_handler);
    rpc_server_handler_register(RPC_WRITE, rpc_write_handler);
    rpc_server_handler_register(RPC_QUIT, rpc_quit_handler);

    rpc_serve();
    _exit(0);

    return 0;
}
