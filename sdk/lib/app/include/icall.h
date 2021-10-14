#ifndef _ICALL_H
#define _ICALL_H

#include "edge_common.h"
#include "edge_call.h"
#include "types.h"

typedef int (*edgecallwrapper)(int, void*, struct shared_region*);
typedef int (*icall_request_handler)(int);

// server interfaces
void icall_server_init();
int icall_server_register_handler(unsigned long call_id, edgecallwrapper func);
void icall_server_launch();
void icall_server_launch_async();
void icall_server_stop();
void icall_server_expect_conn(int expect_conn);
void icall_set_request_handler(icall_request_handler handler);


// client interfaces
void* get_shared_buffer(size_t* size);
uintptr_t icall(uintptr_t enclave_id, unsigned long call_id,
                                   void* data, size_t data_len,
                                   void* return_buffer, size_t return_len);
uintptr_t icall_async(uintptr_t enclave_id, unsigned long call_id,
                                   void* data, size_t data_len,
                                   void* return_buffer, size_t return_len);

void icall_connect(uintptr_t enclave_id);
int get_my_id();

#endif

