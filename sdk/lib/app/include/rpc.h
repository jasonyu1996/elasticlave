#ifndef __RPC_H
#define __RPC_H

#include <stdint.h>
#include <sodium.h>
#include "ecall.h"

#define RPC_DATA(buffer_size) \
	struct { \
		struct ecall_parcel ecall_parcel; \
		unsigned char __args_data[(buffer_size)]; \
		struct ecall_ret retval; \
		unsigned char __retval_data[(buffer_size)];\
	}


typedef size_t (*rpc_handler)(int source, void* args_data, 
		size_t args_size, void* ret_data, 
		size_t ret_size_lim, int* exit);

// client interfaces
int rpc_client_init(int crypto_en);
void rpc_issue(struct ecall_parcel* parcel, struct ecall_ret* retval,
	   	size_t ret_size_lim, int secure);
// server interfaces
int rpc_server_init(int crypto_en);
void rpc_server_handler_register(int rpc_no, rpc_handler handler);
void rpc_serve();
#endif

