#ifndef _EDGE_WRAPPER_DATA_H_
#define _EDGE_WRAPPER_DATA_H_

#include "stdint.h"
#include <stddef.h>

typedef unsigned char byte;

#define RPC_DATA_BUFFER_SIZE 8192



struct ecall_args {
	int ecall_num; // ecall_num inside ecall_args to keep the ecall number secret
	unsigned char args[];
};

struct ecall_parcel {
	int secure;
	int source, target;
	size_t size;
	unsigned char data[];
};

struct ecall_ret {
	size_t ret_size;
	unsigned char retval[];
};

inline static struct ecall_args* ecall_args_from_parcel(struct ecall_parcel* parcel){
    return (struct ecall_args*)parcel->data;
}

inline static void setup_parcel_size(struct ecall_parcel* parcel, size_t args_size){
    parcel->size = sizeof(struct ecall_args) + args_size;
}

inline static void setup_parcel_target(struct ecall_parcel* parcel, int target){
    parcel->target = target;
}


#define RPC_DATA(buffer_size) \
	struct { \
		struct ecall_parcel ecall_parcel; \
		unsigned char __args_data[(buffer_size)]; \
		struct ecall_ret retval; \
		unsigned char __retval_data[(buffer_size)];\
	}


#endif
