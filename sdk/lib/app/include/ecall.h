#ifndef _ECALL_EDGE_WRAPPER_H
#define _ECALL_EDGE_WRAPPER_H

#include<stdint.h>
#include<stdlib.h>

#define OCALL_ECALL_SERVE 0
#define OCALL_ECALL_DONE_CONT 1
#define OCALL_ECALL_DONE	2
#define OCALL_RPC_ISSUE 3
#define OCALL_GET_ENCLAVE_COUNT 4
#define OCALL_GET_MY_ID 5
#define OCALL_GET_RECORD_SIZE 6

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

void ecall_serve(struct ecall_parcel* parcel, size_t arg_size_lim);

void ecall_done(struct ecall_ret* retval);

void ecall_done_cont(struct ecall_ret* retval, struct ecall_parcel* parcel, size_t arg_size_lim);


#endif

