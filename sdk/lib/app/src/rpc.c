#include<string.h>
#include<stdint.h>
#include<stdio.h>
#include<assert.h>
#include<sodium.h>
#include "ecall.h"
#include "rpc.h"

#define MAX_ENCLAVES 32
#define MAX_RPC_NUM 16

#ifndef SECURE_STORAGE_SIZE
#define SECURE_STORAGE_SIZE (1<<20)
#endif

#ifndef SECURE_LOCK_NUM
#define SECURE_LOCK_NUM 32
#endif

#define MSG_BLOCKSIZE 32

#define RPC_DATA_BUFFER_SIZE (1<<19)

// predefined RPC numbers
#define RPC_CREATE_CHANNEL 0


struct create_channel_args {
    unsigned char pubkey[crypto_kx_PUBLICKEYBYTES];
};

struct create_channel_ret {
    int success;
    unsigned char pubkey[crypto_kx_PUBLICKEYBYTES];
};

struct crypto_parcel {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char data[];
};

static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data, secure_rpc_data;
static rpc_handler rpc_handler_table[MAX_RPC_NUM];
static unsigned char in_secure_storage[SECURE_STORAGE_SIZE];
static unsigned char out_secure_storage[SECURE_STORAGE_SIZE];

//static int secure_locks[SECURE_LOCK_NUM];
static int num_rpc;
static char* rpc_names[MAX_RPC_NUM];


static unsigned char my_pubkey[crypto_kx_PUBLICKEYBYTES];
static unsigned char my_seckey[crypto_kx_SECRETKEYBYTES];
static unsigned char server_pubkey[crypto_kx_PUBLICKEYBYTES];
static unsigned char worker_rx[MAX_ENCLAVES][crypto_kx_SESSIONKEYBYTES];
static unsigned char worker_tx[MAX_ENCLAVES][crypto_kx_SESSIONKEYBYTES];
static int worker_channel_ready[MAX_ENCLAVES];

static unsigned char worker_pubkeys[MAX_ENCLAVES][crypto_kx_PUBLICKEYBYTES];
static unsigned char manager_seckey[crypto_kx_SECRETKEYBYTES];
static unsigned char manager_pubkey[crypto_kx_PUBLICKEYBYTES];

static unsigned char my_pubkey[crypto_kx_PUBLICKEYBYTES];
static unsigned char my_seckey[crypto_kx_SECRETKEYBYTES];
static unsigned char server_pubkey[crypto_kx_PUBLICKEYBYTES];
static unsigned char my_tx[crypto_kx_SESSIONKEYBYTES];
static unsigned char my_rx[crypto_kx_SESSIONKEYBYTES];

static int rpc_crypto_create_channel(){
    struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
    struct create_channel_args* cc_args = (struct create_channel_args*)args->args;

    memcpy(cc_args->pubkey, my_pubkey, crypto_kx_PUBLICKEYBYTES);

    args->ecall_num = RPC_CREATE_CHANNEL;
    setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct create_channel_args));

    rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, 0);

    struct create_channel_ret* ret = (struct create_channel_ret*)rpc_data.retval.retval;
    if(!ret->success)
        return 1;

    memcpy(server_pubkey, ret->pubkey, crypto_kx_PUBLICKEYBYTES);
    printf("Server pubkey in client: ");
    int i;
    for(i = 0; i < crypto_kx_PUBLICKEYBYTES; i ++)
        printf("%u ", server_pubkey[i]);
    printf("\n");
    if(crypto_kx_client_session_keys(my_rx, my_tx, my_pubkey, my_seckey, server_pubkey)){
        printf("Error creating client session keys!\n");
        return 1;
    }

    return 0;
}


static size_t rpc_crypto_data_pack(struct crypto_parcel* parcel, void* data, size_t len,
        size_t size_lim, unsigned char* tx){
    randombytes_buf(parcel->nonce, crypto_secretbox_NONCEBYTES);
    size_t padded_len;
    if(sodium_pad(&padded_len, data, len, MSG_BLOCKSIZE, size_lim)){
        fprintf(stderr, "Sodium padding error!\n");
        return 0;
    }
    //TODO: size lim, reserve mac unsigned chars
    if(crypto_secretbox_easy(parcel->data, data, padded_len, parcel->nonce, tx)){
        fprintf(stderr, "Error encryption data!\n");
        return 0;
    }
    return padded_len + crypto_secretbox_MACBYTES;
}

static size_t rpc_crypto_data_unpack(struct crypto_parcel* parcel, void* data,
        size_t len, size_t size_lim, unsigned char* rx){
    if(crypto_secretbox_open_easy(data, parcel->data, len, parcel->nonce, rx)){
        fprintf(stderr, "Error decrypting data!\n");
        return 0;
    }
    size_t res_len;
    if(sodium_unpad(&res_len, data, len - crypto_secretbox_MACBYTES, MSG_BLOCKSIZE)){
        fprintf(stderr, "Error unpadding data!\n");
        return 0;
    }
    return res_len;
}

void rpc_server_handler_register(int rpc_no, rpc_handler handler){
    rpc_handler_table[rpc_no] = handler;
}

void rpc_serve(){
    ecall_serve(&rpc_data.ecall_parcel, RPC_DATA_BUFFER_SIZE);
    do{
        int secure = rpc_data.ecall_parcel.secure;
        int source = rpc_data.ecall_parcel.source;
        struct ecall_args* ecall_args;
        struct ecall_ret* ecall_ret;
        size_t args_size;
        if(source < 0 || source >= MAX_ENCLAVES){
            printf("Bad source!\n");
            fflush(stdout);
            while(1);
        }
        if(secure){
            if(!worker_channel_ready[source]){
                printf("Secure channel unavailable!\n");
                fflush(stdout);
                while(1);
            }
            struct crypto_parcel* crypto_parcel = (struct crypto_parcel*)rpc_data.ecall_parcel.data;
            ecall_args = ecall_args_from_parcel(&secure_rpc_data.ecall_parcel);
            size_t unpacked_size = rpc_crypto_data_unpack(crypto_parcel, ecall_args, rpc_data.ecall_parcel.size - sizeof(struct crypto_parcel), RPC_DATA_BUFFER_SIZE, worker_rx[source]);
            assert(unpacked_size >= sizeof(struct ecall_args));
            args_size = unpacked_size - sizeof(struct ecall_args);

            ecall_ret = &secure_rpc_data.retval;
        } else{
            ecall_args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
            assert(rpc_data.ecall_parcel.size >= sizeof(struct ecall_args));
            args_size = rpc_data.ecall_parcel.size - sizeof(struct ecall_args);
            ecall_ret = &rpc_data.retval;
        }
        int ecall_num = ecall_args->ecall_num;
        if(ecall_num < 0 || ecall_num >= MAX_RPC_NUM
                || !rpc_handler_table[ecall_num]){
            printf("Bad ecall num %d!\n", ecall_num);
            while(1);
        } else{
            int exit = 0;
            size_t data_size = rpc_handler_table[ecall_num](source, 
                    ecall_args->args,
                    args_size,
                    ecall_ret->retval,
                    RPC_DATA_BUFFER_SIZE - sizeof(struct ecall_ret), &exit);
            ecall_ret->ret_size = data_size;

            if(secure){
                // need to encrypt the return data
                struct crypto_parcel* crypto_parcel = (struct crypto_parcel*)rpc_data.retval.retval;
                size_t packed_size = rpc_crypto_data_pack(crypto_parcel, ecall_ret->retval, data_size, RPC_DATA_BUFFER_SIZE, worker_tx[source]);
                rpc_data.retval.ret_size = packed_size + sizeof(struct crypto_parcel);
            }

            if(!exit)
                ecall_done_cont(&rpc_data.retval, &rpc_data.ecall_parcel, RPC_DATA_BUFFER_SIZE);
            else{
                // quit when all workers have left
                ecall_done(&rpc_data.retval);
                break;
            }
        }
    } while(1);
}


static size_t rpc_create_channel_handler(int source, void* args_data, 
        size_t args_size, void* ret_data,
        size_t ret_size_lim, int* exit){
    if(args_size < sizeof(struct create_channel_args) ||
            ret_size_lim < sizeof(struct create_channel_ret))
        return 0;
    struct create_channel_args* args = (struct create_channel_args*)args_data;
    struct create_channel_ret* ret = (struct create_channel_ret*)ret_data;

    if(source < 0 || source >= MAX_ENCLAVES || worker_channel_ready[source]){
        goto create_channel_fail;
    }

    memcpy(worker_pubkeys[source], args->pubkey, crypto_kx_PUBLICKEYBYTES);
    if(crypto_kx_server_session_keys(worker_rx[source], worker_tx[source], manager_pubkey, manager_seckey, worker_pubkeys[source])){
        int i;
        fprintf(stderr, "Error creating server session keys\n");
        goto create_channel_fail;
    }

    ret->success = 1;
    worker_channel_ready[source] = 1;
    memcpy(ret->pubkey, manager_pubkey, crypto_kx_PUBLICKEYBYTES);

    return sizeof(struct create_channel_ret);
create_channel_fail:
    ret->success = 0;
    memset(ret->pubkey, 0, crypto_kx_PUBLICKEYBYTES);
    return sizeof(struct create_channel_ret);
}



int rpc_client_init(int crypto_en){
    if(crypto_en){
        if(sodium_init() < 0){
            printf("Unable to init sodium!\n");
            return 1;
        }

        // create keys
        if(crypto_kx_keypair(my_pubkey, my_seckey)){
            fprintf(stderr, "Error creating keypair in worker!\n");
            return 1;
        }

        if(rpc_crypto_create_channel()){
            printf("Error create channel with manager!\n");
            return 1;
        }
    }

    return 0;
}

int rpc_server_init(int crypto_en){
    if(crypto_en){
        int res = sodium_init();
        if(res < 0){
            printf("Unable to init sodium %d\n", res);
            return 1;
        }
        randombytes_set_implementation(&randombytes_salsa20_implementation);
        if(crypto_kx_keypair(manager_pubkey, manager_seckey)){
            printf("Unable to generate manager keys\n");
            return 1;
        }

        rpc_server_handler_register(RPC_CREATE_CHANNEL, rpc_create_channel_handler);
    }

    return 0;
}

void rpc_issue(struct ecall_parcel* parcel, struct ecall_ret* retval, \
        size_t ret_size_lim, int secure){
    static RPC_DATA(RPC_DATA_BUFFER_SIZE) secure_rpc_data;	

    if(secure){
        memcpy(&secure_rpc_data.ecall_parcel, parcel, sizeof(struct ecall_parcel));
        struct crypto_parcel* crypto_parcel = (struct crypto_parcel*)secure_rpc_data.ecall_parcel.data;
        size_t pack_size = rpc_crypto_data_pack(crypto_parcel, parcel->data, parcel->size, RPC_DATA_BUFFER_SIZE, my_tx);
        pack_size += sizeof(struct crypto_parcel);

        secure_rpc_data.ecall_parcel.size = pack_size;
        secure_rpc_data.ecall_parcel.secure = 1;

        ocall(OCALL_RPC_ISSUE, &secure_rpc_data.ecall_parcel, sizeof(struct ecall_parcel) + pack_size,
                &secure_rpc_data.retval, sizeof(struct ecall_ret) + ret_size_lim);	

        crypto_parcel = (struct crypto_parcel*)secure_rpc_data.retval.retval;

        assert(secure_rpc_data.retval.ret_size >= sizeof(struct crypto_parcel));
        pack_size = secure_rpc_data.retval.ret_size - sizeof(struct crypto_parcel);

        retval->ret_size = rpc_crypto_data_unpack(crypto_parcel, retval->retval, \
                pack_size, ret_size_lim, my_rx);
    } else{
        parcel->secure = 0;
        ocall(OCALL_RPC_ISSUE, parcel, sizeof(struct ecall_parcel) + parcel->size,
                retval, sizeof(struct ecall_ret) + ret_size_lim);
    }
}

