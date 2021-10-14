//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"
#include "string.h"
#include "edge_wrapper.h"
#include "edge_call.h"
#include "rpc_crypto.h"
#include "rpc_crypto_enc.h"
#include "performance.h"

#define OCALL_RPC_ISSUE 3

extern unsigned char my_tx[];
extern unsigned char my_rx[];

#ifdef PERFORMANCE_MEASURE
static struct performance_stats dumb_rpc_issue_encryption_stats;
static struct performance_stats dumb_rpc_issue_decryption_stats;

struct performance_stats* rpc_issue_encryption_stats;
struct performance_stats* rpc_issue_decryption_stats;
#endif

void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
#ifdef PERFORMANCE_MEASURE
	performance_stats_init(&dumb_rpc_issue_encryption_stats);
	performance_stats_init(&dumb_rpc_issue_decryption_stats);

    rpc_issue_encryption_stats = &dumb_rpc_issue_encryption_stats;
    rpc_issue_decryption_stats = &dumb_rpc_issue_decryption_stats;
#endif
}

/*void ocall_issue_rpc(struct ecall_parcel* parcel, struct ecall_ret* retval, size_t ret_size_lim, int secure){*/
	/*static struct rpc_data secure_rpc_data;	*/

	/*if(secure){*/
		/*memcpy(&secure_rpc_data.ecall_parcel, parcel, sizeof(struct ecall_parcel));*/
		/*struct crypto_parcel* crypto_parcel = (struct crypto_parcel*)secure_rpc_data.ecall_parcel.data;*/
/*#ifdef PERFORMANCE_MEASURE*/
		/*performance_check_start(rpc_issue_encryption_stats);*/
/*#endif*/
		/*size_t pack_size = rpc_crypto_data_pack(crypto_parcel, parcel->data, parcel->size, RPC_DATA_BUFFER_SIZE, my_tx);*/
/*#ifdef PERFORMANCE_MEASURE*/
		/*performance_check_end(rpc_issue_encryption_stats);*/
		/*performance_count(rpc_issue_encryption_stats);*/
		/*performance_count_data(rpc_issue_encryption_stats, parcel->size);*/
/*#endif*/
		/*pack_size += sizeof(struct crypto_parcel);*/
		/*secure_rpc_data.ecall_parcel.size = pack_size;*/
		/*secure_rpc_data.ecall_parcel.secure = 1;*/

		/*dispatch_edgecall_ocall(OCALL_ISSUE_RPC, &secure_rpc_data.ecall_parcel, sizeof(struct ecall_parcel) + pack_size,*/
			   /*&secure_rpc_data.retval, sizeof(struct ecall_ret) + ret_size_lim, 1);*/

		/*crypto_parcel = (struct crypto_parcel*)secure_rpc_data.retval.retval;*/
		
		/*pack_size = secure_rpc_data.retval.ret_size - sizeof(struct crypto_parcel);*/

/*#ifdef PERFORMANCE_MEASURE*/
		/*performance_check_start(rpc_issue_decryption_stats);*/
/*#endif*/
		/*retval->ret_size = rpc_crypto_data_unpack(crypto_parcel, retval->retval, pack_size, ret_size_lim, my_rx);*/
/*#ifdef PERFORMANCE_MEASURE*/
		/*performance_check_end(rpc_issue_decryption_stats);*/
		/*performance_count(rpc_issue_decryption_stats);*/
		/*performance_count_data(rpc_issue_decryption_stats, pack_size);*/
/*#endif*/
	/*} else{*/
		/*parcel->secure = 0;*/
		/*dispatch_edgecall_ocall(OCALL_ISSUE_RPC, parcel, sizeof(struct ecall_parcel) + parcel->size,*/
				/*retval, sizeof(struct ecall_ret) + ret_size_lim, 1);*/
	/*}*/
/*}*/



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

        dispatch_edgecall_ocall(OCALL_RPC_ISSUE, &secure_rpc_data.ecall_parcel, sizeof(struct ecall_parcel) + pack_size,
                &secure_rpc_data.retval, sizeof(struct ecall_ret) + ret_size_lim, 1);	

        crypto_parcel = (struct crypto_parcel*)secure_rpc_data.retval.retval;

        assert(secure_rpc_data.retval.ret_size >= sizeof(struct crypto_parcel));
        pack_size = secure_rpc_data.retval.ret_size - sizeof(struct crypto_parcel);

        retval->ret_size = rpc_crypto_data_unpack(crypto_parcel, retval->retval, \
                pack_size, ret_size_lim, my_rx);
    } else{
        parcel->secure = 0;
        dispatch_edgecall_ocall(OCALL_RPC_ISSUE, parcel, sizeof(struct ecall_parcel) + parcel->size,
                retval, sizeof(struct ecall_ret) + ret_size_lim, 1);
    }
}


