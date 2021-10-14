#include "ecall.h"

void ecall_serve(struct ecall_parcel* parcel, size_t arg_size_lim){
	ocall(OCALL_ECALL_SERVE, NULL, 0, parcel, sizeof(struct ecall_parcel) + arg_size_lim);
}

void ecall_done(struct ecall_ret* retval){
	ocall(OCALL_ECALL_DONE, retval, sizeof(struct ecall_ret) + retval->ret_size, NULL, 0);
}

void ecall_done_cont(struct ecall_ret* retval, struct ecall_parcel* parcel, size_t arg_size_lim){
	ocall(OCALL_ECALL_DONE_CONT, retval, sizeof(struct ecall_ret) + retval->ret_size,
		   	parcel, sizeof(struct ecall_parcel) + arg_size_lim);
}


