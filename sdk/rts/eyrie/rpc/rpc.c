#include "printf.h"
#include "string.h"
#include "rpc.h"
#include "rpc_data.h"
#include "edge_wrapper_data.h"
#include "edge_wrapper.h"
#include "performance.h"

#define RPC_N 3

static RPC_DATA(RPC_DATA_BUFFER_SIZE) rpc_data;

#ifdef PERFORMANCE_MEASURE
extern struct performance_stats* rpc_issue_encryption_stats;
extern struct performance_stats* rpc_issue_decryption_stats;

static struct performance_stats encryption_stats[RPC_MAX];
static struct performance_stats decryption_stats[RPC_MAX];
static struct performance_stats args_copy_stats[RPC_MAX];
static struct performance_stats retval_copy_stats[RPC_MAX];
#endif

const char* RPC_NAMES[] = {
	"read",
	"write",
	"lock",
	"quit"
};

#define MANAGER_EID 1

static size_t __rpc_read(uintptr_t addr, size_t size, void* buffer, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct read_args* read_args = (struct read_args*)args->args;
	read_args->addr = addr;
	read_args->size = size;

	args->ecall_num = RPC_READ;
	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct read_args));
#ifdef PERFORMANCE_MEASURE
	rpc_issue_encryption_stats = encryption_stats + RPC_READ;
	rpc_issue_decryption_stats = decryption_stats + RPC_READ;
#endif

	setup_parcel_target(&rpc_data.ecall_parcel, MANAGER_EID);
	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);

	struct read_ret* read_ret = (struct read_ret*)rpc_data.retval.retval;
#ifdef PERFORMANCE_MEASURE
	performance_check_start(retval_copy_stats + RPC_READ);
#endif
	memcpy(buffer, read_ret->data, read_ret->size);
#ifdef PERFORMANCE_MEASURE
	performance_check_end(retval_copy_stats + RPC_READ);
	performance_count(retval_copy_stats + RPC_READ);
	performance_count_data(retval_copy_stats + RPC_READ, read_ret->size);
#endif
	return read_ret->size;
}


size_t rpc_read(uintptr_t addr, size_t size, void* buffer){
    /*printf("R %llu\n", addr);*/
	return __rpc_read(addr, size, buffer, 0);
}

size_t rpc_secure_read(uintptr_t addr, size_t size, void* buffer){
	return __rpc_read(addr, size, buffer, 1);
}


static size_t __rpc_write(uintptr_t addr, size_t size, void* buffer, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct write_args* write_args = (struct write_args*)args->args;
	write_args->addr = addr;
	write_args->size = size;
#ifdef PERFORMANCE_MEASURE
	performance_check_start(args_copy_stats + RPC_WRITE);
#endif
	memcpy(write_args->data, buffer, size);
#ifdef PERFORMANCE_MEASURE
	performance_check_end(args_copy_stats + RPC_WRITE);
	performance_count(args_copy_stats + RPC_WRITE);
	performance_count_data(args_copy_stats + RPC_WRITE, size);
#endif

	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct write_args) + size);
	args->ecall_num = RPC_WRITE;

#ifdef PERFORMANCE_MEASURE
	rpc_issue_encryption_stats = encryption_stats + RPC_WRITE;
	rpc_issue_decryption_stats = decryption_stats + RPC_WRITE;
#endif
	setup_parcel_target(&rpc_data.ecall_parcel, MANAGER_EID);
	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);

	struct write_ret* write_ret = (struct write_ret*)rpc_data.retval.retval;
	return write_ret->size;
}


size_t rpc_write(uintptr_t addr, size_t size, void* buffer){
	return __rpc_write(addr, size, buffer, 0);
}

size_t rpc_secure_write(uintptr_t addr, size_t size, void* buffer){
	return __rpc_write(addr, size, buffer, 1);
}

static int __rpc_lock_access(unsigned int lock_index, int to_lock, int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);
	struct lock_args* lock_args = (struct lock_args*)args->args;
	lock_args->to_lock = to_lock;
	lock_args->lock_index = lock_index;
	
	setup_parcel_size(&rpc_data.ecall_parcel, sizeof(struct lock_args));
	args->ecall_num = RPC_LOCK;
#ifdef PERFORMANCE_MEASURE
	rpc_issue_encryption_stats = encryption_stats + RPC_LOCK;
	rpc_issue_decryption_stats = decryption_stats + RPC_LOCK;
#endif

	setup_parcel_target(&rpc_data.ecall_parcel, MANAGER_EID);
	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
	struct lock_ret* lock_ret = (struct lock_ret*)rpc_data.retval.retval;
	return lock_ret->success;
}

int rpc_lock(unsigned int lock_index){
	return __rpc_lock_access(lock_index, 1, 0);
}

int rpc_secure_lock(unsigned int lock_index){
	return __rpc_lock_access(lock_index, 1, 1);
}

int rpc_unlock(unsigned int lock_index){
	return __rpc_lock_access(lock_index, 0, 0);
}

int rpc_secure_unlock(unsigned int lock_index){
	return __rpc_lock_access(lock_index, 0, 1);
}

static void __rpc_quit(int secure){
	struct ecall_args* args = ecall_args_from_parcel(&rpc_data.ecall_parcel);

	args->ecall_num = RPC_QUIT;
	setup_parcel_size(&rpc_data.ecall_parcel, 0);
#ifdef PERFORMANCE_MEASURE
	rpc_issue_encryption_stats = encryption_stats + RPC_QUIT;
	rpc_issue_decryption_stats = decryption_stats + RPC_QUIT;
#endif

	setup_parcel_target(&rpc_data.ecall_parcel, MANAGER_EID);
	rpc_issue(&rpc_data.ecall_parcel, &rpc_data.retval, RPC_DATA_BUFFER_SIZE, secure);
}

void rpc_quit(){
	return __rpc_quit(0);
}

void rpc_quit_secure(){
	return __rpc_quit(1);
}

void rpc_init(){
#ifdef PERFORMANCE_MEASURE
	int i;
	for(i = 0; i < RPC_N; i ++){
		performance_stats_init(encryption_stats + i);
		performance_stats_init(decryption_stats + i);
		performance_stats_init(args_copy_stats + i);
		performance_stats_init(retval_copy_stats + i);
	}
#endif
}

#ifdef PERFORMANCE_MEASURE
void rpc_stats_print(){
	printf("==== RPC issue stats (RT) ====\n");
	int i;
	for(i = 0; i < RPC_N; i ++){
		if(i == RPC_READ){
			performance_stats_print(retval_copy_stats + i, "read retval_copy");
			performance_stats_print_total(retval_copy_stats + i, "read retval_copy");
		} else if(i == RPC_WRITE){
			performance_stats_print(args_copy_stats + i, "write args_copy");
			performance_stats_print_total(args_copy_stats + i, "write args_copy");
		}
	}
}
#endif

