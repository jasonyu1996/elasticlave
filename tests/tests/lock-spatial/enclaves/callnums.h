#ifndef _H_CALLNUMS_
#define _H_CALLNUMS_


#define RPC_DATA_BUFFER_SIZE 4096

#define RPC_READ 1
#define RPC_WRITE 2
#define RPC_LOCK 3
#define RPC_QUIT 4

#define OCALL_GET_THREAD_COUNT 7
#define OCALL_GET_SERVER_EID 8
#define OCALL_GET_CONTENTION 9
#define ICALL_WORK_BUFFER 2
#define ICALL_QUIT 3
#define ICALL_SET_BUFFER 4

// buffer type
#define BUFFER_IN 0
#define BUFFER_OUT 1

struct buffer_info {
  uid_t uid;
  int buffer_type;
};

struct write_args {
  uintptr_t addr;
  size_t size;
  char data[];
};

struct write_ret {
  size_t size;
};

struct read_args {
  uintptr_t addr;
  size_t size;
};

struct read_ret {
  size_t size;
  char data[];
};

struct lock_args {
	int to_lock; // 0 for unlock, 1 for lock
	unsigned int lock_index;
};

struct lock_ret {
	int success;
};

#endif

