#ifndef _H_ICALL_NUMS_
#define _H_ICALL_NUMS_

#define RPC_DATA_BUFFER_SIZE 4096

#define RPC_READ 1
#define RPC_WRITE 2
#define RPC_QUIT 3

#define OCALL_GET_SERVER_EID 7
#define OCALL_GET_RECORD_SIZE 8
#define OCALL_GET_PROXY_EID 9
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

#endif
