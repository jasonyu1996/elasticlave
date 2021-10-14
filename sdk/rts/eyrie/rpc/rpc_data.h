#ifndef __RPC_DATA_H
#define __RPC_DATA_H

#include <stdint.h>
#include <stddef.h>

#define RPC_READ 1
#define RPC_WRITE 2
#define RPC_LOCK 3
#define RPC_QUIT 4
// with secure channel
#define RPC_CREATE_CHANNEL 4
#define RPC_MAX 16

typedef unsigned char byte;

struct read_args {
	uintptr_t addr;
	size_t size;
};

struct read_ret {
	size_t size;
	byte data[];
};

struct write_args {
	uintptr_t addr;
	size_t size;
	byte data[];
};

struct write_ret {
	size_t size;
};

struct lock_args {
	int to_lock; // 0 for unlock, 1 for lock
	unsigned int lock_index;
};

struct lock_ret {
	int success;
};

#endif
