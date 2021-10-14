#ifndef __RPC_H
#define __RPC_H

#include <stdint.h>
#include <stddef.h>

size_t rpc_read(uintptr_t addr, size_t size, void* buffer);
size_t rpc_write(uintptr_t addr, size_t size, void* buffer);
int rpc_lock(unsigned int lock_index);
int rpc_unlock(unsigned int lock_index);
void rpc_quit();

size_t rpc_secure_read(uintptr_t addr, size_t size, void* buffer);
size_t rpc_secure_write(uintptr_t addr, size_t size, void* buffer);
int rpc_secure_lock(unsigned int lock_index);
int rpc_secure_unlock(unsigned int lock_index);
void rpc_secure_quit();


void rpc_init();
#ifdef PERFORMANCE_MEASURE
void rpc_stats_print();
#endif

#endif

