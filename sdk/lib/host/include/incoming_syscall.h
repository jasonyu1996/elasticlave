#ifndef _INCOMING_SYSCALL_H
#define _INCOMING_SYSCALL_H

#include "keystone.h"

void incoming_syscall(Keystone* enclave, struct edge_call* buffer, struct shared_region* shared_region);

#endif

