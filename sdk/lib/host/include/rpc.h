#ifndef __RPC_H
#define __RPC_H

#include "keystone.h"
#include "edge_dispatch.h"

int RPCServerInit(DefaultEdgeCallDispatcher* dispatcher,
		Keystone* enclave);
int RPCClientInit(DefaultEdgeCallDispatcher* dispatcher,
		Keystone* enclave);
void RPCServerClose(Keystone* enclave);

#endif

