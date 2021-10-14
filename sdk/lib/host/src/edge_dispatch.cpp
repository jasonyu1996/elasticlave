//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "edge_call.h"
#include "edge_dispatch.h"
#include "stdio.h"
#include "keystone.h"
#include "incoming_syscall.h"

#if defined(IO_SYSCALL_WRAPPING) || defined(FAST_IO_SYSCALL_WRAPPING)
#include "edge_syscall.h"
#endif /*  IO_SYSCALL_WRAPPING */

/* Registered handler for incoming edge calls */
int DefaultEdgeCallDispatcher::dispatch(Keystone* enclave, void* buffer){
    struct edge_call* edge_call = (struct edge_call*) buffer;

#if defined(IO_SYSCALL_WRAPPING) || defined(FAST_IO_SYSCALL_WRAPPING)
    /* If its a syscall handle it specially */
    if( edge_call->call_id == EDGECALL_SYSCALL){
        incoming_syscall(enclave, edge_call, &shared_region);
        return 0;
    }
#endif /*  IO_SYSCALL_WRAPPING */

    /* Otherwise try to lookup the call in the table */
    if( edge_call->call_id > MAX_EDGE_CALL ||
            edge_call_table[edge_call->call_id] == NULL ){
        /* Fatal error */
        goto fatal_error;
    }
    return edge_call_table[edge_call->call_id](enclave, buffer, &shared_region);

fatal_error:
    edge_call->return_data.call_status = CALL_STATUS_BAD_CALL_ID;
    return 0;
}


int DefaultEdgeCallDispatcher::dispatchBlocked(Keystone* enclave, void* buffer){
    struct edge_call* edge_call = (struct edge_call*) buffer;
#if defined(IO_SYSCALL_WRAPPING) || defined(FAST_IO_SYSCALL_WRAPPING)
    if( edge_call->call_id == EDGECALL_SYSCALL){
        goto fatal_error;
    }
#endif /*  IO_SYSCALL_WRAPPING */
    /* Otherwise try to lookup the call in the table */
    if( edge_call->call_id > MAX_EDGE_CALL ||
            edge_call_blocked_table[edge_call->call_id] == NULL ){
        /* Fatal error */
        goto fatal_error;
    }
    return edge_call_blocked_table[edge_call->call_id](enclave, buffer, &shared_region);

fatal_error:
    edge_call->return_data.call_status = CALL_STATUS_BAD_CALL_ID;
    return 0;
}

int DefaultEdgeCallDispatcher::register_call(unsigned long call_id, edgecallwrapper handler, edgecallwrapper blocked_handler){
    if( call_id > MAX_EDGE_CALL){
        return -1;
    }

    edge_call_table[call_id] = handler;
    edge_call_blocked_table[call_id] = blocked_handler;
    return 0;
}

