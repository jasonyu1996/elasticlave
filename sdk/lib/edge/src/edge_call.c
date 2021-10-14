//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <edge_call.h>
#include <string.h>
#include <stdio.h>

void shared_region_init(uintptr_t buffer_start, size_t buffer_len, struct shared_region* shared_region ){
    shared_region->shared_start = buffer_start;
    shared_region->shared_len = buffer_len;
}

int edge_call_get_ptr_from_offset(edge_data_offset offset, size_t data_len,
        uintptr_t* ptr, struct shared_region* shared_region){

    //TODO double check these checks

    /* Validate that shared_region->shared_start+offset is sane */
    if( offset > UINTPTR_MAX - shared_region->shared_start ||
            offset > shared_region->shared_len ){
        return -1;
    }


    /* Validate that shared_region->shared_start+offset+data_len in range */
    if( data_len > UINTPTR_MAX - (shared_region->shared_start+offset) ||
            data_len > shared_region->shared_len - offset ){
        return -1;
    }

    /* ptr looks valid, create it */
    *ptr = shared_region->shared_start+offset;
    return 0;
}


int edge_call_check_ptr_valid(uintptr_t ptr, size_t data_len, struct shared_region* shared_region ){

    //TODO double check these checks

    /* Validate that ptr starts in range */
    if( ptr > shared_region->shared_start+shared_region->shared_len ||
            ptr < shared_region->shared_start ){
        return 1;
    }

    if( data_len > UINTPTR_MAX - ptr){
        return 2;
    }

    /* Validate that the end is in range */
    if( ptr+data_len  > shared_region->shared_start+shared_region->shared_len){
        return 3;
    }

    return 0;
}

int edge_call_get_offset_from_ptr(uintptr_t ptr, size_t data_len,
        edge_data_offset* offset, struct shared_region* shared_region ){
    int valid = edge_call_check_ptr_valid(ptr, data_len, shared_region);
    if( valid != 0){
        return valid;
    }

    /* ptr looks valid, create it */
    *offset = ptr-shared_region->shared_start;
    return 0;
}


int edge_call_args_ptr(struct edge_call* edge_call, uintptr_t* ptr, size_t* size, struct shared_region* shared_region ){
    *size = edge_call->call_arg_size;
    return edge_call_get_ptr_from_offset(edge_call->call_arg_offset,
            *size, ptr, shared_region );
}

int edge_call_ret_ptr(struct edge_call* edge_call, uintptr_t* ptr, size_t* size, struct shared_region* shared_region ){
    *size = edge_call->return_data.call_ret_size;
    return edge_call_get_ptr_from_offset(edge_call->return_data.call_ret_offset,
            *size, ptr, shared_region);
}

int edge_call_setup_call(struct edge_call* edge_call, void* ptr, size_t size, struct shared_region* shared_region ){
    edge_call->call_arg_size = size;
    return edge_call_get_offset_from_ptr((uintptr_t)ptr, size,
            &edge_call->call_arg_offset, shared_region);
}

int edge_call_setup_ret(struct edge_call* edge_call, void* ptr, size_t size, struct shared_region* shared_region ){
    edge_call->return_data.call_ret_size = size;
    return edge_call_get_offset_from_ptr((uintptr_t)ptr, size,
            &edge_call->return_data.call_ret_offset, shared_region);
}

/* This is only usable for the host */
int edge_call_setup_wrapped_ret(struct edge_call* edge_call, void* ptr, size_t size, struct shared_region* shared_region ){
    struct edge_data data_wrapper;
    data_wrapper.size = size;
    edge_call_get_offset_from_ptr(shared_region->shared_start+sizeof(struct edge_call)+sizeof(struct edge_data),
            sizeof(struct edge_data),
            &data_wrapper.offset,
            shared_region);

    memcpy((void*)(shared_region->shared_start+sizeof(struct edge_call)+sizeof(struct edge_data)),
            ptr,
            size);

    memcpy((void*)(shared_region->shared_start+sizeof(struct edge_call)),
            &data_wrapper,
            sizeof(struct edge_data));

    edge_call->return_data.call_ret_size = sizeof(struct edge_data);
    return edge_call_get_offset_from_ptr(shared_region->shared_start+sizeof(struct edge_call),
            sizeof(struct edge_data),
            &edge_call->return_data.call_ret_offset, shared_region);
}


/* This is temporary until we have a better way to handle multiple things */
uintptr_t edge_call_data_ptr(struct shared_region* shared_region ){
    return shared_region->shared_start + sizeof(struct edge_call);
}
