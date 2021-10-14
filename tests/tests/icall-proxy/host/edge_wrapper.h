//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include "edge_call.h"
#include "keystone.h"
#include "edge_dispatch.h"

typedef struct packaged_str{
  unsigned long str_offset;
  size_t len;
} packaged_str_t;

typedef unsigned char byte;

int edge_init(Keystone* enclave, DefaultEdgeCallDispatcher* dispatcher);
int get_other_enclave_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region);
int get_record_size_wrapper(Keystone* enclave, void* buffer, struct shared_region* shared_region);
const char* get_host_string();

#endif /* _EDGE_WRAPPER_H_ */
