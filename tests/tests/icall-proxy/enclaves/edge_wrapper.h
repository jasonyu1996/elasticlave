//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"

void edge_init();

#define ICALL_OPEN_REGIONS 1
#define ICALL_WORK_BUFFER 2
#define OCALL_GET_OTHER_ENCLAVE 5
#define ICALL_END 3
#define ICALL_PRINT_STATS 4

int ocall_get_other_enclave();
size_t ocall_get_record_size();
void icall_open_regions(uintptr_t enclave_id);
void icall_work_buffer(uintptr_t enclave_id, void* out_buf, size_t record_size);
void icall_print_stats(uintptr_t enclave_id);
void icall_end(uintptr_t enclave_id);
void icall_init(uintptr_t enclave_id);
#endif /* _EDGE_WRAPPER_H_ */

