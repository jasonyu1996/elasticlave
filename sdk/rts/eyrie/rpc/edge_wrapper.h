//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"
#include "edge_wrapper_data.h"

void edge_init();

void rpc_issue(struct ecall_parcel* parcel, struct ecall_ret* retval, size_t ret_size_lim, int secure);

#endif /* _EDGE_WRAPPER_H_ */
