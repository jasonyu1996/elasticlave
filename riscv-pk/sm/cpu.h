//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __CPU_H__
#define __CPU_H__

#include "sm.h"
#include "sm_types.h"

/* hart state for regulating SBI */
struct cpu_state
{
  int is_enclave;
  enclave_id eid;
  int to_terminate;
};

/* external functions */
int cpu_is_enclave_context();
int cpu_get_enclave_id();
void cpu_enter_enclave_context(enclave_id eid);
void cpu_exit_enclave_context();
int cpu_get_enclave_id_idx(int i);
int cpu_is_enclave_context_idx(int i);
// enclave is going to terminate
void cpu_set_to_terminate(int to_terminate);
int cpu_is_to_terminate();

#endif
