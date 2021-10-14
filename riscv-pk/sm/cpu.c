//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "cpu.h"
#include "enclave.h"

static struct cpu_state cpus[MAX_HARTS];

int cpu_is_enclave_context_idx(int i){
  return cpus[i].is_enclave != 0;
}

int cpu_get_enclave_id_idx(int i){
  return encl_index(encl_get(cpus[i].eid));
}

int cpu_is_enclave_context()
{
  return cpus[read_csr(mhartid)].is_enclave != 0;
}

int cpu_get_enclave_id()
{
  int k = read_csr(mhartid);
  if(cpus[k].is_enclave)
	  return cpus[k].eid;
  return 0;
}


void cpu_enter_enclave_context(enclave_id eid)
{
  cpus[read_csr(mhartid)].is_enclave = 1;
  cpus[read_csr(mhartid)].eid = eid;
}

void cpu_exit_enclave_context()
{
  cpus[read_csr(mhartid)].is_enclave = 0;
}

void cpu_set_to_terminate(int to_terminate){
  cpus[read_csr(mhartid)].to_terminate = to_terminate;
}

int cpu_is_to_terminate(){
  return cpus[read_csr(mhartid)].to_terminate;
}

