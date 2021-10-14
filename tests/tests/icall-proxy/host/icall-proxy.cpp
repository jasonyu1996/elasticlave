//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include "keystone.h"
#include "edge_wrapper.h"
#include "report.h"
#include "test_dev_key.h"
#include "edge_dispatch.h"

extern Keystone* enclaves[];
extern int enclave_n;
extern size_t record_size;

pid_t pid;

void* slave_run(void* _d){
	enclaves[1]->run();
}

int main(int argc, char* argv[])
{
  if(argc < 2)
	  return -1;
  record_size = atol(argv[1]);

  int self_timing = 0;
  int load_only = 0;

  size_t untrusted_size = 2*1024*1024;
  size_t freemem_size = 48*1024*1024;
  uintptr_t utm_ptr = (uintptr_t)DEFAULT_UNTRUSTED_PTR;

  Keystone enclave1, enclave2;
  Params params;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedMem(utm_ptr, untrusted_size);

  enclave1.init("icall-proxy-s.eapp_riscv", "eyrie-rt", params); // two identical enclaves

  enclave2.init("icall-proxy-c.eapp_riscv", "eyrie-rt", params);

  DefaultEdgeCallDispatcher dispatcher1, dispatcher2;
  edge_init(&enclave1, &dispatcher1);
  edge_init(&enclave2, &dispatcher2);

  //enclave.registerNewMemHandler(new_mem_handler);

  // while(1);
	
  enclaves[0] = &enclave1;
  enclaves[1] = &enclave2;
  enclave_n = 2;

  pthread_t slave_thread;
  pthread_create(&slave_thread, 0, slave_run, NULL);
  
  enclaves[0]->run();

  pthread_join(slave_thread, NULL);


/*  EnclaveGroup enclave_group;
  enclave_group.addEnclave(&enclave1);
  enclave_group.addEnclave(&enclave2);

  //enclave_group.run();
  enclave_group.run();
  */

  return 0;
}
