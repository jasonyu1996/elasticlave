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
#include "report.h"
#include "rpc.h"
#include "test_dev_key.h"

#define OCALL_GET_SERVER_EID 7
#define OCALL_GET_RECORD_SIZE 8

#define ENCLAVE_MAX_COUNT 8

static Keystone* enclaves[ENCLAVE_MAX_COUNT];
static int enclave_n;
static size_t record_size;
static pid_t pid;

static void* slave_run(void* _d){
	enclaves[1]->run();
}

static int get_record_size_handler(Keystone* encalve, void* buffer, struct shared_region* shared_region){
    struct edge_call* edge_call = (struct edge_call*)buffer;
	uintptr_t data_section = edge_call_data_ptr(shared_region);
	*(size_t*)data_section = record_size;
	if(edge_call_setup_ret(edge_call,
				(void*)data_section, sizeof(record_size), shared_region)){
		edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
	} else{
		edge_call->return_data.call_status = CALL_STATUS_OK;
	}
	return 0;
}

static int get_server_eid_handler(Keystone* enclave, void* buffer, struct shared_region* shared_region){
	struct edge_call* edge_call = (struct edge_call*)buffer;

	uintptr_t* data_section = (uintptr_t*)edge_call_data_ptr(shared_region);
	*data_section = enclaves[0]->getSID();

	if( edge_call_setup_ret(edge_call, (void*) data_section, \
				sizeof(int), shared_region)){
		edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
	}
	else{
		edge_call->return_data.call_status = CALL_STATUS_OK;
	}

	return 0;
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

  enclave1.init("icall-consumer-baseline-s.eapp_riscv", "eyrie-rt", params); // two identical enclaves

  enclave2.init("icall-consumer-baseline-c.eapp_riscv", "eyrie-rt", params);

  DefaultEdgeCallDispatcher dispatcher1, dispatcher2;
	enclave1.registerOcallDispatch(&dispatcher1);
	RPCServerInit(&dispatcher1, &enclave1);
	dispatcher1.register_call(OCALL_GET_RECORD_SIZE, get_record_size_handler, NULL);

	enclave2.registerOcallDispatch(&dispatcher2);
	RPCClientInit(&dispatcher2, &enclave2);
	dispatcher2.register_call(OCALL_GET_SERVER_EID, get_server_eid_handler, NULL);
	dispatcher2.register_call(OCALL_GET_RECORD_SIZE, get_record_size_handler, NULL);

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
