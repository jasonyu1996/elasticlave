//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <getopt.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include "keystone.h"
#include "edge_wrapper.h"
#include "report.h"
#include "test_dev_key.h"
#include "edge_dispatch.h"

extern Keystone* enclaves[];
extern int enclave_n;

const char* longstr = "hellohellohellohellohellohellohellohellohellohello";

pid_t pid;
void* shared_buffer;

void new_mem_handler(void* mem){
	printf("Handler called\n");
	shared_buffer = mem;	
	pid = fork();
	if(!pid){
		char* c = (char*)shared_buffer;
		while(true);
		exit(0);
	}
}

unsigned long print_buffer(int eid, char* str){
  printf("[E%d]: %s", eid, str);
  return strlen(str);
}

void print_value(int eid, unsigned long val){
  printf("[E%d]: %u\n", eid, val);
  return;
}

const char* get_host_string(){
  return longstr;
}

static struct report_t report;

void print_hex(void* buffer, size_t len)
{
  int i;
  for(i = 0; i < len; i+=sizeof(uintptr_t))
  {
    printf("%.16lx ", *((uintptr_t*) ((uintptr_t)buffer + i)));
  }
  printf("\n");
}

void copy_report(void* buffer)
{
  Report report;

  report.fromBytes((unsigned char*)buffer);

  if (report.checkSignaturesOnly(_sanctum_dev_public_key))
  {
    printf("Attestation report SIGNATURE is valid\n");
  }
  else
  {
    printf("Attestation report is invalid\n");
  }
}

int main()
{
  int self_timing = 0;
  int load_only = 0;

  size_t untrusted_size = 2*1024*1024;
  size_t freemem_size = 48*1024*1024;
  uintptr_t utm_ptr = (uintptr_t)DEFAULT_UNTRUSTED_PTR;

  Keystone enclave1, enclave2;
  Params params;

  params.setFreeMemSize(freemem_size);
  params.setUntrustedMem(utm_ptr, untrusted_size);

  enclave1.init("enclave-a.eapp_riscv", "eyrie-rt", params); // two identical enclaves

  enclave2.init("enclave-b.eapp_riscv", "eyrie-rt", params);

  DefaultEdgeCallDispatcher dispatcher1, dispatcher2;
  edge_init(&enclave1, &dispatcher1);
  edge_init(&enclave2, &dispatcher2);

  //enclave.registerNewMemHandler(new_mem_handler);

  // while(1);
	
  enclaves[0] = &enclave1;
  enclaves[1] = &enclave2;
  enclave_n = 2;

  EnclaveGroup enclave_group;
  enclave_group.addEnclave(&enclave1);
  enclave_group.addEnclave(&enclave2);

  //enclave_group.run();
  enclave_group.run();

  return 0;
}
