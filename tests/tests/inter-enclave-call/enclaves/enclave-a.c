//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"

int main(){
  edge_init();
  char* msg = "Hello World!\n";

  int oeid = ocall_get_other_enclave();
  void* shared_mem = elasticlave_create("shared", 4096, 0);
  char* buffer = (char*)shared_mem;
  elasticlave_change((uintptr_t)shared_mem, (uintptr_t)oeid, 1);

  while(*msg){
	  *buffer = *msg;
	  ++ msg;
	  ++ buffer;
  }
  *buffer = 0xff;
  ++ buffer;
  elasticlave_change((uintptr_t)shared_mem, (uintptr_t)oeid, 3);
  while(*buffer != 0xff);

  return 0;
}

