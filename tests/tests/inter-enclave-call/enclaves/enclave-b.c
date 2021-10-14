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

  int oeid = ocall_get_other_enclave();
  void* shared_mem;
  size_t size;
  do {
	  shared_mem = elasticlave_map((uintptr_t)oeid, "shared", &size);
  } while(!shared_mem);
  ocall_print_value(666);
  char* buffer = (char*)shared_mem;

  while(1){
	 while(!*buffer);
     if(*buffer == 0xff){
		 *buffer = '\0';
		 break;
	 }
	 ++ buffer;
  }
  ocall_print_buffer((char*)shared_mem, buffer - (char*)shared_mem);
  ++ buffer;
  *buffer = 0xff;

  return 0;
}

