//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "edge_wrapper.h"
#include "edge_call.h"

void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
}

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_GET_STRING 4
#define OCALL_GET_OTHER_ENCLAVE 5

void ocall_print_value(unsigned long val){

  unsigned long val_ = val;
  ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

  return;
}

unsigned long ocall_print_buffer(char* data, size_t data_len){

  unsigned long retval;
  ocall(OCALL_PRINT_BUFFER, data, data_len, &retval ,sizeof(unsigned long));

  return retval;
}

void ocall_get_string(struct edge_data* retdata){
  ocall(OCALL_GET_STRING, NULL, 0, retdata, sizeof(struct edge_data));
  return;
}

int ocall_get_other_enclave(){
   int retval;
   ocall(OCALL_GET_OTHER_ENCLAVE, NULL, 0, &retval, sizeof(retval));
   return retval;
}

