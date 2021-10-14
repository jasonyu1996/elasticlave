#ifndef ENCLAVE_REQUEST_H
#define ENCLAVE_REQUEST_H

#define ENCLAVE_REQUEST_ARGS_LIM 8

enum enclave_request_type {
  REQUEST_NO_REQUEST,
  REQUEST_ELASTICLAVE_CREATE,
  REQUEST_ELASTICLAVE_DESTROY
};


struct enclave_request {
  enum enclave_request_type type;
  uintptr_t args[ENCLAVE_REQUEST_ARGS_LIM];
};

/*
args:
SHAREDALLOC: size, perm
*/




#endif
