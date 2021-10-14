//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <stddef.h>
#include <cerrno>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>
#include "common.h"
#include "elffile.h"
#include "params.h"
#include "sha3.h"
#include "memory.h"
#include "edge_dispatch.h"
#include "performance.h"

#define MAX_DR_REQUEST_ARGS 8

class Keystone;
typedef void (*NewMemHandler)(void*);
typedef sha3_ctx_t hash_ctx_t;

#define REGIONS_MAX 32


inline static void print_enclave_stats(struct enclave_stats* stats){
	performance_stats_print_total(&stats->switch_to_enclave, "Switch to enclave");
	performance_stats_print_total(&stats->switch_to_host, "Switch to host");
	performance_stats_print_total(&stats->enclave_execution, "Enclave execution");
	performance_stats_print_total(&stats->host_execution, "Host execution");
}

inline static void print_enclave_rt_stats(struct enclave_rt_stats* rt_stats){
	performance_stats_print(&rt_stats->args_copy_stats, "RT Args Copy");
	performance_stats_print_total(&rt_stats->args_copy_stats, "RT Args Copy");
	performance_stats_print(&rt_stats->retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&rt_stats->retval_copy_stats, "RT Retval Copy");
	performance_stats_print_total(&rt_stats->page_fault_stats, "RT Page Fault");
	performance_stats_print_total(&rt_stats->stats_sbi, "RT SBI");
	performance_stats_print_total(&rt_stats->stats_rt, "RT Total");
	performance_stats_print_total(&rt_stats->stats_boot_sbi, "RT Boot SBI");
	performance_stats_print_total(&rt_stats->stats_boot, "RT Boot Total");
}

enum enclave_state {
	ENCLAVE_STATE_INVALID,
	ENCLAVE_STATE_INITIALISED,
	ENCLAVE_STATE_LAUNCHED,
	ENCLAVE_STATE_BLOCKED,
	ENCLAVE_STATE_ENDED
};

struct ecall_stats {
	struct performance_stats args_copy_stats;
	struct performance_stats retval_copy_stats; 
};

inline static void init_ecall_stats(struct ecall_stats* stats){
	performance_stats_init(&stats->args_copy_stats);
	performance_stats_init(&stats->retval_copy_stats);
}

inline static void print_ecall_stats(struct ecall_stats* stats){
	performance_stats_print(&stats->args_copy_stats, "Host args copy (SDK)");
	performance_stats_print_total(&stats->args_copy_stats, "Host args copy (SDK) Total");
	performance_stats_print(&stats->retval_copy_stats, "Host retval copy (SDK)");
	performance_stats_print_total(&stats->retval_copy_stats, "Host retval copy (SDK) Total");
}

class EdgeCallDispatcher;

class Keystone
{
private:
  enum enclave_state state;
  Params params;
  ELFFile* runtimeFile;
  ELFFile* enclaveFile;
  Memory* pMemory;
  char hash[MDSIZE];
  hash_ctx_t hash_ctx;
  vaddr_t enclave_stk_start;
  vaddr_t enclave_stk_sz;
  vaddr_t runtime_stk_sz;
  vaddr_t untrusted_size;
  vaddr_t untrusted_start;
  vaddr_t pt_free_list;
  vaddr_t epm_free_list;
  vaddr_t root_page_table;
  vaddr_t utm_free_list;
  vaddr_t start_addr;
  int eid;
  int fd;
  void* shared_buffer;
  size_t shared_buffer_size;

  void* o_shared_buffer;
  size_t o_shared_buffer_size;

  struct ecall_stats ecall_stats;
  struct performance_stats run_stats;

  /* ecall */
  unsigned long target_call_id;

  EdgeCallDispatcher* ocall_dispatcher;
  keystone_status_t mapUntrusted(size_t size);
  keystone_status_t loadUntrusted();
  keystone_status_t loadELF(ELFFile* file, uintptr_t* data_start);
  keystone_status_t initStack(vaddr_t start, size_t size, bool is_rt);
  keystone_status_t allocPage(vaddr_t va, vaddr_t free_addr, unsigned int mode);
  keystone_status_t validate_and_hash_enclave(struct runtime_params_t args, struct keystone_hash_enclave* cargs);
  NewMemHandler new_mem_handler;

  bool initFiles(const char*, const char*);
  bool initDevice();
  bool prepareEnclave(struct keystone_ioctl_create_enclave*, uintptr_t alternate_phys_addr);
  bool initMemory();
  void process_new_memory_region(uintptr_t size);

  struct keystone_ioctl_run_enclave run_args;
  uintptr_t dr_request_args[MAX_DR_REQUEST_ARGS];

  // directly return after being stopped
  uid_t region_uids[REGIONS_MAX];
  void* region_bufs[REGIONS_MAX];
  int region_n;

public:
  void* custom; // custom data

  Keystone();
  ~Keystone();
  void* getSharedBuffer();
  size_t getSharedBufferSize();
  int getID() const{
	  return eid;
  }
  int getSID() const;
  keystone_status_t registerOcallDispatch(EdgeCallDispatcher* dispatcher);
  keystone_status_t init(const char* filepath, const char* runtime, Params parameters);
  keystone_status_t init(const char *eapppath, const char *runtimepath, Params _params, uintptr_t alternate_phys_addr);
  keystone_status_t measure(const char* filepath, const char* runtime, Params parameters);
  keystone_status_t destroy();
  keystone_status_t runOnce(int* ret_code);
  keystone_status_t run();
  keystone_status_t call(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len);
  keystone_status_t call_with_stats(unsigned long call_id, void* data, size_t data_len, void* return_buffer, size_t return_len, struct ecall_stats* stats);
  int print_sm_stats(struct enclave_stats* stats);
  int print_rt_stats(struct enclave_rt_stats* rt_stats);
  void add_region_buffer(uid_t uid, void* buf);
  void* get_region_buffer(uid_t uid) const;

  void set_target_call(unsigned long target);
  void print_call_stats();
  keystone_status_t registerNewMemHandler(NewMemHandler handler);
  struct performance_stats get_run_stats() const;
  enum enclave_state getState() const;
  friend class EnclaveGroup;

  // elasticlave interfaces
  keystone_status_t elasticlave_share(uid_t uid, unsigned long perm);
  keystone_status_t elasticlave_transfer(uid_t uid);


  bool futex_initialised;
  int *shared_futex_start, *local_futex_start;
  uintptr_t in_enclave_shared_futex_start; // the address inside enclave
  pthread_mutex_t* futex_mutex;
};

#define ENCLAVE_GROUP_MAX 8

class EnclaveGroup {
	private:
		Keystone* enclaves[ENCLAVE_GROUP_MAX];
		int enclave_n;
	public:
		EnclaveGroup() : enclave_n(0) {}
		void addEnclave(Keystone* enclave){
			enclaves[enclave_n ++] = enclave;
		}
		keystone_status_t run();
};

unsigned long calculate_required_pages(
        unsigned long eapp_sz,
        unsigned long eapp_stack_sz,
        unsigned long rt_sz,
        unsigned long rt_stack_sz);

extern "C" {
	uid_t elasticlave_create(size_t size);
	int elasticlave_change(uid_t uid, unsigned long perm);
	int elasticlave_unmap(void* vaddr);
	void* elasticlave_map(uid_t uid);
	int elasticlave_destroy(uid_t uid);
}

bool keystone_init();

#endif
