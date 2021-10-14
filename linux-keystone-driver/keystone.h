//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <asm/sbi.h>
#include <asm/csr.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>
#include <linux/list.h>

#include <linux/file.h>

/* IMPORTANT: This code assumes Sv39 */
#include "riscv64.h"

#include "performance.h"

typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;

extern struct miscdevice keystone_dev;
extern struct list_head shm_list;
#define SBI_SM_CREATE_ENCLAVE   101
#define SBI_SM_DESTROY_ENCLAVE  102
#define SBI_SM_RUN_ENCLAVE      105
#define SBI_SM_STOP_ENCLAVE     106
#define SBI_SM_RESUME_ENCLAVE   107
#define SBI_SM_SHGET			111
#define SBI_SM_REGION_OPEN		112
#define SBI_SM_PRINT_STATS		116
#define SBI_SM_PRINT_RT_STATS	117
#define SBI_SM_ELASTICLAVE_CREATE			 109
#define SBI_SM_ELASTICLAVE_CHANGE			 110
#define SBI_SM_ELASTICLAVE_MAP		 112
#define SBI_SM_ELASTICLAVE_SHARE	118
#define SBI_SM_ELASTICLAVE_UNMAP		 119
#define SBI_SM_ELASTICLAVE_TRANSFER		 120
#define SBI_SM_ELASTICLAVE_DESTROY		 121
#define SBI_SM_ELASTICLAVE_REGION_EVENTS 122

			
// requests from the SM
#define SBI_SM_REQUEST_ARGS_LIM 8
#define SBI_SM_REQUEST_ELASTICLAVE_CREATE 1000
#define SBI_SM_REQUEST_ELASTICLAVE_DESTROY 1001


/* error codes: need to add more */
#define ENCLAVE_INTERRUPTED     2
#define ENCLAVE_NEW_MEM_REGION	100

/* don't want to taint asm/sbi.h, so just copied SBI_CALL and increased # args */
#define _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, arg5) ({			\
	register uintptr_t a0 asm ("a0") = (uintptr_t)(arg0);	\
	register uintptr_t a1 asm ("a1") = (uintptr_t)(arg1);	\
	register uintptr_t a2 asm ("a2") = (uintptr_t)(arg2);	\
	register uintptr_t a3 asm ("a3") = (uintptr_t)(arg3);	\
	register uintptr_t a4 asm ("a4") = (uintptr_t)(arg4);	\
	register uintptr_t a5 asm ("a5") = (uintptr_t)(arg5);	\
	register uintptr_t a7 asm ("a7") = (uintptr_t)(which);	\
	asm volatile ("ecall"					\
		      : "+r" (a0)				\
		      : "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r"(a5), "r" (a7)		\
		      : "memory");				\
	a0;							\
})

#define SBI_CALL_3(which, arg0, arg1, arg2) _SBI_CALL(which,arg0, arg1, arg2, 0, 0, 0)
#define SBI_CALL_4(which, arg0, arg1, arg2, arg3) _SBI_CALL(which, arg0, arg1, arg2, arg3, 0, 0)
#define SBI_CALL_5(which, arg0, arg1, arg2, arg3, arg4) _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, 0)
#define SBI_CALL_6(which, arg0, arg1, arg2, arg3, arg4, arg5) _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, arg5)

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);
int keystone_release(struct inode *inode, struct file *file);
int keystone_mmap(struct file *filp, struct vm_area_struct *vma);

/* enclave private memory */
struct epm {
  pte_t* root_page_table;
  vaddr_t ptr;
  size_t size;
  unsigned long order;
  paddr_t pa;
  bool is_cma;
};

#define UTM_MODE_R 1
#define UTM_MODE_W 2

struct utm {
  pte_t* root_page_table;
  void* ptr;
  size_t size;
  unsigned long order;
};

struct shm {
  struct list_head list;
  void* ptr; // kernel address
  paddr_t pa; // physical address
  uintptr_t va; // user virtual address
  size_t size;
  unsigned long order;
  int is_cma;
};

struct mem_mapping {
  uid_t uid;
  uintptr_t va;
  uintptr_t pa;
  size_t size;  
};


extern struct mem_mapping mem_mappings[];
extern int mem_mappings_n;

#define MAX_REQUEST_ARGS 8

enum dr_request_type {
  DR_REQUEST_NONE,
  DR_REQUEST_NEW_MEM_REGION
};

struct dr_request {
  enum dr_request_type type;
  uintptr_t args[MAX_REQUEST_ARGS];
};


struct enclave
{
  unsigned long eid;
  int close_on_pexit;
  struct utm* utm;
  struct epm* epm;
  struct shm* recent_shm;
  struct dr_request request;

  bool is_init;
  bool epm_mapped;

};

extern struct enclave host_enclave;
extern int map_pending;
extern uid_t map_uid;
extern uintptr_t map_pa, map_size;

// global debug functions
void debug_dump(char* ptr, unsigned long size);

// runtime/app loader
int keystone_rtld_init_runtime(struct enclave* enclave, void* __user rt_ptr, size_t rt_sz, unsigned long rt_stack_sz, unsigned long* rt_offset);

int keystone_rtld_init_app(struct enclave* enclave, void* __user app_ptr, size_t app_sz, size_t app_stack_sz, unsigned long stack_offset);

// untrusted memory mapper
int keystone_rtld_init_untrusted(struct enclave* enclave, void* untrusted_ptr, size_t untrusted_size);

int keystone_get_enclave_id(unsigned long ueid);

struct enclave* get_enclave_by_id(unsigned int ueid);
struct enclave* create_enclave(unsigned long min_pages);
int destroy_enclave(struct enclave* enclave);

int destroy_shm_by_pa(uintptr_t pa); 
struct shm* get_shm_by_pa(uintptr_t pa);
struct shm* get_shm_by_va(uintptr_t va);

unsigned int enclave_idr_alloc(struct enclave* enclave);
struct enclave* enclave_idr_remove(unsigned int ueid);
struct enclave* get_enclave_by_id(unsigned int ueid);

static inline uintptr_t  epm_satp(struct epm* epm) {
  return ((uintptr_t)epm->root_page_table >> RISCV_PGSHIFT | SATP_MODE_CHOICE);
}

int epm_destroy(struct epm* epm);
int epm_init(struct epm* epm, unsigned int count);
int utm_destroy(struct utm* utm);
int utm_init(struct utm* utm, size_t untrusted_size);
int shm_destroy(struct shm* shm);
int shm_init(struct shm* shm, size_t shared_size);
paddr_t epm_va_to_pa(struct epm* epm, vaddr_t addr);
uintptr_t enclave_elasticlave_create(struct enclave* enclave, uintptr_t size);


unsigned long calculate_required_pages(
		unsigned long eapp_sz,
		unsigned long eapp_stack_sz,
		unsigned long rt_sz,
		unsigned long rt_stack_sz);

struct enclave_stats {
	struct performance_stats switch_to_enclave;
	struct performance_stats switch_to_host;
	struct performance_stats enclave_execution;
	struct performance_stats host_execution;
};

#define keystone_info(fmt, ...) \
  pr_info("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_err(fmt, ...) \
  pr_err("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_warn(fmt, ...) \
  pr_warn("keystone_enclave: " fmt, ##__VA_ARGS__)
#endif
