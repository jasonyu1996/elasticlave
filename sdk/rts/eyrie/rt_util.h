#ifndef _RT_UTIL_H_
#define _RT_UTIL_H_

#include "regs.h"
#include <stddef.h>
#include "vm.h"
#include "types.h"

#define FATAL_DEBUG

#define MEM_ACCESS_UNKNOWN 0
#define MEM_ACCESS_LOAD 1
#define MEM_ACCESS_STORE 2
#define MEM_ACCESS_FETCH 3
#define MEM_ACCESS_REG_AC 4
#define MEM_ACCESS_REG_RE 5
#define MEM_ACCESS_REG_TR 6
#define MEM_ACCESS_REG_XX 7


size_t rt_util_getrandom(void* vaddr, size_t buflen);
uintptr_t not_implemented_fatal(struct encl_ctx* ctx, unsigned long start_cycle);
void rt_util_misc_fatal();
uintptr_t rt_page_fault(struct encl_ctx* ctx, unsigned long start_cycle);
void tlb_flush(void);
void rt_page_fault_init(void);
uintptr_t mem_access_fault(struct encl_ctx* ctx, unsigned long start_cycle);
void register_mem_handler(uintptr_t handler_entry);
void mem_handler_return(uintptr_t user_regs, struct regs* regs);
void mem_access_handler_setup(struct regs* regs, uintptr_t event_no, uid_t uid);
void deliver_region_event(struct encl_ctx* ctx, int uid, int ype);

extern unsigned char rt_copy_buffer_1[RISCV_PAGE_SIZE];
extern unsigned char rt_copy_buffer_2[RISCV_PAGE_SIZE];

#endif /* _RT_UTIL_H_ */
