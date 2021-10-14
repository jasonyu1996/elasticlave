//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "mm.h"
#include "rt_util.h"
#include "printf.h"
#include "uaccess.h"
#include "vm.h"
#include "rpc.h"
#include "fp.h"
#include "string.h"
#include "performance.h"

typedef uint32_t insn_t;

// Statically allocated copy-buffer
unsigned char rt_copy_buffer_1[RISCV_PAGE_SIZE];
unsigned char rt_copy_buffer_2[RISCV_PAGE_SIZE];

static uintptr_t mem_handler_entry;

#define STATUS_SPP (1U << 8)

static inline int trap_is_from_user(struct encl_ctx* ctx){
	return (ctx->sstatus & STATUS_SPP) == 0;
}

size_t rt_util_getrandom(void* vaddr, size_t buflen){
  size_t remaining = buflen;
  uintptr_t rnd;
  uintptr_t* next = (uintptr_t*)vaddr;
  // Get data
  while(remaining > sizeof(uintptr_t)){
    rnd = sbi_random();
    ALLOW_USER_ACCESS( *next = rnd );
    remaining -= sizeof(uintptr_t);
    next++;
  }
  // Cleanup
  if( remaining > 0 ){
    rnd = sbi_random();
    copy_to_user(next, &rnd, remaining);
  }
  size_t ret = buflen;
  return ret;
}

void rt_util_misc_fatal(){
  //Better hope we can debug it!
  sbi_exit_enclave(-1, kernel_va_to_pa(&stats));
}

uintptr_t not_implemented_fatal(struct encl_ctx* ctx, unsigned long start_cycle){
#ifdef FATAL_DEBUG
    unsigned long addr, cause, pc;
    pc = ctx->regs.sepc;
    addr = ctx->sbadaddr;
    cause = ctx->scause;
    printf("[runtime] non-handlable interrupt/exception at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
	printf("[runtime] registers:\r\n");
	uintptr_t i;
	for(i = 0; i < sizeof(struct regs); i += sizeof(uintptr_t)){
		printf("--- %lx\r\n", *(uintptr_t*)(i + (uintptr_t)&ctx->regs));
	}
#endif

    // Bail to m-mode
    asm volatile ("csrr a0, scause\r\nli a7, 1111\r\n ecall");

	performance_check_start_with(&stats.stats_rt, start_cycle);
	performance_count(&stats.stats_rt);
    return (uintptr_t)&stats.stats_rt.total_cycle;
}

uintptr_t rt_page_fault(struct encl_ctx* ctx, unsigned long start_cycle)
{

  unsigned long addr, cause, pc;
  pc = ctx->regs.sepc;
  addr = ctx->sbadaddr;
  cause = ctx->scause;

#ifdef VSHMEM_ENABLED
  // load or store page fault
  if(addr >= EYRIE_VSHM_REGION_START &&
		  addr < EYRIE_VSHM_REGION_END &&
		  (cause == 13 || cause == 15)){
	  insn_t insn = (insn_t)get_word_from_user((void*)pc);
	  unsigned long addr_offset = addr - EYRIE_VSHM_REGION_START;
	  unsigned int type, reg;
	  unsigned int width, extend;
	  int success = 1, is_fp = 0, insn_width;
	  uintptr_t buffer;

	  if((insn & 3) == 3){
		// uncompressed instruction
		insn_width = 4;
		type = (insn >> 12) & 7;
		width = 1 << (type & 3);
		extend = (type >> 2) & 1;
		switch(insn & 0x7c){
			case 0x4:
				// load fp
			    is_fp = 1;
			case 0x0: 
				// load
				if(cause != 13){
					success = 0;
					break;
				}
				reg = (insn >> 7) & 31;
				break;
			case 0x24:
				// store fp
			    is_fp = 1;
			case 0x20:
				// store
				if(cause != 15){
					success = 0;
					break;
				}
				reg = (insn >> 20) & 31;
				break;
			default:
				success = 0;
		}
	  } else if((insn & 3) == 0){
		  insn_width = 2;
		  reg = ((insn >> 2) & 7) + 8;
		  if(((insn >> 15) & 1) ^ (cause == 13)){
			  switch((insn >> 13) & 3){
				  case 0:
					  success = 0;
					  break;
				  case 1: // fld or fsd
					  width = 8;
					  is_fp = 1;
					  break;
				  default:
					  width = 1 << ((insn >> 13) & 3);
					  extend = 0;
			  }
		  } else
			  success = 0;
	  } else
		  success = 0;

	  if(!success)
		  sbi_exit_enclave(-1, kernel_va_to_pa(&stats));
	  if(cause == 13){
		  buffer = 0;
		  rpc_read(addr_offset, width, &buffer);
		  if(!is_fp && reg){
			  int bitwidth = width << 3;
			  if(!extend && width != 8 && ((buffer >> (bitwidth - 1)) & 1)){
				  buffer |= ((uintptr_t)-1 >> bitwidth) << bitwidth;
			  }
			  ((uintptr_t*)&ctx->regs)[reg] = (uintptr_t)buffer;
		  } else if(is_fp){
			  if(width == 8)
				  write_double(reg, buffer);
			  else
				  write_float(reg, buffer);
		  }
	  } else if(cause == 15){
		  if(is_fp){
			  buffer = width == 8 ? read_double(reg) : read_float(reg);
		  } else{
			  buffer = reg ? (unsigned long)((uintptr_t*)&ctx->regs)[reg] : 0;
		  }
		  rpc_write(addr_offset, width, &buffer);
	  }
	  ctx->regs.sepc += insn_width;

	  performance_check_start_with(&stats.page_fault_stats, start_cycle);
	  performance_count(&stats.page_fault_stats);
	  return (uintptr_t)&stats.page_fault_stats.total_cycle;
  }
#endif

#ifdef FATAL_DEBUG
  printf("[runtime] page fault at 0x%lx on 0x%lx (scause: 0x%lx)\r\n", pc, addr, cause);
#endif

  sbi_exit_enclave(-1, kernel_va_to_pa(&stats));

  /* never reach here */
  assert(false);
  performance_check_start_with(&stats.page_fault_stats, start_cycle);
  performance_count(&stats.page_fault_stats);
  return (uintptr_t)&stats.page_fault_stats.total_cycle;
}

#define STACK_PAD 32

#define FAULT_LOAD 5
#define FAULT_STORE 7
#define FAULT_FETCH 1

void mem_access_handler_setup(struct regs* regs, uintptr_t event_no, uid_t uid){
	// set up handler execution environment
	// TODO: sanitation check on sp
	if(!mem_handler_entry)
		return;
	uintptr_t user_sp = regs->sp;
	user_sp -= sizeof(struct regs) + STACK_PAD;
	copy_to_user((void*)user_sp, regs, sizeof(struct regs));
	uintptr_t user_gp = regs->gp,
			  user_tp = regs->tp;
	memset(regs, 0, sizeof(struct regs));
	regs->gp = user_gp;
	regs->tp = user_tp;
	regs->sp = user_sp;
	// arguments to the handler
	// arg0: event number
	// arg1: uid
	// arg2: pointer to regs
	regs->a0 = event_no;
	regs->a1 = (uintptr_t)uid;
	regs->a2 = user_sp;
	regs->sepc = mem_handler_entry;
}

uintptr_t mem_access_fault(struct encl_ctx* ctx, unsigned long start_cycle){
	unsigned long cause = ctx->scause;
	uintptr_t event_no;
	if(trap_is_from_user(ctx)){
		switch(cause){
			case FAULT_LOAD:
				event_no = MEM_ACCESS_LOAD;
				break;
			case FAULT_STORE:
				event_no = MEM_ACCESS_STORE;
				break;
			case FAULT_FETCH:
				event_no = MEM_ACCESS_FETCH;
				break;
			default:
				event_no = MEM_ACCESS_UNKNOWN;
		}
		struct vma* vma = get_vma_by_va(ctx->sbadaddr);
		if(vma == NULL || vma->type != VMA_TYPE_SHARED){
			printf("VMA not found: %lx\n", ctx->sbadaddr);
			return 0;
		}
		mem_access_handler_setup(&ctx->regs, event_no, vma->uid);
	}

	return 0;
}


#define REGION_EVENT_TRANSFERRED 0
#define REGION_EVENT_ACQUIRED 1
#define REGION_EVENT_RELEASED 2
#define REGION_EVENT_DESTROYED 3

void deliver_region_event(struct encl_ctx* ctx, int uid, int type){
	int event_no;
	switch(type){
		case REGION_EVENT_TRANSFERRED:
			event_no = MEM_ACCESS_REG_TR;
			break;
		case REGION_EVENT_ACQUIRED:
			event_no = MEM_ACCESS_REG_AC;
			break;
		case REGION_EVENT_RELEASED:
			event_no = MEM_ACCESS_REG_RE;
			break;
		case REGION_EVENT_DESTROYED:
			event_no = MEM_ACCESS_REG_XX;
			break;
		default:
			event_no = MEM_ACCESS_UNKNOWN;
	}
	mem_access_handler_setup(&ctx->regs, event_no, (uid_t)uid);
}

void tlb_flush(void)
{
  asm volatile ("fence.i\t\nsfence.vma\t\n");
}

void rt_page_fault_init(void){
  performance_stats_init(&stats.page_fault_stats);
}

void register_mem_handler(uintptr_t handler_entry){
	mem_handler_entry = handler_entry;
}

void mem_handler_return(uintptr_t user_regs, struct regs* regs){
	copy_from_user(regs, (void*)user_regs, sizeof(struct regs));	
}

