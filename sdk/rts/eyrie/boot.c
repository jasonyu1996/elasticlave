#include <asm/csr.h>

#include "rpc.h"
#include "printf.h"
#include "interrupt.h"
#include "syscall.h"
#include "vm.h" 
#include "string.h"
#include "sbi.h"
#include "freemem.h"
#include "mm.h"
#include "env.h"
#include "paging.h"
#include "rt_util.h"
#include "performance.h"

rt_performance_stats_t stats;

/* defined in vm.h */
extern uintptr_t shared_buffer;
extern uintptr_t shared_buffer_size;

/* initial memory layout */
uintptr_t utm_base;
size_t utm_size;

int eid;

/* defined in entry.S */
extern void* encl_trap_handler;

#ifdef USE_FREEMEM


/* map entire enclave physical memory so that
 * we can access the old page table and free memory */
/* remap runtime kernel to a new root page table */
void
map_physical_memory(uintptr_t dram_base,
                    uintptr_t dram_size)
{
  uintptr_t ptr = EYRIE_LOAD_START;
  /* load address should not override kernel address */
  //assert(RISCV_GET_PT_INDEX(ptr, 1) != RISCV_GET_PT_INDEX(runtime_va_start, 1));
  map_with_reserved_page_table(dram_base, dram_size, ptr);
}

void
remap_kernel_space(uintptr_t runtime_base,
                   uintptr_t runtime_size)
{
  /* eyrie runtime is supposed to be smaller than a megapage */
  //assert(runtime_size <= RISCV_GET_LVL_PGSIZE(2));

  map_with_reserved_page_table(runtime_base, runtime_size, runtime_va_start);
}

void
copy_page_table(pte* old_page_table, pte* new_page_table, int lvl)
{
  /* the old table lives in the first page */
  int i;

  /* copy all valid entries of the old root page table */
  for (i = 0; i < BIT(RISCV_PT_INDEX_BITS); i++) {
	if(old_page_table[i] & PTE_V){
		if((new_page_table[i] & PTE_V) && lvl < 2){
			pte* old_pte = (pte*)__va((uintptr_t)pte_ppn(old_page_table[i]) << RISCV_PAGE_BITS);
			pte* new_pte = (pte*)__va((uintptr_t)pte_ppn(new_page_table[i]) << RISCV_PAGE_BITS);
			copy_page_table(old_pte, new_pte, lvl+1);
		} else if(!(new_page_table[i] & PTE_V)){
		    new_page_table[i] = old_page_table[i];
		}
	}
  }
}


void copy_root_page_table(){
  pte* old_root_page_table = (pte*) EYRIE_LOAD_START;
  copy_page_table(old_root_page_table, root_page_table, 0);
  tlb_flush();
}


/* initialize free memory with a simple page allocator*/
void
init_freemem()
{
  spa_init(freemem_va_start, freemem_size);
}

#endif // USE_FREEMEM

/* initialize user stack */
void
init_user_stack_and_env()
{
  void* user_sp = (void*) EYRIE_USER_STACK_START;

#ifdef USE_FREEMEM
  size_t count;
  uintptr_t stack_end = EYRIE_USER_STACK_END;
  size_t stack_count = EYRIE_USER_STACK_SIZE >> RISCV_PAGE_BITS;


  // allocated stack pages right below the runtime
  count = alloc_pages(vpn(stack_end), stack_count,
      PTE_R | PTE_W | PTE_D | PTE_A | PTE_U);

  assert(count == stack_count);

#endif // USE_FREEMEM

  // setup user stack env/aux
  user_sp = setup_start(user_sp);

  // prepare user sp
  csr_write(sscratch, user_sp);
}

void
eyrie_boot(uintptr_t enclave_id, // $a0 contains the return value from the SBI
           uintptr_t dram_base,
           uintptr_t dram_size,
           uintptr_t runtime_paddr,
           uintptr_t user_paddr,
           uintptr_t free_paddr,
           uintptr_t utm_vaddr,
           uintptr_t utm_size) // enclave id used by the security monitor
{
  performance_stats_init(&stats.stats_boot);
  performance_check_start(&stats.stats_boot);

  performance_stats_init(&stats.stats_sbi);

  /* set initial values */
  load_pa_start = dram_base;
  shared_buffer = utm_vaddr;
  shared_buffer_size = utm_size;
  runtime_va_start = (uintptr_t) &rt_base;
  kernel_offset = runtime_va_start - runtime_paddr;
  uintptr_t sepc = csr_read(sepc);
  printf("Enclave ID = %lx\n", enclave_id);
  printf("EAPP entry = %lx", sepc);
  printf("DRAM = %lx, %lx, UTM = %lx, %lx\n", dram_base, dram_size, utm_vaddr, utm_size);
  //printf("User Paddr = %lx, Runtime Paddr = %lx\n, Runtime va start = %lx\n", user_paddr, runtime_paddr, runtime_va_start);

  debug("UTM : 0x%lx-0x%lx (%u KB)", utm_vaddr, utm_vaddr+utm_size, utm_size/1024);
  debug("DRAM: 0x%lx-0x%lx (%u KB)", dram_base, dram_base + dram_size, dram_size/1024);
#ifdef USE_FREEMEM
  freemem_va_start = __va(free_paddr);
  freemem_size = dram_base + dram_size - free_paddr;

  debug("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  eid = (int)enclave_id;

  page_tables_count = 0;
  /* remap kernel VA */
  remap_kernel_space(runtime_paddr, user_paddr - runtime_paddr);
  map_physical_memory(dram_base, dram_size);

  /* switch to the new page table */
  csr_write(satp, satp_new(kernel_va_to_pa(root_page_table)));

  /* copy valid entries from the old page table */
  copy_root_page_table();
  printf("copy root page table done!\n");

  /* initialize free memory */
  init_freemem();
  printf("init_freemem done!\n");

  //TODO: This should be set by walking the userspace vm and finding
  //highest used addr. Instead we start partway through the anon space
  set_program_break(EYRIE_ANON_REGION_START + (1024 * 1024 * 1024));
  printf("set_program_break done!\n");

  #ifdef USE_PAGING
  init_paging(user_paddr, free_paddr);
  #endif /* USE_PAGING */
#endif /* USE_FREEMEM */

  /* initialize user stack */
  init_user_stack_and_env();

  printf("init_user_stack_and_env done!\n");
  /* set trap vector */
  csr_write(stvec, &encl_trap_handler);

  /* prepare edge & system calls */
  init_edge_internals();

  /* set timer */
  init_timer();


  /* Enable the FPU */
  csr_write(sstatus, csr_read(sstatus) | 0x6000);

#ifdef VSHMEM_ENABLED
  rpc_init();
#endif

  rt_page_fault_init();

  printf("Drop to user land\n");
  debug("eyrie boot finished. drop to the user land ...");
  //printf("FREE: 0x%lx-0x%lx (%u KB), va 0x%lx", free_paddr, dram_base + dram_size, freemem_size/1024, freemem_va_start);

  /* booting all finished, droping to the user land */

  stats.stats_boot_sbi = stats.stats_sbi;
  performance_stats_init(&stats.stats_sbi);
  performance_check_end(&stats.stats_boot);

  return;
}
