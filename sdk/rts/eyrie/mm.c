#include "rt_util.h"
#include "common.h"
#include "syscall.h"
#include "mm.h"
#include "freemem.h"
#include "paging.h"

#define VMA_MAX_N 16

#ifdef USE_FREEMEM

/* Page table utilities */
static pte*
__walk_create(pte* root, uintptr_t addr, int internal);

static struct vma vma_list[VMA_MAX_N];
static int vma_count;

/* Hacky storage of current u-mode break */
static uintptr_t current_program_break;

uintptr_t get_program_break(){
	return current_program_break;
}

void set_program_break(uintptr_t new_break){
	current_program_break = new_break;
}

	static pte*
__continue_walk_create(pte* root, uintptr_t addr, pte* pte, int internal)
{
	uintptr_t new_page;
	uintptr_t free_ppn;
	if(internal){
		assert(page_tables_count < MAX_PT_COUNT);
		new_page = (uintptr_t)secondary_page_tables[page_tables_count ++];
		free_ppn = ppn(kernel_va_to_pa((void*)new_page));
	} else{
		new_page = spa_get_zero();
		assert(new_page);
		free_ppn = ppn(__pa(new_page));
	}

	*pte = ptd_create(free_ppn);
	return __walk_create(root, addr, internal);
}

	static pte*
__walk_internal(pte* root, uintptr_t addr, int create, int internal)
{
	pte* t = root;
	int i;
	for (i = 1; i < RISCV_PT_LEVELS; i++)
	{
		size_t idx = RISCV_GET_PT_INDEX(addr, i);

		if (!(t[idx] & PTE_V))
			return create ? __continue_walk_create(root, addr, &t[idx], internal) : 0;
		if(internal)
			t = (pte*) kernel_pa_to_va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
		else
			t = (pte*) __va(pte_ppn(t[idx]) << RISCV_PAGE_BITS);
	}

	return &t[RISCV_GET_PT_INDEX(addr, 3)];
}

/* walk the page table and return PTE
 * return 0 if no mapping exists */
	static pte*
__walk(pte* root, uintptr_t addr, int internal)
{
	return __walk_internal(root, addr, 0, internal);
}

/* walk the page table and return PTE
 * create the mapping if non exists */
	static pte*
__walk_create(pte* root, uintptr_t addr, int internal)
{
	return __walk_internal(root, addr, 1, internal);
}


/* allocate a new page to a given vpn
 * returns VA of the page, (returns 0 if fails) */
	uintptr_t
alloc_page(uintptr_t vpn, int flags)
{
	uintptr_t page;
	pte* pte = __walk_create(root_page_table, vpn << RISCV_PAGE_BITS, 0);

	assert(flags & PTE_U);

	if (!pte)
		return 0;

	/* if the page has been already allocated, return the page */
	if(*pte & PTE_V) {
		return __va(*pte << RISCV_PAGE_BITS);
	}

	/* otherwise, allocate one from the freemem */
	page = spa_get();
	assert(page);

	*pte = pte_create(ppn(__pa(page)), flags | PTE_V);
#ifdef USE_PAGING
	paging_inc_user_page();
#endif

	return page;
}

void
free_page(uintptr_t vpn){

	pte* pte = __walk(root_page_table, vpn << RISCV_PAGE_BITS, 0);

	// No such PTE, or invalid
	if(!pte || !(*pte & PTE_V))
		return;

	assert(*pte & PTE_U);

	uintptr_t ppn = pte_ppn(*pte);
	// Mark invalid
	// TODO maybe do more here
	*pte = 0;

#ifdef USE_PAGING
	paging_dec_user_page();
#endif
	// Return phys page
	spa_put(__va(ppn << RISCV_PAGE_BITS));

	return;

}

/* allocate n new pages from a given vpn
 * returns the number of pages allocated */
	size_t
alloc_pages(uintptr_t vpn, size_t count, int flags)
{
	unsigned int i;
	for (i = 0; i < count; i++) {
		if(!alloc_page(vpn + i, flags))
			break;
	}

	return i;
}

void
free_pages(uintptr_t vpn, size_t count){
	unsigned int i;
	for (i = 0; i < count; i++) {
		free_page(vpn + i);
	}

}

/*
 * Check if a range of VAs contains any allocated pages, starting with
 * the given VA. Returns the number of sequential pages that meet the
 * conditions.
 */
size_t
test_va_range(uintptr_t vpn, size_t count){

	unsigned int i;
	/* Validate the region */
	for (i = 0; i < count; i++) {
		pte* pte = __walk_internal(root_page_table, (vpn+i) << RISCV_PAGE_BITS, 0, 0);
		// If the page exists and is valid then we cannot use it
		if(pte && *pte){
			break;
		}
	}
	return i;
}

/* get a mapped physical address for a VA */
	uintptr_t
translate(uintptr_t va)
{
	pte* pte = __walk(root_page_table, va, 0);

	if(pte && (*pte & PTE_V))
		return (pte_ppn(*pte) << RISCV_PAGE_BITS) | (RISCV_PAGE_OFFSET(va));
	else
		return 0;
}

/* try to retrieve PTE for a VA, return 0 if fail */
	pte*
pte_of_va(uintptr_t va)
{
	pte* pte = __walk(root_page_table, va, 0);
	return pte;
}

	void
map_with_reserved_page_table(uintptr_t dram_base, // paddr
		uintptr_t dram_size,
		uintptr_t ptr) // virtual address
{
	uintptr_t start_pa = PAGE_DOWN(dram_base);
	uintptr_t start_va = PAGE_DOWN(ptr);
	uintptr_t end_va = PAGE_UP(ptr + dram_size);

	for(; start_va != end_va; start_va += RISCV_PAGE_SIZE, start_pa += RISCV_PAGE_SIZE){
		pte* pte_entry = __walk_create(root_page_table, start_va, 1);
		*pte_entry = pte_create(ppn(start_pa),
				PTE_R | PTE_W | PTE_X | PTE_A | PTE_D);
	}
}

uintptr_t find_va_range(uintptr_t size){
  uintptr_t req_pages = size >> RISCV_PAGE_BITS;
  // Start looking at EYRIE_ANON_REGION_START for VA space
  uintptr_t starting_vpn = vpn(EYRIE_ANON_REGION_START);
  uintptr_t valid_pages;
  while((starting_vpn + req_pages) <= EYRIE_ANON_REGION_END){
    valid_pages = test_va_range(starting_vpn, req_pages);

    if(req_pages == valid_pages){
      // Set a successful value if we allocate
      // TODO free partial allocation on failure
	  return starting_vpn << RISCV_PAGE_BITS;
      break;
    }
    else
      starting_vpn += valid_pages + 1;
  }
  return 0;
}

void add_vma(uintptr_t vaddr, uintptr_t paddr, uintptr_t size,
		enum vma_type type, uid_t uid){
	vma_list[vma_count].vaddr = vaddr;
	vma_list[vma_count].paddr = paddr;
	vma_list[vma_count].size = size;
	vma_list[vma_count].type = type;
	vma_list[vma_count].uid = uid;

	++ vma_count;
}

void remove_vma(struct vma* vma){
	struct vma* prev = vma;
	++ vma;
	while(vma != vma_list + vma_count){
		*prev = *vma;
		prev = vma;
		++ vma;
	}
	-- vma_count;
}


void map_pages(uintptr_t vaddr_base, uintptr_t paddr_base, uintptr_t size, unsigned int mode,
		enum vma_type type, uid_t uid){
	printf("Map pages %lx %lx %x\n", vaddr_base, paddr_base, size);
	uintptr_t start_pa = PAGE_DOWN(paddr_base);
	uintptr_t start_va = PAGE_DOWN(vaddr_base);
	uintptr_t end_va = PAGE_UP(start_va + size);


	for(; start_va != end_va; start_va += RISCV_PAGE_SIZE, start_pa += RISCV_PAGE_SIZE){
		pte* pte_entry = __walk_create(root_page_table, start_va, 0);
		*pte_entry = pte_create(ppn(start_pa), mode);
	}
	tlb_flush();
	assert(translate(vaddr_base) == paddr_base);

	add_vma(vaddr_base, paddr_base, size, type, uid);	
}

void unmap_pages(struct vma* vma){
	uintptr_t start_pa = PAGE_DOWN(vma->paddr);
	uintptr_t start_va = PAGE_DOWN(vma->vaddr);
	uintptr_t end_va = PAGE_UP(start_va + vma->size);

	for(; start_va != end_va; start_va += RISCV_PAGE_SIZE, start_pa += RISCV_PAGE_SIZE){
		pte* pte_entry = __walk_create(root_page_table, start_va, 0);
		*pte_entry = pte_create_invalid(0, 0);
	}
	tlb_flush();
	
	remove_vma(vma);
}

struct vma* get_vma_by_pa(uintptr_t pa){
	int i;
	for(i = 0; i < vma_count; i ++){
		if(pa >= vma_list[i].paddr && pa < vma_list[i].paddr + vma_list[i].size) 
			return vma_list + i;
	}
	return NULL;
}

struct vma* get_vma_by_va(uintptr_t va){
	int i;
	for(i = 0; i < vma_count; i ++){
		if(va >= vma_list[i].vaddr && va < vma_list[i].vaddr + vma_list[i].size) 
			return vma_list + i;
	}
	return NULL;
}

struct vma* get_vma_by_uid(uid_t uid){
	int i;
	for(i = 0; i < vma_count; i ++)
		if(vma_list[i].type == VMA_TYPE_SHARED && vma_list[i].uid == uid)
			return vma_list + i;
	return NULL;
}

#endif /* USE_FREEMEM */
