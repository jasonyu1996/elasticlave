#ifndef _MM_H_
#define _MM_H_
#include <stdint.h>
#include <stddef.h>
#include "vm.h"
#include "types.h"

enum vma_type {
	VMA_TYPE_ANON,
	VMA_TYPE_SHARED
};

struct vma {
	uintptr_t vaddr, paddr, size;
	enum vma_type type;
	uid_t uid;
};


uintptr_t translate(uintptr_t va);
pte* pte_of_va(uintptr_t va);
#ifdef USE_FREEMEM
uintptr_t alloc_page(uintptr_t vpn, int flags);
void free_page(uintptr_t vpn);
size_t alloc_pages(uintptr_t vpn, size_t count, int flags);
void free_pages(uintptr_t vpn, size_t count);
size_t test_va_range(uintptr_t vpn, size_t count);

uintptr_t get_program_break();
void set_program_break(uintptr_t new_break);

uintptr_t find_va_range(uintptr_t size);
void map_with_reserved_page_table(uintptr_t base, uintptr_t size, uintptr_t ptr);
void map_pages(uintptr_t vaddr_base, uintptr_t paddr_base, uintptr_t size, unsigned int mode, enum vma_type type, uid_t uid);
void unmap_pages(struct vma* vma);
struct vma* get_vma_by_pa(uintptr_t pa);
struct vma* get_vma_by_va(uintptr_t va);


void add_vma(uintptr_t vaddr, uintptr_t paddr, uintptr_t size,
		enum vma_type type, uid_t uid);
void remove_vma(struct vma* vma);
struct vma* get_vma_by_uid(uid_t uid);

#endif /* USE_FREEMEM */

#endif /* _MM_H_ */
