//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _SM_PAGE_H_
#define _SM_PAGE_H_

#include "pk.h"
#include "bits.h"
#include "encoding.h"
#include "mtrap.h"
/*
 * Generic page.h implementation, for NOMMU architectures.
 * This provides the dummy definitions for the memory management.
 */
//#include "memory.h"

/*
 * These are used to make use of C type-checking..
 */


typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;
typedef struct {
	unsigned long pte;
} s_pte_t;
typedef struct {
	unsigned long pmd[16];
} s_pmd_t;
typedef struct {
	unsigned long pgd;
} s_pgd_t;
typedef struct {
	unsigned long pgprot;
} pgprot_t;
typedef struct page *pgtable_t;


#define pte_val(x)	((x).pte)
#define pmd_val(x)	((&x)->pmd[0])
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __va(x) ((void *)((unsigned long) (x)))
#define __pa(x) ((unsigned long) (x))

#define __pte(x)	((s_pte_t) { (x) } )
#define __pmd(x)	((s_pmd_t) { (x) } )
#define __pgd(x)	((s_pgd_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

// page table entry (PTE) fields
#define PTE_V     0x001 // Valid
#define PTE_R     0x002 // Read
#define PTE_W     0x004 // Write
#define PTE_X     0x008 // Execute
#define PTE_U     0x010 // User
#define PTE_G     0x020 // Global
#define PTE_A     0x040 // Accessed
#define PTE_D     0x080 // Dirty
#define PTE_SOFT  0x300 // Reserved for Software

#define PTE_PPN_SHIFT 10

#define VA_BITS 39

#define RISCV_PGLEVEL_BITS 9
#define RISCV_PGSHIFT 12
#define RISCV_PGSIZE (1 << RISCV_PGSHIFT)

#if __riscv_xlen == 64
# define RISCV_PGLEVEL_MASK 0x1ff
# define RISCV_PGTABLE_HIGHEST_BIT 0x100
#else
# define RISCV_PGLEVEL_MASK 0x3ff
# define RISCV_PGTABLE_HIGHEST_BIT 0x300
#endif

#define RISCV_PGLEVEL_TOP ((VA_BITS - RISCV_PGSHIFT)/RISCV_PGLEVEL_BITS)

static paddr_t pte_ppn(s_pte_t pte)
{
	return pte_val(pte) >> PTE_PPN_SHIFT;
}

static paddr_t ppn(vaddr_t addr)
{
	return __pa(addr) >> RISCV_PGSHIFT;
}

static size_t pt_idx(vaddr_t addr, int level)
{
	size_t idx = addr >> (RISCV_PGLEVEL_BITS*level + RISCV_PGSHIFT);
	return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}


static s_pte_t* __ept_walk(s_pte_t* root_page_table, vaddr_t addr) 
{
	s_pte_t* t = (root_page_table);

	int i;
	for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
		size_t idx = pt_idx(addr, i);
		if (!(pte_val(t[idx]) & PTE_V)){
			return 0;
		}
		t = (s_pte_t *) ((vaddr_t)pte_ppn(t[idx]) << RISCV_PGSHIFT);  
	}
	return &t[pt_idx(addr, 0)];
}


static vaddr_t epm_va_to_pa(s_pte_t* root_page_table, vaddr_t addr)
{
	s_pte_t* pte = (s_pte_t *) __ept_walk(root_page_table, addr);
	assert(pte_val(*pte) & PTE_V);
	assert(pte_val(*pte) & PTE_R);
	if(pte)
		return pte_ppn(*pte) << RISCV_PGSHIFT;
	else
		return 0;
}

#endif
