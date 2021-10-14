//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "riscv64.h"
#include <linux/kernel.h>
#include "keystone.h"
#include <linux/dma-mapping.h>

/* Destroy all memory associated with an EPM */
int epm_destroy(struct epm* epm) {

  if(!epm->ptr || !epm->size)
    return 0;

  /* free the EPM hold by the enclave */
  if (epm->is_cma) {
    dma_free_coherent(keystone_dev.this_device,
        epm->size,
        (void*) epm->ptr,
        epm->pa);
  } else {
    free_pages(epm->ptr, epm->order);
  }

  return 0;
}

/* Create an EPM and initialize the free list */
int epm_init(struct epm* epm, unsigned int min_pages)
{
  vaddr_t epm_vaddr = 0;
  unsigned long order = 0;
  unsigned long count = min_pages;
  phys_addr_t device_phys_addr = 0;

  /* try to allocate contiguous memory */
  epm->is_cma = 0;
  order = ilog2(min_pages - 1) + 1;
  count = 0x1 << order;

  /* prevent kernel from complaining about an invalid argument */
  if (order <= MAX_ORDER)
    epm_vaddr = (vaddr_t) __get_free_pages(GFP_HIGHUSER, order);

#ifdef CONFIG_CMA
  /* If buddy allocator fails, we fall back to the CMA */
  if (!epm_vaddr) {
    epm->is_cma = 1;
    count = min_pages;

    epm_vaddr = (vaddr_t) dma_alloc_coherent(keystone_dev.this_device,
      count << PAGE_SHIFT,
      &device_phys_addr,
      GFP_KERNEL | __GFP_DMA32);

    if(!device_phys_addr)
      epm_vaddr = 0;
  }
#endif

  if(!epm_vaddr) {
    keystone_err("failed to allocate %lu page(s)\n", count);
    return -ENOMEM;
  }

  /* zero out */
  memset((void*)epm_vaddr, 0, PAGE_SIZE*count);

  epm->root_page_table = (void*)epm_vaddr;
  epm->pa = __pa(epm_vaddr);
  epm->order = order;
  epm->size = count << PAGE_SHIFT;
  epm->ptr = epm_vaddr;

  return 0;
}

int utm_destroy(struct utm* utm){

  if(utm->ptr != NULL){
    free_pages((vaddr_t)utm->ptr, utm->order);
  }

  return 0;
}

int utm_init(struct utm* utm, size_t untrusted_size)
{
  unsigned long req_pages = 0;
  unsigned long order = 0;
  unsigned long count;
  req_pages += PAGE_UP(untrusted_size)/PAGE_SIZE;
  order = ilog2(req_pages - 1) + 1;
  count = 0x1 << order;

  utm->order = order;

  /* Currently, UTM does not utilize CMA.
   * It is always allocated from the buddy allocator */
  utm->ptr = (void*) __get_free_pages(GFP_HIGHUSER, order);
  if (!utm->ptr) {
    return -ENOMEM;
  }

  utm->size = count * PAGE_SIZE;
  if (utm->size != untrusted_size) {
    /* Instead of failing, we just warn that the user has to fix the parameter. */
    keystone_warn("shared buffer size is not multiple of PAGE_SIZE\n");
	// this is actually not right, it should be PAGE_SIZE * 2^order
  }

  return 0;
}

int shm_init(struct shm* shm, size_t shared_size){
  unsigned long order = 0;
  unsigned long count;
  unsigned long req_pages = PAGE_UP(shared_size)/PAGE_SIZE;
  order = ilog2(req_pages - 1) + 1;
  count = 0x1 << order;

  shm->order = order;
  INIT_LIST_HEAD(&shm->list);

  int is_cma = 0;
  void* ptr = NULL;
  if (order <= MAX_ORDER)
	  ptr = (void*) __get_free_pages(GFP_HIGHUSER, order);

#ifdef CONFIG_CMA
  /* If buddy allocator fails, we fall back to the CMA */
  if (!ptr) {
	phys_addr_t device_phys_addr = 0;
    //count = req_pages;
    is_cma = 1;
    ptr = (void*)dma_alloc_coherent(keystone_dev.this_device,
      count << PAGE_SHIFT,
      &device_phys_addr,
      GFP_KERNEL | __GFP_DMA32);

    if(!device_phys_addr)
      ptr = NULL;
  }
#endif
  if (!ptr) {
    keystone_err("failed to allocate %lu page(s)\n", count);
    return -ENOMEM;
  }

  shm->ptr = ptr;
  shm->pa = __pa((paddr_t)ptr);
  shm->size = count * PAGE_SIZE;
  shm->is_cma = is_cma;

  if(shm->size != shared_size){
    keystone_warn("bad! shared size is not good! %lx %lx\n", shm->size, shared_size);
  }

  return 0;
}

int shm_destroy(struct shm* shm){
  if(!shm->ptr || !shm->size)
    return 0;

  if (shm->is_cma) {
    dma_free_coherent(keystone_dev.this_device,
        shm->size,
        (void*) shm->ptr,
        shm->pa);
  } else {
    free_pages(shm->ptr, shm->order);
  }
  return 0;
}

