//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <linux/dma-mapping.h>
#include "keystone.h"
/* idr for enclave UID to struct enclave */
DEFINE_IDR(idr_enclave);
DEFINE_SPINLOCK(idr_enclave_lock);

struct list_head shm_list;

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

unsigned long calculate_required_pages(
    unsigned long eapp_sz,
    unsigned long eapp_stack_sz,
    unsigned long rt_sz,
    unsigned long rt_stack_sz)
{
  unsigned long req_pages = 0;

  req_pages += PAGE_UP(eapp_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(eapp_stack_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(rt_sz)/PAGE_SIZE;
  req_pages += PAGE_UP(rt_stack_sz)/PAGE_SIZE;

  // FIXME: calculate the required number of pages for the page table.
  // For now, we must allocate at least 1 (top) + 2 (enclave) + 2 (runtime) pages for pg tables
  req_pages += 15;
  return req_pages;
}

/* Smart destroy, handles partial initialization of epm and utm etc */
int destroy_enclave(struct enclave* enclave)
{
  struct epm* epm;
  struct utm* utm;
  if (enclave == NULL)
    return -ENOSYS;

  epm = enclave->epm;
  utm = enclave->utm;

  if (epm)
  {
    epm_destroy(epm);
    kfree(epm);
  }
  if (utm)
  {
    utm_destroy(utm);
    kfree(utm);
  }
  return 0;
}

struct enclave* create_enclave(unsigned long min_pages)
{
  struct enclave* enclave;

  enclave = kmalloc(sizeof(struct enclave), GFP_KERNEL);
  if (!enclave){
    keystone_err("failed to allocate enclave struct\n");
    goto error_no_free;
  }

  enclave->recent_shm = NULL;

  enclave->utm = NULL;
  enclave->close_on_pexit = 1;

  enclave->epm = kmalloc(sizeof(struct epm), GFP_KERNEL);
  enclave->request.type = DR_REQUEST_NONE;
  enclave->is_init = true;
  enclave->epm_mapped = false;
  if (!enclave->epm)
  {
    keystone_err("failed to allocate epm\n");
    goto error_destroy_enclave;
  }

  if(epm_init(enclave->epm, min_pages)) {
    keystone_err("failed to initialize epm\n");
    goto error_destroy_enclave;
  }
  return enclave;

 error_destroy_enclave:
  destroy_enclave(enclave);
 error_no_free:
  return NULL;
}

unsigned int enclave_idr_alloc(struct enclave* enclave)
{
  unsigned int ueid;

  spin_lock_bh(&idr_enclave_lock);
  ueid = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
  spin_unlock_bh(&idr_enclave_lock);

  if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
    keystone_err("failed to allocate UID\n");
    return 0;
  }

  return ueid;
}

struct enclave* enclave_idr_remove(unsigned int ueid)
{
  struct enclave* enclave;
  spin_lock_bh(&idr_enclave_lock);
  enclave = idr_remove(&idr_enclave, ueid);
  spin_unlock_bh(&idr_enclave_lock);
  return enclave;
}

struct enclave* get_enclave_by_id(unsigned int ueid)
{
  struct enclave* enclave;
  spin_lock_bh(&idr_enclave_lock);
  enclave = idr_find(&idr_enclave, ueid);
  spin_unlock_bh(&idr_enclave_lock);
  return enclave;
}

struct shm* get_shm_by_pa(uintptr_t pa){
	struct list_head *shm_head = &shm_list, *ptr;
	for(ptr = shm_head->next; ptr != shm_head; ptr = ptr->next){
		struct shm* cur_entry = list_entry(ptr, struct shm, list);
		if(cur_entry->pa == pa){
			return cur_entry;
		}
	}
	return NULL;
}

struct shm* get_shm_by_va(uintptr_t va){
	struct list_head *shm_head = &shm_list, *ptr;
	for(ptr = shm_head->next; ptr != shm_head; ptr = ptr->next){
		struct shm* cur_entry = list_entry(ptr, struct shm, list);
		if(va >= cur_entry->va && va < cur_entry->va + cur_entry->size){
			return cur_entry;
		}
	}
	return NULL;
}
int destroy_shm_by_pa(uintptr_t pa){
	struct list_head *shm_head = &shm_list,	*ptr;
	int cnt = 0;	
	for(ptr = shm_head->next; ptr != shm_head; ptr = ptr->next){
		++ cnt;
		struct shm* cur_entry = list_entry(ptr, struct shm, list);
		if(cur_entry->pa == pa){
			list_del_init(ptr);
			shm_destroy(cur_entry);
			kfree(cur_entry);
			return 1;
		}
	}
	return 0;
}

uintptr_t enclave_elasticlave_create(struct enclave* enclave, uintptr_t size){
  if(!enclave){
    keystone_err("invalid enclave id!\n");
    return 0;
  }

  if(enclave->is_init){
    keystone_err("uninitialised enclave sharing memory not supported for now!\n");
    return 0;
  }

  struct shm* shm = (struct shm*)kmalloc(sizeof(struct shm), GFP_KERNEL);
  if(!shm){
    keystone_err("allocation error!\n");
    return 0;
  }

  if(shm_init(shm, size)){
    kfree(shm);
    return 0;
  }

  enclave->recent_shm = shm;
  list_add(&shm->list, &shm_list);

  return shm->pa;
}
