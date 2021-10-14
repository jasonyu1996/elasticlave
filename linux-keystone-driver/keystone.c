//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"
#include "keystone-sbi-arg.h"

#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include "keystone_user.h"
#define   DRV_DESCRIPTION   "keystone enclave"
#define   DRV_VERSION       "0.2"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Dayeol Lee <dayeol@berkeley.edu>");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

struct enclave host_enclave;
int map_pending;
uid_t map_uid;
uintptr_t map_pa, map_size;

#define MAX_MEM_MAPPINGS 16

struct mem_mapping mem_mappings[MAX_MEM_MAPPINGS];
int mem_mappings_n;

static const struct file_operations keystone_fops = {
    .owner          = THIS_MODULE,
    .mmap           = keystone_mmap,
    .unlocked_ioctl = keystone_ioctl,
    .release        = keystone_release
};

struct miscdevice keystone_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "keystone_enclave",
  .fops = &keystone_fops,
  .mode = 0666,

};

int keystone_mmap(struct file* filp, struct vm_area_struct *vma)
{
	struct utm* utm;
	struct epm* epm;
	struct enclave* enclave;
	unsigned long vsize, psize;
	vaddr_t paddr;

	vsize = vma->vm_end - vma->vm_start;

	if(map_pending){
		if(vma->vm_pgoff != 0 || vsize > map_size)
			return -EINVAL;
		remap_pfn_range(vma, vma->vm_start, 
				map_pa >> PAGE_SHIFT, vsize, vma->vm_page_prot);
		map_pending = 0;

		// add the memory mapping
		mem_mappings[mem_mappings_n].uid = map_uid;
		mem_mappings[mem_mappings_n].va = vma->vm_start;
		mem_mappings[mem_mappings_n].pa = map_pa;
		mem_mappings[mem_mappings_n].size = vsize;
		++mem_mappings_n;
	} else{
		enclave = get_enclave_by_id((unsigned long) filp->private_data);
		if(!enclave) {
			keystone_err("invalid enclave id\n");
			return -EINVAL;
		}

		utm = enclave->utm;
		epm = enclave->epm;

		if(!enclave->epm_mapped){
			if(vsize + (vma->vm_pgoff << PAGE_SHIFT) > epm->size)
				return -EINVAL;
			paddr = __pa(epm->root_page_table) + (vma->vm_pgoff << PAGE_SHIFT);
			remap_pfn_range(vma,
					vma->vm_start,
					paddr >> PAGE_SHIFT,
					vsize, vma->vm_page_prot);
		}
		else if(!enclave->recent_shm)
		{
			uintptr_t utm_offset = vma->vm_pgoff << PAGE_SHIFT;
			psize = utm->size;
			if(utm_offset + vsize > psize)
				return -EINVAL;
			remap_pfn_range(vma,
					vma->vm_start,
					(__pa(utm->ptr) + utm_offset) >> PAGE_SHIFT,
					vsize, vma->vm_page_prot);
		} else{
			if((vma->vm_pgoff << PAGE_SHIFT) + vsize > enclave->recent_shm->size)
				return -EINVAL;
			remap_pfn_range(vma,
					vma->vm_start,
					(enclave->recent_shm->pa + (vma->vm_pgoff << PAGE_SHIFT)) >> PAGE_SHIFT,
					vsize, vma->vm_page_prot);
			enclave->recent_shm->va = vma->vm_start;
		}
  }
  return 0;
}

static int __init keystone_dev_init(void)
{
  int ret;

  INIT_LIST_HEAD(&shm_list);

  ret = misc_register(&keystone_dev);
  if (ret < 0)
  {
    pr_err("keystone_enclave: misc_register() failed\n");
  }

  keystone_dev.this_device->coherent_dma_mask = DMA_BIT_MASK(32);

  pr_info("keystone_enclave: " DRV_DESCRIPTION " v" DRV_VERSION "\n");
  return ret;
}

static void __exit keystone_dev_exit(void)
{
  pr_info("keystone_enclave: keystone_dev_exit()\n");
  misc_deregister(&keystone_dev);
  return;
}

module_init(keystone_dev_init);
module_exit(keystone_dev_exit);
