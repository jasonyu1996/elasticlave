#ifndef H_REGION_PERMITS
#define H_REGION_PERMITS

#include "atomic.h"
#include "sm_types.h"
#include "cpu.h"
#include "perm.h"

#define REGION_PERMITS_MAX 16

enum region_type {
  REGION_INVALID,
  REGION_EPM,
  REGION_UTM,
  REGION_SHARED,
  REGION_OTHER,
};

struct region
{
  uid_t uid; // universal id (should be kept unique)
  //int borrows; // -1 for write, positive values for number of read
  uintptr_t paddr, size;
  region_id pmp_rid;
  enum region_type type;
  struct region_perm_config perm_conf;
};

struct region* get_region_by_uid(
		struct region* region_list,
	   	int count,
	   	uid_t uid);

static void update_region_perm(struct region* reg){
	static spinlock_t print_lock = SPINLOCK_INIT;
	int eid = cpu_get_enclave_id();
	int perm = (int)get_perm(&reg->perm_conf, eid);
	pmp_set(reg->pmp_rid, perm);
}

static int get_region_index(struct region* region_list, enum region_type type){
	size_t i;
	for(i = 0;i < REGIONS_MAX; i++){
		if(region_list[i].type == type){
			return i;
		}
	}
	// No such region for this enclave
	return -1;
}

static uintptr_t get_region_size(struct region* region_list, int memid){
	if (0 <= memid && memid < REGIONS_MAX)
		return pmp_region_get_size(region_list[memid].pmp_rid);

	return 0;
}

static uintptr_t get_region_base(struct region* region_list, int memid){
	if (0 <= memid && memid < REGIONS_MAX)
		return pmp_region_get_addr(region_list[memid].pmp_rid);

	return 0;
}

#endif
