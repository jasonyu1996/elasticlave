#include "plugins/multimem.h"
#include "sm.h"

uintptr_t multimem_get_other_region_size(enclave_id eid)
{
	/*
  int mem_id = get_region_index(eid, REGION_OTHER);
  return get_region_size(eid, mem_id);
  */
	return 0;
}

uintptr_t multimem_get_other_region_addr(enclave_id eid)
{
	/*
  int mem_id = get_region_index(eid, REGION_OTHER);
  return get_region_base(eid, mem_id);
  */
	return 0;
}

uintptr_t do_sbi_multimem(enclave_id eid, uintptr_t call_id)
{
  switch(call_id)
  {
    case MULTIMEM_GET_OTHER_REGION_SIZE:
      return multimem_get_other_region_size(eid);
    case MULTIMEM_GET_OTHER_REGION_ADDR:
      return multimem_get_other_region_addr(eid);
    default:
      return 0;
  }
  return 0;
}
