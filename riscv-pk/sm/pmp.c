//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "pmp.h"
#include "mtrap.h"
#include "atomic.h"
#include "safe_math_util.h"
#include "region.h"
#include "cpu.h"
#include "enclave.h"
#include "ipi.h"

#define PMP_IPI_SHAREDEM 0
#define PMP_IPI_SET 1
#define PMP_IPI_UNSET 2

/* PMP global spin locks */
static spinlock_t pmp_lock = SPINLOCK_INIT;

/* PMP region getter/setters */
static struct pmp_region regions[PMP_MAX_N_REGION];
static uint32_t reg_bitmap = 0;
static uint32_t region_def_bitmap = 0;

static inline int region_register_idx(region_id i)
{
  return regions[i].reg_idx;
}

static inline int region_allows_overlap(region_id i)
{
  return regions[i].allow_overlap;
}

static inline uintptr_t region_get_addr(region_id i)
{
  return regions[i].addr;
}

static inline uint64_t region_get_size(region_id i)
{
  return regions[i].size;
}

static inline int region_is_napot(region_id i)
{
  return regions[i].addrmode == PMP_NAPOT;
}

static inline int region_is_tor(region_id i)
{
  return regions[i].addrmode == PMP_TOR;
}

static inline int region_needs_two_entries(region_id i)
{
  return region_is_tor(i) && regions[i].reg_idx > 0;
}

static inline int region_is_napot_all(region_id i)
{
  return regions[i].addr == 0 && regions[i].size == -1UL;
}

static inline uintptr_t region_pmpaddr_val(region_id i)
{
  if(region_is_napot_all(i))
    return (-1UL);
  else if(region_is_napot(i))
    return (regions[i].addr | (regions[i].size/2-1)) >> 2;
  else if(region_is_tor(i))
    return (regions[i].addr + regions[i].size) >> 2;
  else
    return 0;
}

static inline uintptr_t region_pmpcfg_val(region_id i, pmpreg_id reg_idx, uint8_t perm_bits)
{
  return (uintptr_t) (regions[i].addrmode | perm_bits) << (8*(reg_idx%PMP_PER_GROUP));
}

static void region_clear_all(region_id i)
{
  regions[i].addr = 0;
  regions[i].size = 0;
  regions[i].addrmode = 0;
  regions[i].allow_overlap = 0;
  regions[i].reg_idx = 0;
}

static void region_init(region_id i,
                        uintptr_t addr,
                        uint64_t size,
                        uint8_t addrmode,
                        int allow_overlap,
                        pmpreg_id reg_idx)
{
  regions[i].addr = addr;
  regions[i].size = size;
  regions[i].addrmode = addrmode;
  regions[i].allow_overlap = allow_overlap;
  regions[i].reg_idx = (addrmode == PMP_TOR && reg_idx > 0 ? reg_idx + 1 : reg_idx);
}

static int is_pmp_region_valid(region_id region_idx)
{
  return TEST_BIT(region_def_bitmap, region_idx);
}

static int search_rightmost_unset(uint32_t bitmap, int max, uint32_t mask)
{
  int i = 0;

  assert(max < 32);
  assert(!((mask + 1) & mask));

  while(mask < (1UL << max)) {
    if((~bitmap & mask) == mask)
      return i;
    mask = mask << 1;
    i++;
  }

  return -1;
}

static region_id get_free_region_idx()
{
  return search_rightmost_unset(region_def_bitmap, PMP_MAX_N_REGION, 0x1);
}

static pmpreg_id get_free_reg_idx()
{
  return search_rightmost_unset(reg_bitmap, PMP_N_REG, 0x1);
}

static pmpreg_id get_conseq_free_reg_idx()
{
  return search_rightmost_unset(reg_bitmap, PMP_N_REG, 0x3);
}

/* IPI-related functions */


/* We do an integery overflow safety check here for the inputs (addr +
 * size).  We do NOT do a safety check on epm_base + epm_size, since
 * only valid region should have been created previously.
 *
 * On a failed addr + size overflow, we return failure, since this
 * cannot be a valid addr and size anyway.
 */
static int detect_region_overlap(uintptr_t addr, uintptr_t size)
{
  void* epm_base;
  size_t epm_size;
  int region_overlap = 0, i;

  // Safety check the addr+size
  uintptr_t input_end;
  if( __checked_uaddl(addr, size, &input_end)){
    return 1;
  }

  for(i=0; i<PMP_MAX_N_REGION; i++)
  {
    if(!is_pmp_region_valid(i))
      continue;

    if(region_allows_overlap(i)) {
      continue;
    }

    epm_base = (void*) region_get_addr(i);
    epm_size = region_get_size(i);

    // Only looking at valid regions, no need to check epm_base+size
    region_overlap |= ((uintptr_t) epm_base < input_end) &&
                      ((uintptr_t) epm_base + epm_size > addr);
  }

  return region_overlap;
}

int pmp_detect_region_overlap_atomic(uintptr_t addr, uintptr_t size)
{
  int region_overlap = 0;
  spinlock_lock(&pmp_lock);
  region_overlap = detect_region_overlap(addr, size);
  spinlock_unlock(&pmp_lock);
  return region_overlap;
}

extern struct enclave enclaves[];

void pmp_ipi_update(int* args) {
	int ipi_type = args[0];
	if(ipi_type == PMP_IPI_SHAREDEM){ 
	  update_region_perm(shared_regions + args[1]);
	} else if(ipi_type == PMP_IPI_SET) {
      uint8_t perm = (uint8_t)args[2];
	  pmp_set(args[1], perm);
    } else{
      pmp_unset(args[1]);
    }
}

/*********************************
 *
 * External Functions
 *
 **********************************/

int pmp_unset_global(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");

  /* We avoid any complex PMP-related IPI management
   * by ensuring only one hart can enter this region at a time */
#ifdef __riscv_atomic
  int args[IPI_ARG_N] = {0};
  args[0] = PMP_IPI_UNSET;
  args[1] = region_idx;
  args[2] = PMP_NO_PERM;
  send_encl_ipis((uintptr_t)-1, IPI_TYPE_PMP, args, 1);
#endif
  /* unset PMP of itself */
  pmp_unset(region_idx);

  return PMP_SUCCESS;
}

int pmp_shmem_update_global(int region, uintptr_t enclave_mask){
#ifdef __riscv_atomic
  int args[IPI_ARG_N] = {0};
  args[0] = PMP_IPI_SHAREDEM;
  args[1] = region;
  send_encl_ipis(enclave_mask, IPI_TYPE_PMP, args, 1);
#endif
  /* set PMP of itself */
  if(enclave_mask & ENCLAVE_MASK(cpu_get_enclave_id())){
	  update_region_perm(shared_regions + region);
  }

  return PMP_SUCCESS;
}

int pmp_terminate_global(uintptr_t enclave_mask){
#ifdef __riscv_atomic
  send_encl_ipis(enclave_mask, IPI_TYPE_TERMINATE, NULL, 1);
#endif
  /* set PMP of itself */
  if(enclave_mask & ENCLAVE_MASK(cpu_get_enclave_id())){
	  cpu_set_to_terminate(1);
  }
  return PMP_SUCCESS;
}

/* populate pmp set command to every other hart */
int pmp_set_global(int region_idx, uint8_t perm, int self, uintptr_t enclave_mask)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");

  /* We avoid any complex PMP-related IPI management
   * by ensuring only one hart can enter this region at a time */
#ifdef __riscv_atomic
  int args[IPI_ARG_N] = {0};
  args[0] = PMP_IPI_SET;
  args[1] = region_idx;
  args[2] = perm;
  send_encl_ipis((uintptr_t)enclave_mask, IPI_TYPE_PMP, args, 1);
#endif
  /* set PMP of itself */
  if(self)
    pmp_set(region_idx, perm);
  return PMP_SUCCESS;
}

int pmp_set(int region_idx, uint8_t perm)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");

  uint8_t perm_bits = perm & PMP_ALL_PERM;
  /*perm_bits = PMP_ALL_PERM;*/
  pmpreg_id reg_idx = region_register_idx(region_idx);
  uintptr_t pmpcfg = region_pmpcfg_val(region_idx, reg_idx, perm_bits);
  uintptr_t pmpaddr;

  pmpaddr = region_pmpaddr_val(region_idx);

  int n=reg_idx;

  switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      die("pmp_set failed: this must not be tolerated\n");
  }

  /* TOR decoding with 2 registers */
  if(region_needs_two_entries(region_idx))
  {
    n--;
    pmpcfg = 0;
    pmpaddr = region_get_addr(region_idx) >> 2;
    switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      die("pmp_set failed: this must not be tolerated\n");
    }
  }
  return PMP_SUCCESS;
}

int pmp_unset(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID,"Invalid PMP region index");

  pmpreg_id reg_idx = region_register_idx(region_idx);
  int n=reg_idx;
  switch(n) {
#define X(n,g) case n: { PMP_UNSET(n, g); break;}
  LIST_OF_PMP_REGS
#undef X
    default:
      die("pmp_unset failed: this must not be tolerated\n");
  }

  if(region_needs_two_entries(region_idx))
  {
    n--;
    switch(n) {
#define X(n,g) case n: { PMP_UNSET(n,g); break; }
  LIST_OF_PMP_REGS
#undef X
    default:
      die("pmp_unset failed: this must not be tolerated\n");
    }
  }

  return PMP_SUCCESS;
}

int pmp_region_init_atomic(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  int ret;
  spinlock_lock(&pmp_lock);
  ret = pmp_region_init(start, size, priority, rid, allow_overlap);
  spinlock_unlock(&pmp_lock);
  return ret;
}

static int tor_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  pmpreg_id reg_idx = -1;
  region_id region_idx = -1;
  int region_overlap = 0, i=0;

  assert(size);
  assert(!(size & (RISCV_PGSIZE-1)));
  assert(!(start & (RISCV_PGSIZE-1)));
  assert(rid);
  assert(priority != PMP_PRI_BOTTOM);

  region_idx = get_free_region_idx();
  if(region_idx < 0 || region_idx > PMP_MAX_N_REGION)
    PMP_ERROR(PMP_REGION_MAX_REACHED, "Reached the maximum number of PMP regions");

  *rid = region_idx;
  switch(priority)
  {
    case(PMP_PRI_ANY): {
      reg_idx = get_conseq_free_reg_idx();
      if(reg_idx < 0)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "No available PMP register");
      if(TEST_BIT(reg_bitmap, reg_idx) || TEST_BIT(reg_bitmap, reg_idx + 1) || reg_idx + 1 >= PMP_N_REG)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");

      break;
    }
    case(PMP_PRI_TOP): {
      assert(start == 0);
      reg_idx = 0;
      if(TEST_BIT(reg_bitmap, reg_idx))
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");
      break;
    }
    default: {
      assert(0);
    }
  }

  // initialize the region
  region_init(region_idx, start, size, PMP_TOR, allow_overlap, reg_idx);
  SET_BIT(region_def_bitmap, region_idx);
  SET_BIT(reg_bitmap, reg_idx);

  if(reg_idx > 0)
    SET_BIT(reg_bitmap, reg_idx + 1);

  return PMP_SUCCESS;
}

static int napot_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, region_id* rid, int allow_overlap)
{
  pmpreg_id reg_idx = -1;
  region_id region_idx = -1;
  int region_overlap = 0, i = 0;

  assert(size);
  assert(rid);

  if(!(size == -1UL && start == 0))
  {
    assert(!(size & (size-1)));
    assert(!(start & (size - 1)));
    assert(!(size & (RISCV_PGSIZE-1)));
    assert(!(start & (RISCV_PGSIZE-1)));
  }

  //find avaiable pmp region idx
  region_idx = get_free_region_idx();
  if(region_idx < 0 || region_idx > PMP_MAX_N_REGION)
    PMP_ERROR(PMP_REGION_MAX_REACHED, "Reached the maximum number of PMP regions");

  *rid = region_idx;

  switch(priority)
  {
    case(PMP_PRI_ANY): {
      reg_idx = get_free_reg_idx();
      if(reg_idx < 0)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "No available PMP register");
      if(TEST_BIT(reg_bitmap, reg_idx) || reg_idx >= PMP_N_REG)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");
      break;
    }
    case(PMP_PRI_TOP): {
      reg_idx = 0;
      if(TEST_BIT(reg_bitmap, reg_idx))
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");
      break;
    }
    case(PMP_PRI_BOTTOM): {
      /* the bottom register can be used by multiple regions,
       * so we don't check its availability */
      reg_idx = PMP_N_REG - 1;
      break;
    }
    default: {
      assert(0);
    }
  }

  // initialize the region
  region_init(region_idx, start, size, PMP_NAPOT, allow_overlap, reg_idx);
  SET_BIT(region_def_bitmap, region_idx);
  SET_BIT(reg_bitmap, reg_idx);

  return PMP_SUCCESS;
}

int pmp_region_free_atomic(int region_idx)
{

  spinlock_lock(&pmp_lock);

  if(!is_pmp_region_valid(region_idx))
  {
    spinlock_unlock(&pmp_lock);
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");
  }

  pmpreg_id reg_idx = region_register_idx(region_idx);
  UNSET_BIT(region_def_bitmap, region_idx);
  UNSET_BIT(reg_bitmap, reg_idx);
  if(region_needs_two_entries(region_idx))
    UNSET_BIT(reg_bitmap, reg_idx - 1);

  region_clear_all(region_idx);

  spinlock_unlock(&pmp_lock);

  return PMP_SUCCESS;
}

int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, int* rid, int allow_overlap)
{
  if(!size)
    PMP_ERROR(PMP_REGION_SIZE_INVALID, "Invalid PMP size");

  /* overlap detection */
  if (!allow_overlap) {
    if (detect_region_overlap(start, size)) {
      return PMP_REGION_OVERLAP;
    }
  }

  /* PMP granularity check */
  if(size != -1UL && (size & (RISCV_PGSIZE - 1)))
    PMP_ERROR(PMP_REGION_NOT_PAGE_GRANULARITY, "PMP granularity is RISCV_PGSIZE");
  if(start & (RISCV_PGSIZE - 1))
    PMP_ERROR(PMP_REGION_NOT_PAGE_GRANULARITY, "PMP granularity is RISCV_PGSIZE");

  /* if the address covers the entire RAM or it's NAPOT */
  int r;
  if ((size == -1UL && start == 0) ||
      (!(size & (size - 1)) && !(start & (size - 1)))) {
    r = napot_region_init(start, size, priority, rid, allow_overlap);
  }
  else
  {
    if(priority != PMP_PRI_ANY &&
      (priority != PMP_PRI_TOP || start != 0)) {
      PMP_ERROR(PMP_REGION_IMPOSSIBLE_TOR, "The top-priority TOR PMP entry must start from address 0");
    }

    r =  tor_region_init(start, size, priority, rid, allow_overlap);
  }
  return r;
}

uintptr_t pmp_region_get_addr(region_id i)
{
  if(is_pmp_region_valid(i))
    return region_get_addr(i);
  return 0;
}

uint64_t pmp_region_get_size(region_id i)
{
  if(is_pmp_region_valid(i))
    return region_get_size(i);
  return 0;
}


