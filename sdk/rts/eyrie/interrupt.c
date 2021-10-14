//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "regs.h"
#include "sbi.h"
#include "vm.h"
#include "timex.h"
#include "interrupt.h"
#include "printf.h"
#include "rt_util.h"
#include <asm/csr.h>
#include "types.h"

#define DEFAULT_CLOCK_DELAY 10000

void init_timer(void)
{
  sbi_set_timer(get_cycles64() + DEFAULT_CLOCK_DELAY);
  csr_set(sstatus, SR_SPIE);
  csr_set(sie, SIE_STIE | SIE_SSIE);
}

void handle_timer_interrupt()
{
  sbi_stop_enclave(0);
  unsigned long next_cycle = get_cycles64() + DEFAULT_CLOCK_DELAY;
  sbi_set_timer(next_cycle);
  csr_set(sstatus, SR_SPIE);
  return;
}

#define EVENTS_MAX 16

static void handle_software_interrupt(struct encl_ctx* ctx){
  uintptr_t event_count, event_buf[EVENTS_MAX << 1];
  uintptr_t pa_event_count = (uintptr_t)kernel_va_to_pa(&event_count),
			pa_event_buf = (uintptr_t)kernel_va_to_pa(event_buf);
  uintptr_t ret = SBI_CALL_3(SBI_SM_ELASTICLAVE_REGION_EVENTS,
		  pa_event_buf,
		  pa_event_count,
		  EVENTS_MAX);
  if(!ret){
	  int i;
	  for(i = 0; i < event_count; i ++)
		  deliver_region_event(ctx, (int)event_buf[i << 1], (int)event_buf[(i << 1) | 1]);
  }
}

uintptr_t handle_interrupts(struct encl_ctx* regs)
{
  unsigned long cause = regs->scause;

  switch(cause) {
    case INTERRUPT_CAUSE_TIMER:
      handle_timer_interrupt();
      break;
    /* ignore other interrupts */
    case INTERRUPT_CAUSE_SOFTWARE:
	  handle_software_interrupt(regs);
	  break;
    case INTERRUPT_CAUSE_EXTERNAL:
    default:
      sbi_stop_enclave(0);
      return 0;
  }
  return 0;
}
