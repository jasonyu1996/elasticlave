#ifndef _IPI_H_
#define _IPI_H_

#include "mtrap.h"
#include "atomic.h"

#define IPI_ARG_N 3

enum ipi_type {
	IPI_TYPE_PMP,
	IPI_TYPE_REGION,
	IPI_TYPE_TERMINATE
};

void send_ipi(int target_hart, enum ipi_type type, int* args);

void send_encl_ipis(uintptr_t enclave_mask, enum ipi_type type,
		int* args, int sync);

void handle_ipi(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc);
void ipi_acquire_lock(spinlock_t* lock);
void ipi_release_lock(spinlock_t* lock);

#endif
