#include "ipi.h"
#include "cpu.h"
#include "atomic.h"
#include "pmp.h"
#include "fdt.h"
#include "disabled_hart_mask.h"
#include "enclave.h"

// types of IPIs
/*static enum ipi_type {IPI_PMP_INVALID=-1,*/
/*IPI_PMP_SET,*/
/*IPI_PMP_UNSET,*/
/*IPI_PMP_SHAREDEM,*/
/*IPI_REG_LOCK_TR, // lock transferred */
/*IPI_REG_LOCK_AC, // lock acquired*/
/*IPI_REG_LOCK_RE, // lock released*/
/*IPI_REG_DESTROYED, // region destroyed*/
/*IPI_TERMINATE*/
/*};*/

/* IPI mailbox */
struct ipi_msg {
    uint8_t pending;
    int args[IPI_ARG_N];
    enum ipi_type type;
};

static struct ipi_msg ipi_mailbox[MAX_HARTS] = {0,};

static void ipi_update();

void send_ipi(int target_hart, enum ipi_type type, int* args){
    if (((disabled_hart_mask >> target_hart) & 1)) return;
    /* never send IPI to my self; it will result in a deadlock */
    if (target_hart == read_csr(mhartid)) return;
    ipi_mailbox[target_hart].type = type;
    if(args){
        int i;
        for(i = 0; i < IPI_ARG_N; i ++)
            ipi_mailbox[target_hart].args[i] = args[i];
    }
    ipi_mailbox[target_hart].pending = 1;

    atomic_or(&OTHER_HLS(target_hart)->mipi_pending, IPI_PMP);
    mb();
    *OTHER_HLS(target_hart)->ipi = 1;
}

// send IPIs to harts running any of the enclaves specified in enclave_mask
// sync=1 will wait until the IPIs are processed
void send_encl_ipis(uintptr_t enclave_mask, enum ipi_type type, 
        int* args, int sync){
    uintptr_t mask = hart_mask, delivered_mask = 0;

    int host_anycast = type != IPI_TYPE_PMP;
    int host_delivered = 0;
    for(uintptr_t i=0, m=mask; m; i++, m>>=1) {
        if(m & 1){
            int idx = cpu_get_enclave_id_idx(i);
            if(enclave_mask & ENCLAVE_MASK(idx)){
                if(host_anycast && idx == 0 && !host_delivered){
                    send_ipi(i, type, args);
                    delivered_mask |= (uintptr_t)1 << i;
                    host_delivered = 1;
                } else if(!host_anycast || idx != 0){
                    send_ipi(i, type, args);
                    delivered_mask |= (uintptr_t)1 << i;
                }
            }
        }
    }

    if(host_anycast && !host_delivered){
        // if no host is running at present
        // don't need to do anything about it
    }

    if(sync){
        for(uintptr_t i=0, m=delivered_mask; m; i++, m>>=1) {
            if(m & 1){
                while( atomic_read(&ipi_mailbox[i].pending) ) {
                    continue;
                }
            }
        }
    }
}

/* 
 * Attempt to acquire the given lock. If it fails, it means another core is broadcasting,
 * this means we may need to update our pmp state and then try to get the lock again.
 */
void ipi_acquire_lock(spinlock_t* lock) {
    while(spinlock_trylock(lock)) {
        ipi_update();
    }
}

void ipi_release_lock(spinlock_t* lock) {
    spinlock_unlock(lock);
}

void handle_ipi(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc){
    ipi_update();
    try_terminate_enclave(regs);
}

static void ipi_update(){
    struct ipi_msg* msg = ipi_mailbox + read_csr(mhartid);
    if(!msg->pending)
        return;
    switch(msg->type){
        case IPI_TYPE_TERMINATE:
            if(cpu_is_enclave_context()){
                cpu_set_to_terminate(1);
            }
            break;
        case IPI_TYPE_PMP:
            pmp_ipi_update(msg->args);
            break;
        case IPI_TYPE_REGION:
            region_ipi_update(msg->args);
            break;
        default:;
    }
    msg->pending = 0;
}

