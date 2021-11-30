#include "mtrap.h"
#include "bits.h"
#include "config.h"

  .data
  .align 6
enclave_trap_table:
#define BAD_TRAP_VECTOR 0
  .word pmp_trap
  .word pmp_trap
  .word illegal_insn_trap
  .word bad_trap
  .word misaligned_load_trap
  .word pmp_trap
  .word misaligned_store_trap
  .word pmp_trap
  .word bad_trap
  .word mcall_trap // 9 --> ECALL from S-mode
  .word bad_trap
  .word bad_trap
  .word bad_trap
#define TRAP_FROM_MACHINE_MODE_VECTOR 13
  .word __trap_from_machine_mode
  .word pmp_trap
  .word pmp_trap
#ifdef SM_ENABLED
# define HANDLE_IPI_PMP_VECTOR 16
  .word handle_ipi
#endif

  .option norvc
  .section .text.init,"ax",@progbits
  .globl enclave_trap_table
  .globl trap_vector_enclave


trap_vector_enclave:
  csrrw sp, mscratch, sp
  beqz sp, .Ltrap_from_machine_mode

  STORE a0, 10*REGBYTES(sp)
  STORE a1, 11*REGBYTES(sp)

  li a0, 3
  sll a0, a0, 13
  csrr a1, mstatus
  or a0, a0, a1
  csrw mstatus, a0

  csrr a1, mcause

  bgez a1, .Lhandle_trap_in_machine_mode

  # This is an interrupt.  Discard the mcause MSB and decode the rest.
  sll a1, a1, 1

  # Is it a machine timer interrupt?
  li a0, IRQ_M_TIMER * 2
  bne a0, a1, 1f

  # Yes.  Simply clear MSIE and raise SSIP.
  li a0, MIP_MTIP
  csrc mie, a0
  li a0, MIP_STIP
  csrs mip, a0

1:
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
  STORE t1, 6*REGBYTES(sp)
  STORE t2, 7*REGBYTES(sp)
  STORE s0, 8*REGBYTES(sp)
  STORE s1, 9*REGBYTES(sp)
  STORE a2,12*REGBYTES(sp)
  STORE a3,13*REGBYTES(sp)
  STORE a4,14*REGBYTES(sp)
  STORE a5,15*REGBYTES(sp)
  STORE a6,16*REGBYTES(sp)
  STORE a7,17*REGBYTES(sp)
  STORE s2,18*REGBYTES(sp)
  STORE s3,19*REGBYTES(sp)
  STORE s4,20*REGBYTES(sp)
  STORE s5,21*REGBYTES(sp)
  STORE s6,22*REGBYTES(sp)
  STORE s7,23*REGBYTES(sp)
  STORE s8,24*REGBYTES(sp)
  STORE s9,25*REGBYTES(sp)
  STORE s10,26*REGBYTES(sp)
  STORE s11,27*REGBYTES(sp)
  STORE t3,28*REGBYTES(sp)
  STORE t4,29*REGBYTES(sp)
  STORE t5,30*REGBYTES(sp)
  STORE t6,31*REGBYTES(sp)

#ifdef __riscv_flen
#  csrr a2, mstatus 
#  srli a2, a2, 12
#  andi a2, a2, 0x6
#  beqz a2, 1f


frcsr a2
fsd f0, 32*REGBYTES(sp)
fsd f1, 33*REGBYTES(sp)
fsd f2, 34*REGBYTES(sp)
fsd f3, 35*REGBYTES(sp)
fsd f4, 36*REGBYTES(sp)
fsd f5, 37*REGBYTES(sp)
fsd f6, 38*REGBYTES(sp)
fsd f7, 39*REGBYTES(sp)
fsd f8, 40*REGBYTES(sp)
fsd f9, 41*REGBYTES(sp)
fsd f10, 42*REGBYTES(sp)
fsd f11, 43*REGBYTES(sp)
fsd f12, 44*REGBYTES(sp)
fsd f13, 45*REGBYTES(sp)
fsd f14, 46*REGBYTES(sp)
fsd f15, 47*REGBYTES(sp)
fsd f16, 48*REGBYTES(sp)
fsd f17, 49*REGBYTES(sp)
fsd f18, 50*REGBYTES(sp)
fsd f19, 51*REGBYTES(sp)
fsd f20, 52*REGBYTES(sp)
fsd f21, 53*REGBYTES(sp)
fsd f22, 54*REGBYTES(sp)
fsd f23, 55*REGBYTES(sp)
fsd f24, 56*REGBYTES(sp)
fsd f25, 57*REGBYTES(sp)
fsd f26, 58*REGBYTES(sp)
fsd f27, 59*REGBYTES(sp)
fsd f28, 60*REGBYTES(sp)
fsd f29, 61*REGBYTES(sp)
fsd f30, 62*REGBYTES(sp)
fsd f31, 63*REGBYTES(sp)
  STORE a2, 64*REGBYTES(sp)
#endif
1:
  csrrw t0, mscratch, x0           # t0 <- user sp
  STORE t0, 2*REGBYTES(sp)         # sp

  # call mcall_sm_stop_enclave
  mv a0, sp
  li a1, 0
  call mcall_sm_stop_enclave
  li a0, 2
  STORE a0, 10*REGBYTES(sp)

  j restore_mscratch

############ Below are exact copy of mentry.S
.Lmret:
  # Go back whence we came.
  LOAD a0, 10*REGBYTES(sp)
  LOAD a1, 11*REGBYTES(sp)
  csrrw sp, mscratch, sp # sp <- mscratch
  mret

.Lhandle_ipi_in_machine_mode:
  # Is it an IPI?
  # li a0, IRQ_M_SOFT * 2
  # bne a0, a1, .Lbad_trap

  # Yes.  First, clear the MIPI bit.
  LOAD a0, MENTRY_IPI_OFFSET(sp)
  sw x0, (a0)
  fence

  # Now, decode the cause(s).
#ifdef __riscv_atomic
  addi a0, sp, MENTRY_IPI_PENDING_OFFSET
  amoswap.w a0, x0, (a0)
#else
  lw a0, MENTRY_IPI_PENDING_OFFSET(a0)
  sw x0, MENTRY_IPI_PENDING_OFFSET(a0)
#endif

  and a1, a0, IPI_SOFT
  beqz a1, 1f
  csrs mip, MIP_SSIP
1:
  andi a1, a0, IPI_FENCE_I
  beqz a1, 1f
  fence.i
1:
  andi a1, a0, IPI_SFENCE_VMA
  beqz a1, 1f
  sfence.vma
1:
  andi a1, a0, IPI_HALT
  beqz a1, 1f
  wfi
  j 1b
#ifdef SM_ENABLED
1:
  andi a1, a0, IPI_PMP
  bnez a1, .Lipi_pmp
#endif
1:
  j .Lmret

.Lhandle_trap_in_machine_mode:
  # Preserve the registers.  Compute the address of the trap handler.
  STORE ra, 1*REGBYTES(sp)
  STORE gp, 3*REGBYTES(sp)
  STORE tp, 4*REGBYTES(sp)
  STORE t0, 5*REGBYTES(sp)
1:auipc t0, %pcrel_hi(trap_table)  # t0 <- %hi(trap_table)
  STORE t1, 6*REGBYTES(sp)
  sll t1, a1, 2                    # t1 <- mcause << 2
  STORE t2, 7*REGBYTES(sp)
  add t1, t0, t1                   # t1 <- %hi(trap_table)[mcause]
  STORE s0, 8*REGBYTES(sp)
  LWU t1, %pcrel_lo(1b)(t1)         # t1 <- trap_table[mcause]
  STORE s1, 9*REGBYTES(sp)
  mv a0, sp                        # a0 <- regs
  STORE a2,12*REGBYTES(sp)
  csrr a2, mepc                    # a2 <- mepc
  STORE a3,13*REGBYTES(sp)
  csrrw t0, mscratch, x0           # t0 <- user sp
  STORE a4,14*REGBYTES(sp)
  STORE a5,15*REGBYTES(sp)
  STORE a6,16*REGBYTES(sp)
  STORE a7,17*REGBYTES(sp)
  STORE s2,18*REGBYTES(sp)
  STORE s3,19*REGBYTES(sp)
  STORE s4,20*REGBYTES(sp)
  STORE s5,21*REGBYTES(sp)
  STORE s6,22*REGBYTES(sp)
  STORE s7,23*REGBYTES(sp)
  STORE s8,24*REGBYTES(sp)
  STORE s9,25*REGBYTES(sp)
  STORE s10,26*REGBYTES(sp)
  STORE s11,27*REGBYTES(sp)
  STORE t3,28*REGBYTES(sp)
  STORE t4,29*REGBYTES(sp)
  STORE t5,30*REGBYTES(sp)
  STORE t6,31*REGBYTES(sp)

#ifdef __riscv_flen
#  csrr a3, mstatus
#  srli a3, a3, 12
#  andi a3, a3, 0x6
#  beqz a3, 1f

  frcsr a3
fsd f0, 32*REGBYTES(sp)
fsd f1, 33*REGBYTES(sp)
fsd f2, 34*REGBYTES(sp)
fsd f3, 35*REGBYTES(sp)
fsd f4, 36*REGBYTES(sp)
fsd f5, 37*REGBYTES(sp)
fsd f6, 38*REGBYTES(sp)
fsd f7, 39*REGBYTES(sp)
fsd f8, 40*REGBYTES(sp)
fsd f9, 41*REGBYTES(sp)
fsd f10, 42*REGBYTES(sp)
fsd f11, 43*REGBYTES(sp)
fsd f12, 44*REGBYTES(sp)
fsd f13, 45*REGBYTES(sp)
fsd f14, 46*REGBYTES(sp)
fsd f15, 47*REGBYTES(sp)
fsd f16, 48*REGBYTES(sp)
fsd f17, 49*REGBYTES(sp)
fsd f18, 50*REGBYTES(sp)
fsd f19, 51*REGBYTES(sp)
fsd f20, 52*REGBYTES(sp)
fsd f21, 53*REGBYTES(sp)
fsd f22, 54*REGBYTES(sp)
fsd f23, 55*REGBYTES(sp)
fsd f24, 56*REGBYTES(sp)
fsd f25, 57*REGBYTES(sp)
fsd f26, 58*REGBYTES(sp)
fsd f27, 59*REGBYTES(sp)
fsd f28, 60*REGBYTES(sp)
fsd f29, 61*REGBYTES(sp)
fsd f30, 62*REGBYTES(sp)
fsd f31, 63*REGBYTES(sp)
STORE a3, 64*REGBYTES(sp)
#endif
1:

  STORE t0, 2*REGBYTES(sp)         # sp

#ifndef __riscv_flen
  lw tp, (sp) # Move the emulated FCSR from x0's save slot into tp.
#endif
  STORE x0, (sp) # Zero x0's save slot.

  # Invoke the handler.
  jalr t1

#ifndef __riscv_flen
  sw tp, (sp) # Move the emulated FCSR from tp into x0's save slot.
#endif

restore_mscratch:
  # Restore mscratch, so future traps will know they didn't come from M-mode.
  csrw mscratch, sp

restore_regs:
#ifdef __riscv_flen
#  csrr a2, mstatus
#  srli a2, a2, 12
#  andi a2, a2, 0x6
#  beqz a2, 1f

LOAD a2, 64*REGBYTES(sp)
fld f0, 32*REGBYTES(sp)
fld f1, 33*REGBYTES(sp)
fld f2, 34*REGBYTES(sp)
fld f3, 35*REGBYTES(sp)
fld f4, 36*REGBYTES(sp)
fld f5, 37*REGBYTES(sp)
fld f6, 38*REGBYTES(sp)
fld f7, 39*REGBYTES(sp)
fld f8, 40*REGBYTES(sp)
fld f9, 41*REGBYTES(sp)
fld f10, 42*REGBYTES(sp)
fld f11, 43*REGBYTES(sp)
fld f12, 44*REGBYTES(sp)
fld f13, 45*REGBYTES(sp)
fld f14, 46*REGBYTES(sp)
fld f15, 47*REGBYTES(sp)
fld f16, 48*REGBYTES(sp)
fld f17, 49*REGBYTES(sp)
fld f18, 50*REGBYTES(sp)
fld f19, 51*REGBYTES(sp)
fld f20, 52*REGBYTES(sp)
fld f21, 53*REGBYTES(sp)
fld f22, 54*REGBYTES(sp)
fld f23, 55*REGBYTES(sp)
fld f24, 56*REGBYTES(sp)
fld f25, 57*REGBYTES(sp)
fld f26, 58*REGBYTES(sp)
fld f27, 59*REGBYTES(sp)
fld f28, 60*REGBYTES(sp)
fld f29, 61*REGBYTES(sp)
fld f30, 62*REGBYTES(sp)
fld f31, 63*REGBYTES(sp)
fscsr a2
#endif
1:


  # Restore all of the registers.
  LOAD ra, 1*REGBYTES(sp)
  LOAD gp, 3*REGBYTES(sp)
  LOAD tp, 4*REGBYTES(sp)
  LOAD t0, 5*REGBYTES(sp)
  LOAD t1, 6*REGBYTES(sp)
  LOAD t2, 7*REGBYTES(sp)
  LOAD s0, 8*REGBYTES(sp)
  LOAD s1, 9*REGBYTES(sp)
  LOAD a0,10*REGBYTES(sp)
  LOAD a1,11*REGBYTES(sp)
  LOAD a2,12*REGBYTES(sp)
  LOAD a3,13*REGBYTES(sp)
  LOAD a4,14*REGBYTES(sp)
  LOAD a5,15*REGBYTES(sp)
  LOAD a6,16*REGBYTES(sp)
  LOAD a7,17*REGBYTES(sp)
  LOAD s2,18*REGBYTES(sp)
  LOAD s3,19*REGBYTES(sp)
  LOAD s4,20*REGBYTES(sp)
  LOAD s5,21*REGBYTES(sp)
  LOAD s6,22*REGBYTES(sp)
  LOAD s7,23*REGBYTES(sp)
  LOAD s8,24*REGBYTES(sp)
  LOAD s9,25*REGBYTES(sp)
  LOAD s10,26*REGBYTES(sp)
  LOAD s11,27*REGBYTES(sp)
  LOAD t3,28*REGBYTES(sp)
  LOAD t4,29*REGBYTES(sp)
  LOAD t5,30*REGBYTES(sp)
  LOAD t6,31*REGBYTES(sp)
  LOAD sp, 2*REGBYTES(sp)
  mret

#ifdef SM_ENABLED
.Lipi_pmp:
  li a1, HANDLE_IPI_PMP_VECTOR
  j .Lhandle_trap_in_machine_mode
#endif

.Ltrap_from_machine_mode:
  csrr sp, mscratch
  addi sp, sp, -INTEGER_CONTEXT_SIZE
  STORE a0,10*REGBYTES(sp)
  STORE a1,11*REGBYTES(sp)
  li a1, TRAP_FROM_MACHINE_MODE_VECTOR
  j .Lhandle_trap_in_machine_mode

.Lbad_trap:
  li a1, BAD_TRAP_VECTOR
  j .Lhandle_trap_in_machine_mode

__trap_from_machine_mode:
  jal trap_from_machine_mode
  j restore_regs

