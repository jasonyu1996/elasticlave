#ifndef __FP_H
#define __FP_H

extern unsigned int* get_f32_reg;
extern unsigned int* put_f32_reg;
extern unsigned int* get_f64_reg;
extern unsigned int* put_f64_reg;

static inline unsigned long read_double(unsigned int reg){
	unsigned int offset = reg << 3;
	unsigned long res;
	asm volatile ("1: auipc a1, %%pcrel_hi(get_f64_reg); \
			add a1,a1,%1; \
			jalr t0,a1,%%pcrel_lo(1b); \
			mv %0,a0;" : "=r"(res) : "r"(offset) : "a0", "a1", "t0");
	return res;
}

static inline unsigned int read_float(unsigned int reg){
	unsigned int offset = reg << 3;
	unsigned long res;
	asm volatile ("1: auipc a1, %%pcrel_hi(get_f32_reg); \
			add a1,a1,%1; \
			jalr t0,a1,%%pcrel_lo(1b); \
			mv %0,a0;" : "=r"(res) : "r"(offset) : "a0", "a1", "t0");
	return res;
}

static inline void write_double(unsigned int reg, unsigned long val){
	unsigned int offset = reg << 3;
	asm volatile ("1: auipc a1, %%pcrel_hi(put_f64_reg); \
			mv a0,%1; \
			add a1,a1,%0; \
			jalr t0,a1,%%pcrel_lo(1b);" :: "r"(offset), "r"(val) : "a0", "a1", "t0");
}

static inline void write_float(unsigned int reg, unsigned int val){
	unsigned int offset = reg << 3;
	asm volatile ("1: auipc a1, %%pcrel_hi(put_f32_reg); \
			mv a0,%1; \
			add a1,a1,%0; \
			jalr t0,a1,%%pcrel_lo(1b);" :: "r"(offset), "r"(val) : "a0", "a1", "t0");
}

#endif

