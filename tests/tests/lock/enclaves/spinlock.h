/*
#ifndef FUTEX_H
#define FUTEX_H

#define barrier() __asm__ __volatile__("fence rw, rw": : :"memory")

#define atomic_set(ptr, val) (*(volatile typeof(*(ptr)) *)(ptr) = val)
#define atomic_read(ptr) (*(volatile typeof(*(ptr)) *)(ptr))

typedef int spinlock_t;

static inline void spinlock_init(spinlock_t* spinlock){
	*spinlock = 0;
}

#define spinlock_acquire(spinlock) \
	__asm__ __volatile__("li t0, 1\n\t" \
						 "1: amoswap.w.aq t0, t0, %0 \n\t" \
						 "bnez t0, 1b" : "+A"(*(spinlock))  :: "memory", "t0")


#define spinlock_release(spinlock) \
	__asm__ __volatile__("amoswap.w.rl x0, x0, %0" : "+A"(*(spinlock)) :: "memory");


#endif
*/
#ifndef _RISCV_ATOMIC_H
#define _RISCV_ATOMIC_H

typedef struct { int lock; } spinlock_t;
#define SPINLOCK_INIT {0}

#define mb() asm volatile ("fence" ::: "memory")
#define atomic_set(ptr, val) (*(volatile typeof(*(ptr)) *)(ptr) = val)
#define atomic_read(ptr) (*(volatile typeof(*(ptr)) *)(ptr))

#ifdef __riscv_atomic
# define atomic_add(ptr, inc) __sync_fetch_and_add(ptr, inc)
# define atomic_or(ptr, inc) __sync_fetch_and_or(ptr, inc)
# define atomic_swap(ptr, swp) __sync_lock_test_and_set(ptr, swp)
# define atomic_cas(ptr, cmp, swp) __sync_val_compare_and_swap(ptr, cmp, swp)
#else
# define atomic_binop(ptr, inc, op) ({     typeof(*(ptr)) res = atomic_read(ptr);   atomic_set(ptr, op);   res; })
# define atomic_add(ptr, inc) atomic_binop(ptr, inc, res + (inc))
# define atomic_or(ptr, inc) atomic_binop(ptr, inc, res | (inc))
# define atomic_swap(ptr, inc) atomic_binop(ptr, inc, (inc))
# define atomic_cas(ptr, cmp, swp) ({  typeof(*(ptr)) res = *(volatile typeof(*(ptr)) *)(ptr);   if (res == (cmp)) *(volatile typeof(ptr))(ptr) = (swp);     res; })
#endif

static inline void spinlock_init(spinlock_t* lock){
  lock->lock = 0;
}

static inline int spinlock_try(spinlock_t* lock)
{
  int res = atomic_swap(&lock->lock, -1);
  mb();
  return res;
}

static inline void spinlock_acquire(spinlock_t* lock)
{
  do
  {
    while (atomic_read(&lock->lock))
      ;
  } while (spinlock_try(lock));
}

static inline void spinlock_release(spinlock_t* lock)
{
  mb();
  atomic_set(&lock->lock,0);
}

#endif
