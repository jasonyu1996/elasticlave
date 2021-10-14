#ifndef _UACCESS_H_
#define _UACCESS_H_
#include <asm/asm.h>
#include <asm/csr.h>

/* This is a limited set of the features from linux uaccess, only the
   ones we need for now */

extern unsigned long __asm_copy_to_user(void  *to,
                                        const void  *from, unsigned long n);
extern unsigned long __asm_copy_from_user(void  *to,
                                          const void  *from, unsigned long n);

static inline unsigned long
copy_to_user(void *to, const void *from, unsigned long n)
{
	return __asm_copy_to_user(to, from, n);
}

static inline unsigned long
copy_from_user(void *to, const void *from, unsigned long n)
{
	return __asm_copy_from_user(to, from, n);
}

static inline unsigned long get_word_from_user(const void* from){
	unsigned int buf = 0;
	copy_from_user(&buf, from, sizeof(unsigned int));
	return buf;
}

static inline unsigned long
copy_string_from_user(char* to, const char* from, unsigned long n){
	int i;
    for(i = 0; i < n; i ++){
		if(copy_from_user(to + i, from + i, 1) || !to[i]){
			to[i] = '\0';
			break;
		}
	}	
	if(i >= n){
		to[n - 1] = '\0';
		return n - 1;
	}
	return i;
}

/* Dangerous feature needed for a few things (ex: strlen on usermemory) */
#define ALLOW_USER_ACCESS(x) { \
  unsigned long tmp_storage; \
  asm volatile ("li %0, %1" : "=r" (tmp_storage) : "i" (SR_SUM));       \
  asm volatile ("csrs sstatus, %0" : "=r" (tmp_storage)); \
  (x);                                                    \
  asm volatile ("csrc sstatus, %0" : "=r" (tmp_storage)); \
  }
#endif /* _UACCESS_H_ */
