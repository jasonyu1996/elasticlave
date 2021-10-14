#ifndef __SYNC_H_
#define __SYNC_H_

#ifdef USE_SIMPLE_FUTEX
#include "syscall.h"
#else
#include<pthread.h>
#endif


typedef struct {
#ifdef USE_SIMPLE_FUTEX
	simple_futex_t lock;
#else
	pthread_mutex_t lock;
#endif

	int counter, pass;
} barrier_shared_t;

typedef struct {
	barrier_shared_t* shared_data;
	int locpass;
} barrier_t;

inline static void bar_init(barrier_t* bar, int init_shared){
	bar->locpass = 0;
	if(init_shared){
		bar->shared_data->counter = 0;
		bar->shared_data->pass = 0;
#ifdef USE_SIMPLE_FUTEX
		simple_futex_init(&bar->shared_data->lock);
#else
		pthread_mutexattr_t attr;
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&bar->shared_data->lock, &attr);
#endif
	}
}

inline static void barrier_wait(barrier_t* bar, int n){
	bar->locpass ^= 1;
#ifdef USE_SIMPLE_FUTEX
	simple_futex_lock(&bar->shared_data->lock);
#else
	pthread_mutex_lock(&bar->shared_data->lock);
#endif
	int c_counter = bar->shared_data->counter + 1;
	if(c_counter == n) {
		bar->shared_data->counter = 0;
		bar->shared_data->pass = bar->locpass;
	} else
		bar->shared_data->counter = c_counter;
#ifdef USE_SIMPLE_FUTEX
	simple_futex_unlock(&bar->shared_data->lock);
#else
	pthread_mutex_unlock(&bar->shared_data->lock);
#endif

	while(bar->shared_data->pass != bar->locpass)
		asm volatile("fence" ::: "memory"); // just spin now
}

struct shared_buffer {
#ifdef USE_SIMPLE_FUTEX
	simple_futex_t sfutex;
#else
	pthread_mutex_t mutex;
#endif
	barrier_shared_t bar_shared;
};

#endif
