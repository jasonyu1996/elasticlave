#ifndef __SYNC_H_
#define __SYNC_H_

#include "spinlock.h"

typedef struct {
	spinlock_t lock;
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
		spinlock_init(&bar->shared_data->lock);
	}
}

inline static void barrier_wait(barrier_t* bar, int n){
	bar->locpass ^= 1;
	spinlock_acquire(&bar->shared_data->lock);
	int c_counter = bar->shared_data->counter + 1;
	if(c_counter == n) {
		bar->shared_data->counter = 0;
		bar->shared_data->pass = bar->locpass;
	} else
		bar->shared_data->counter = c_counter;
	spinlock_release(&bar->shared_data->lock);

	while(bar->shared_data->pass != bar->locpass)
		mb(); // just spin now
}

struct shared_buffer {
	spinlock_t spinlock;
	barrier_shared_t bar_shared;
};

#endif
