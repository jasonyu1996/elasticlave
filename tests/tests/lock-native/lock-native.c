#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include "performance.h"

#define N 1000

static pthread_t threads[8];
static pthread_mutex_t lock;
static pthread_barrier_t bar;
static int ENCLAVE_N, CONTENTION;

void run_workload(){
	int i, j;
	for(i = 0; i < N; i ++){
		pthread_mutex_lock(&lock);
		for(j = 0; j < CONTENTION; j ++);
		pthread_mutex_unlock(&lock);
	}
}

void* run_thread(void* arg){
	pthread_barrier_wait(&bar);
	run_workload();
	pthread_barrier_wait(&bar);
}


int main(int argc, char* argv[]){
	if(argc < 3){
		fprintf(stderr, "Missing arguments!\n");
		return 1;
	}

	ENCLAVE_N = atoi(argv[1]);
	CONTENTION = atoi(argv[2]);

	printf("Enclave-N = %d, Contention = %d\n", ENCLAVE_N, \
			CONTENTION);

	struct performance_stats stats;
	performance_stats_init(&stats);

	pthread_mutex_init(&lock, NULL);
	pthread_barrier_init(&bar, NULL, ENCLAVE_N);
	int i;
	for(i = 1; i < ENCLAVE_N; i ++){
		pthread_create(threads + i, NULL, run_thread, NULL);
	}

	pthread_barrier_wait(&bar);
	performance_check_start(&stats);
	run_workload();
	pthread_barrier_wait(&bar);
	performance_check_end(&stats);

	pthread_barrier_destroy(&bar);

	performance_stats_print_total(&stats, "Total Running");
	
	return 0;
}

