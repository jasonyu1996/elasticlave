#include "performance.h"
#include "printf.h"

void performance_stats_print(struct performance_stats* stats, char* caption){
	printf("%s elapsed cycle = %lu\n",
			caption,
			performance_stats_cycle(stats));
}

void performance_stats_thruput_print(struct performance_stats* stats, char* caption, size_t data_size){
	printf("%s throughput/cycle = %lu\n",
			caption,
			data_size / performance_stats_cycle(stats));
}

void performance_stats_print_total(struct performance_stats* stats, char* caption){
	printf("%s total cycle = %lu, count = %lu, data = %lu\n", 
			caption,
			stats->total_cycle,
		   	stats->checked_cnt,
			stats->total_data);
}



