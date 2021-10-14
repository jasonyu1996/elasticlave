#ifndef __PERFORMANCE_H
#define __PERFORMANCE_H

struct performance_stats {
	unsigned long total_cycle;
	unsigned long checked_cnt;
	unsigned long total_data;
};

inline static unsigned long rdcycle(void){
	unsigned long cycle;
	asm volatile ("rdcycle %0" : "=r" (cycle));
	return cycle;
}	

inline static void performance_stats_init(struct performance_stats* stats){
	stats->total_cycle = 0;
	stats->checked_cnt = 0;
	stats->total_data = 0;
}

inline static void performance_check_start(struct performance_stats* stats){
	stats->total_cycle -= rdcycle();
}

inline static void performance_check_end(struct performance_stats* stats){
	stats->total_cycle += rdcycle();
}

inline static void performance_count(struct performance_stats* stats){
	++stats->checked_cnt;
}

inline static void performance_count_data(struct performance_stats* stats, unsigned long data){
	stats->total_data += data;
}

inline static unsigned long performance_stats_cycle(struct performance_stats* stats){
	if(!stats->total_cycle)
		return 0;
	return stats->total_cycle / stats->checked_cnt;
}

inline static void performance_stats_merge(struct performance_stats* stats, struct performance_stats* other){
	stats->total_cycle += other->total_cycle;
	stats->checked_cnt += other->checked_cnt;
	stats->total_data += other->total_data;
}

inline static void performance_check_start_with(struct performance_stats* stats, unsigned long start_cycle){
	stats->total_cycle -= start_cycle;
}

#endif

