#ifndef __RT_STATS_H
#define __RT_STATS_H
#include "performance.h"

typedef struct {
	struct performance_stats args_copy_stats;
	struct performance_stats retval_copy_stats;
	struct performance_stats page_fault_stats;
	struct performance_stats stats_sbi;
	struct performance_stats stats_rt;
	struct performance_stats stats_boot_sbi;
	struct performance_stats stats_boot;
} rt_performance_stats_t;

extern rt_performance_stats_t stats;

#endif

