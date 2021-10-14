#include "region.h"

struct region* get_region_by_uid(
		struct region* region_list,
	   	int count,
	   	uid_t uid){
	int i;
	for(i = 0; i < count; i ++){
		if(region_list[i].uid == uid &&
				region_list[i].type != REGION_INVALID)
			return region_list + i;
	}
	return NULL;
}
