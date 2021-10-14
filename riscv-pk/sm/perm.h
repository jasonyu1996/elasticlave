#ifndef H_PERM
#define H_PERM

#include <stdint.h>
#include "consts.h"

#define PERM_NULL 0
// read, write, execute
#define PERM_R 1
#define PERM_W 2
// PERM_X not used for now
#define PERM_X 4
// lock (exclusive access)
#define PERM_L 8
#define PERM_FULL (PERM_R | PERM_W | PERM_X | PERM_L)
#define PERM_NO_LOCK_HOLDER (-1)

typedef char perm_t;
typedef char dyn_perm_t;
typedef char st_perm_t;

struct perm_config {
	int eid;
	dyn_perm_t dyn_perm; // dynamic permissions
	st_perm_t st_perm; // static maximum permissions
	int maps; // number of maps
};

struct region_perm_config {
	// both owner_id and lock_holder are enclave ids
	int owner_id;
	int lock_holder;
	struct perm_config conf_list[ENCLAVES_MAX];
};

perm_t get_perm(struct region_perm_config* r_config, int eid);

struct perm_config* get_perm_conf_by_eid(struct region_perm_config* r_config,
	   	int eid);
st_perm_t get_st_perm(struct region_perm_config* r_config, int eid);

int share_allowed(
		struct region_perm_config* r_config,
		int eid);


struct perm_config* get_new_perm_config(
		struct region_perm_config* r_config);

int change_dyn_perm(struct region_perm_config* perm_conf, int eid, dyn_perm_t dyn_perm);

void region_perm_config_reset(struct region_perm_config* perm_conf);

uintptr_t get_accessors_mask(struct region_perm_config* perm_conf);

int get_maps(
		struct region_perm_config* r_config,
		int eid);

inline static int inc_maps(struct perm_config* p_config){
	return p_config->maps ++;
}

inline static int dec_maps(struct perm_config* p_config){
	if(p_config->maps <= 0)
		return p_config->maps;
	return p_config->maps --;
}

//typedef enum {
	//SHAREDR_NONE,
	//SHAREDR_OWNER,
	//SHAREDR_READ,
	//SHAREDR_FULL,
//} shared_region_rel;

//typedef enum {
	//SHAREDP_NONE,
	//SHAREDP_READ,
	//SHAREDP_FULL
//} shared_region_perm;

#endif
