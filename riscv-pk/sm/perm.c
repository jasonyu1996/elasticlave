#include "perm.h"

#define NULL 0

static struct perm_config* find_perm_config_by_eid(
		struct region_perm_config* r_config,
		int eid){
	int i;
	for(i = 0; i < ENCLAVES_MAX; i ++)
		if(r_config->conf_list[i].eid == eid)
			return r_config->conf_list + i;
	return (struct perm_config*)0;
}


perm_t get_perm(
		struct region_perm_config* r_config,
		int eid){
	struct perm_config* p_conf = find_perm_config_by_eid(r_config, eid);	

	if(p_conf && (r_config->lock_holder == PERM_NO_LOCK_HOLDER || r_config->lock_holder == eid)) // here assume that untrusted_id == 0
		return p_conf->dyn_perm & ~PERM_L;
	return PERM_NULL;
}

int get_maps(
		struct region_perm_config* r_config,
		int eid){
	struct perm_config* p_conf = find_perm_config_by_eid(r_config, eid);	
	if(p_conf)
		return p_conf->maps;
	return 0;
}

int share_allowed(
		struct region_perm_config* r_config,
		int eid){
	return r_config->owner_id == eid;
}

struct perm_config* get_new_perm_config(
		struct region_perm_config* r_config){
	int i;
	for(i = 0; i < ENCLAVES_MAX; i ++){
		if(r_config->conf_list[i].st_perm == PERM_NULL)
			return r_config->conf_list + i;
	}
	return (struct perm_config*)0;
}

struct perm_config* get_perm_conf_by_eid(struct region_perm_config* r_config,
	   	int eid){
	int i;
	for(i = 0; i < ENCLAVES_MAX; i ++){
		if(r_config->conf_list[i].st_perm != PERM_NULL &&
				r_config->conf_list[i].eid == eid)
			return r_config->conf_list + i;
	}
	return (struct perm_config*)0;
}


st_perm_t get_st_perm(struct region_perm_config* r_config,
		int eid){
	struct perm_config* p_config = get_perm_conf_by_eid(r_config, eid);
	if(p_config)
		return p_config->st_perm;
	return PERM_NULL;
}

// return values:
// 0: unsuccessful
// 1: successful without IPI need
// 2: successful, IPI needed
int change_dyn_perm(struct region_perm_config* perm_conf, int eid, dyn_perm_t dyn_perm){
	int lock = dyn_perm & PERM_L;
	if(lock && perm_conf->lock_holder != PERM_NO_LOCK_HOLDER &&
			perm_conf->lock_holder != eid)
		return 0; // region already locked by a different enclave
	struct perm_config* pconf = get_perm_conf_by_eid(perm_conf, eid);
	if(pconf == NULL || (dyn_perm & pconf->st_perm) != dyn_perm)
		return 0;
	pconf->dyn_perm = dyn_perm;
	if(lock != (pconf->dyn_perm & PERM_L)){
		if(lock)
			perm_conf->lock_holder = eid;
		else
			perm_conf->lock_holder = PERM_NO_LOCK_HOLDER;
		// change access for other enclaves
		return 2;
	}
	return 1;
}

void region_perm_config_reset(struct region_perm_config* perm_conf){
	perm_conf->lock_holder = PERM_NO_LOCK_HOLDER;
	int i;
	for(i = 0; i < ENCLAVES_MAX; i ++){
		perm_conf->conf_list[i].st_perm = PERM_NULL;
	}
}

uintptr_t get_accessors_mask(struct region_perm_config* perm_conf){
	uintptr_t mask = 0;
	int i;
	for(i = 0; i < ENCLAVES_MAX; i ++){
		if(perm_conf->conf_list[i].st_perm && perm_conf->conf_list[i].dyn_perm){
			mask |= 1 << i;
		}
	}
	return mask;
}
