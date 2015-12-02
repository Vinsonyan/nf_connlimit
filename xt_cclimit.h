#ifndef __XT_CCLIMIT_H__
#define __XT_CCLIMIT_H__

#include <linux/time.h>
//#include <linux/netfilter/xt_ruleid.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include "connlimit.h"

#ifndef RULEID_NAME_SIZE
#define RULEID_NAME_SIZE 128
#endif	/* RULEID_NAME_SIZE */

enum cclimit_msm_state {
	CCLIMIT_MSM_INIT = 0,
	CCLIMIT_MSM_PERCHECK,
	CCLIMIT_MSM_PREBUILD,	/* Build ip_hash struct */
	CCLIMIT_MSM_POLICY,
	CCLIMIT_MSM_PERIP,
	CCLIMIT_MSM_EXTEND,
	CCLIMIT_MSM_DESTROY,
	CCLIMIT_MSM_DONE,
};

struct xt_cclimit_htable;

/* cclimit match struct */
typedef struct xt_cclimit_info {
	char name[CONNLIMIT_NAME_LEN];
	char ruleid[RULEID_NAME_SIZE];

	/* Used internally by the kernel */
	unsigned int overlimit;
	unsigned long obj_addr;
	connlimit_cfg_t *cfg;
	struct xt_cclimit_htable *hinfo;
	
} xt_cclimit_info_t;

typedef struct ip_cclimit {
	struct hlist_node hnode;
	union nf_inet_addr sip;
	atomic_t ip_count;
	atomic_t overlimit;

} ip_cclimit_t;

typedef struct xt_cclimit_htable {
	struct hlist_head	hhead[SIP_HASH_SIZE];
	struct hlist_node 	hnode;
	spinlock_t 		lock;
	ip_cclimit_t 	*ip_ptr;
	int 			use;
	char 			name[RULEID_NAME_SIZE];
	u8 family;
        unsigned long 		self_addr;
	unsigned long 			ip_limit_addr;
	atomic_t 		policy_count;
	struct net 		*net;
	struct proc_dir_entry 	*pde;
	atomic_t  		overlimit;
	int 			hotdrop;
	int 			match;
	int 			log;
	int 			state, next_state;
	
} xt_cclimit_htable_t;

/* Conntrack extend struct The structure embedded in the conntrack structure. */
#if 0
typedef struct nf_cclimit {
        struct hlist_node hnode;       
        union nf_inet_addr ip;
        unsigned long addr;   
} nf_cclimit_t;

typedef struct nf_conn_cclimit {
	struct hlist_head head;
	/* why exist ip,because destroy_conntrack 
	 * seq is hlist_del->nf_ct_remove_ext so..*/
	union nf_inet_addr ip;
	/* point of policy */
	unsigned int num;
	
} nf_conn_cclimit_t;
#endif

typedef struct nfct_cclimit {
	unsigned long addr, ip_limit_addr;
	union nf_inet_addr ip;
} nfct_cclimit_t;

static inline nfct_cclimit_t *nfct_cclimit(const struct nf_conn *ct)
{
	return nf_ct_ext_find(ct, NF_CT_EXT_CCLIMIT);
}
#endif	/* __XT_CCLIMIT_H__ */
