#ifndef __XT_NCLIMIT_H__
#define __XT_NCLIMIT_H__

#include <linux/time.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include "connlimit.h"

#ifndef RULEID_NAME_SIZE
#define RULEID_NAME_SIZE 128
#endif  /* RULEID_NAME_SIZE */

/* nclimit match state machine */
enum nclimit_match_state {
	NCLIMIT_MSM_INIT	= 0,
	NCLIMIT_MSM_PRECHECK,
	NCLIMIT_MSM_POLICY,
	NCLIMIT_MSM_PERIP,
	//NCLIMIT_MSM_LOG,
	NCLIMIT_MSM_DONE,
};

/* nclimit match struct */
typedef struct ip_nclimit {
	struct hlist_node hnode;
	union nf_inet_addr ip;
	rate_unit_t r;
	unsigned long expires;
	struct rcu_head rcu;
	
} ip_nclimit_t;

typedef struct xt_nclimit_htable {
	struct hlist_head head[SIP_HASH_SIZE];
	struct hlist_node hnode;
	char 		name[RULEID_NAME_SIZE];
	union nf_inet_addr ip;
	u8 		family;
	unsigned long 	now, prev;
	rate_unit_t 	rs, rp;
	int 		log;
	int 		use;
	struct net 	*net;
	struct proc_dir_entry *pde;
	int 		count;
	int 		state;
	int 		next_state;
	int 		match;
	int 		hotdrop;
	spinlock_t	lock;
	struct timer_list timer; 	/* timer for gc */
	
} xt_nclimit_htable_t;

typedef struct xt_nclimit_info {
	char name[CONNLIMIT_NAME_LEN];
	char pf_name[RULEID_NAME_SIZE];
	rate_unit_t rs, rp;
	int log;

	/* Used internally by the kernel */
	unsigned long obj_addr;
	struct xt_nclimit_htable *hinfo;
	
} xt_nclimit_info_t;

/* For nclimit match state machine */
typedef struct nclimit_msm_state {
	int state;
	int next_state;
	xt_nclimit_info_t *info;
	xt_nclimit_htable_t *ht;
	const struct sk_buff *skb;
	int hotdrop;
	unsigned long now;
	
} nclimit_msm_state_t;

#endif	/* __XT_NCLIMIT_H__*/
