#ifndef __XT_NCLIMIT_H__
#define __XT_NCLIMIT_H__

#include <linux/time.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include "connlimit.h"

#ifndef RULEID_NAME_SIZE
#define RULEID_NAME_SIZE 128
#endif  /* RULEID_NAME_SIZE */

#define SAFEDIV(x,y) ((y)? ({ u64 __tmp = x; do_div(__tmp, y); (unsigned int)__tmp; }) : 0)

/* nclimit match state machine */
enum nclimit_match_state {
	NCLIMIT_MSM_INIT	= 0,
	NCLIMIT_MSM_PRECHECK,
	NCLIMIT_MSM_POLICY,
	NCLIMIT_MSM_PERIP,
	NCLIMIT_MSM_DONE,
};

enum nclimit_log {
	POLICY_LOG = 0,
	PERIP_LOG,
};

typedef struct nclimit_stat {
	long   	diff;
	s64	now;
	s64   log_prev_timer;	
} nclimit_stat_t;

/* nclimit match struct */
typedef struct ip_nclimit {
	struct hlist_node hnode;
	
	/* source IP */
	union nf_inet_addr ip;

	/* connlimit information */
	rate_unit_t r;

	/* timeout */
	unsigned long expires;
	struct rcu_head rcu;

	/* For pring log */
	nclimit_stat_t	stat;
	
} ip_nclimit_t;

typedef struct ip_nclimit_head {
	struct hlist_head hhead;
	spinlock_t lock;

} ip_nclimit_hash_t;

typedef struct xt_nclimit_htable {
	ip_nclimit_hash_t iphash[SIP_HASH_SIZE];
	struct hlist_node hnode;
	char 		name[RULEID_NAME_SIZE];
	union nf_inet_addr ip;
	unsigned int	hash;
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
	
	/* For print log */
	nclimit_stat_t stat;
	
} xt_nclimit_htable_t;

typedef struct xt_nclimit_info {
	char name[CONNLIMIT_NAME_LEN];
	char pf_name[RULEID_NAME_SIZE];

	/* Used internally by the kernel */
	unsigned long obj_addr;
	struct xt_nclimit_htable *hinfo;
	
} xt_nclimit_info_t;

#endif	/* __XT_NCLIMIT_H__*/
