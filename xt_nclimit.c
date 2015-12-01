/* Kernel module to match nclimit parameters. */

/* (C) 2015 LeadSec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/utsname.h>

#include "xt_nclimit.h"
#include "connlimit.h"
#include "class_core.h"

MODULE_LICENSE( "GPL" );
MODULE_DESCRIPTION( "x_tables new connections match module" );
MODULE_ALIAS( "ipt_nclimit" );
MODULE_ALIAS( "ip6t_nclimit" );

static DEFINE_MUTEX(nclimit_mutex);

struct nclimit_net {
	struct hlist_head	htables;
	struct proc_dir_entry	*ipt_nclimit;
	struct proc_dir_entry	*ip6t_nclimit;
};

static int nclimit_net_id;
static inline struct nclimit_net *nclimit_pernet(struct net *net)
{
	return net_generic(net, nclimit_net_id);
}

struct proc_dir_entry *nclimit_dir = NULL;
static const struct file_operations nclimit_file_ops;

static void
nclimit_print_log4(union nf_inet_addr addrsrc, const char *tbuff, unsigned long rate)
{
	printk(KERN_INFO "gettextkey(devid=0 date=\"%%s\" dname=\"themis\" logtype=28 "
			 "pri=5 ver=0.3.0 mod=%%s act=%%s "  
			 "dsp_msg=\" host: %%s's address group newconnect over limit,"
			 "over_limit=%%s \" fwlog=0);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%pI4);"
			 "gettextval(%lu);\n" ,
			 tbuff, "flowcontrol","drop", &(addrsrc.ip), rate);
	return ;
}

static void
nclimit_print_log6(union nf_inet_addr addrsrc, const char *tbuff, unsigned long rate)
{
	printk(KERN_INFO "gettextkey(devid=0 date=\"%%s\" dname=\"themis\" logtype=28 "
			 "pri=5 ver=0.3.0 mod=%%s act=%%s "  
			 "dsp_msg=\" host: %%s's address group newconnect over limit,"
			 "over_limit=%%s \" fwlog=0);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%pI6);"
			 "gettextval(%lu);\n" ,
			 tbuff, "flowcontrol", "drop", &(addrsrc.ip), rate);
	return ;
}

static void
nclimit_print_log(xt_nclimit_htable_t *ht, ip_nclimit_t *iplimit, u_int8_t flags)
{
	unsigned long current_rate = 0;
	char tbuff[64] = {0};
	if (!ht->log || (flags == PERIP_LOG && NULL == iplimit)) 
		return ;

	if (!net_ratelimit())
		return ;

	switch (flags) {
	case POLICY_LOG:
		current_rate = SAFEDIV(HZ, ht->stat.diff);
		break;
	case PERIP_LOG:
		current_rate = SAFEDIV(HZ, iplimit->stat.diff);
		break;

	default:
		printk("%s nclimit print log Error!\n",__func__);
	}

	if (0 == current_rate)
		return ;

	connlimit_get_time(tbuff);
	if (NFPROTO_IPV4 == ht->family)
		nclimit_print_log4(ht->ip, tbuff, current_rate);
	else if (NFPROTO_IPV6 == ht->family)
		nclimit_print_log6(ht->ip, tbuff, current_rate);

	return ;
}

static __inline__  void
nclimit_update_rateinfo(xt_nclimit_htable_t *ht, connlimit_cfg_t *cfg)
{
	rcu_read_lock();
	memcpy(&ht->rs, &cfg->rs, sizeof(ht->rs) * 2);
	ht->log = cfg->log;
	rcu_read_unlock();
	return ;
}

static inline void rateinfo_recalc(rate_unit_t *rateinfo, unsigned long now)
{
	rateinfo->credit += (now - rateinfo->prev) * CREDITS_PER_JIFFY;
	if (rateinfo->credit > rateinfo->credit_cap)
		rateinfo->credit = rateinfo->credit_cap;
	rateinfo->prev = now;
}

static ip_nclimit_t *
nclimit_find(xt_nclimit_htable_t *ht)
{
	struct hlist_node *pos;
	ip_nclimit_t *iplimit = NULL, *node = NULL;
	int hash = connlimit_ip_hash(ht->ip, NFPROTO_IPV4);

	hlist_for_each_entry_rcu(node, pos, &ht->head[hash], hnode) {
		if (nf_inet_addr_cmp(&node->ip, &ht->ip)) {
			iplimit = node;
			break;
		}
	}
	
	if (NULL == iplimit) 
		goto out;

	if (iplimit->r.cost == ht->rp.cost)
		goto out;

	/* update perip rateinfo by connlimit object */
	iplimit->r.cost = ht->rp.cost;
	iplimit->r.credit = ht->rp.credit;
	iplimit->r.credit_cap = ht->rp.credit_cap;

out:
	return iplimit;
}

static  ip_nclimit_t *
nclimit_alloc_init(xt_nclimit_htable_t *ht)
{
	int hash = 0;
	ip_nclimit_t *iplimit = NULL;

	iplimit = kzalloc(sizeof(ip_nclimit_t), GFP_ATOMIC);
	if (NULL == iplimit) 
		return NULL;

	iplimit->expires = jiffies + (20 * HZ);
	iplimit->ip = ht->ip;
	memcpy(&iplimit->r, &ht->rp, sizeof(iplimit->r));

	hash = connlimit_ip_hash(iplimit->ip, NFPROTO_IPV4);

	hlist_add_head_rcu(&iplimit->hnode, &ht->head[hash]);
	return iplimit;
}

static int nclimit_check_perip_limit(xt_nclimit_htable_t *ht, ip_nclimit_t **limit, unsigned long now)
{
	ip_nclimit_t *iplimit = NULL;
	
	rcu_read_lock();
	iplimit = nclimit_find(ht);
	if (NULL == iplimit) {
		iplimit = nclimit_alloc_init(ht);
		if (NULL == iplimit) { 
			ht->match = true;
			goto out;
		}

		/* sourct IP. */
		iplimit->ip = ht->ip;
		iplimit->r.prev = now;

		/* Initialize perIP connlimit rateinfo. */
		iplimit->r.credit = ht->rp.credit;
		iplimit->r.credit_cap = ht->rp.credit_cap;
		iplimit->r.cost = ht->rp.cost;

	} else {
		/* refresh expires */
		iplimit->expires = now + (20 * HZ);
		rateinfo_recalc(&iplimit->r, now);
	}

	if (iplimit->r.credit > iplimit->r.cost) 
		iplimit->r.credit -= iplimit->r.cost;
	else  
		ht->match = false;
			
out:
	if (iplimit) *limit = iplimit;

	rcu_read_unlock();
	return (ht->match);
}

#if 0
static void nclimit_update_htable(xt_nclimit_htable_t *ht)
{
	connlimit_cfg_t *cfg = NULL;

	rcu_read_lock();

	cfg = connlimit_get_cfg_rcu(info->obj_addr);
	if (NULL == cfg || NULL == ht) {
		ht->match = -1;
		goto out;
	}

	

	
out:		
	rcu_read_unlock();

}
#endif

static int 
nclimit_msm_init(const struct sk_buff *skb, struct xt_action_param *par)
{
	connlimit_cfg_t *cfg = NULL;
	xt_nclimit_info_t *info = (xt_nclimit_info_t *)par->matchinfo;
	xt_nclimit_htable_t *ht = (xt_nclimit_htable_t *)info->hinfo;

	rcu_read_lock();
	cfg = connlimit_get_cfg_rcu(info->obj_addr);
	if (NULL == cfg || NULL == ht) {
		ht->match = -1;
		goto out;
	}

	if ((ht->rp.cost == cfg->rp.cost) &&
	    (ht->rs.cost == cfg->rs.cost) &&
	    (ht->log == cfg->log)) {
		goto out;
	}

	nclimit_update_rateinfo(ht, cfg);
out:
	ht->match = true;
	ht->hotdrop = false;
	rcu_read_unlock();
	return (ht->match);
}

static int
nclimit_msm_precheck(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	xt_nclimit_info_t *info = (xt_nclimit_info_t *)par->matchinfo;
	xt_nclimit_htable_t *ht = info->hinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || (ct && nf_ct_is_confirmed(ct))) 
		goto no_check;

	if (0 == ht->rp.cost && 0 == ht->rs.cost)
		goto no_check;

	return (ht->match);
	
no_check:
	ht->next_state = NCLIMIT_MSM_DONE;
	return 0;
}

/* Check new connlimit for policy */
static int
nclimit_msm_policy(const struct sk_buff *skb, struct xt_action_param *par)
{
	xt_nclimit_info_t *info = (xt_nclimit_info_t *)par->matchinfo;
	xt_nclimit_htable_t *ht = info->hinfo;
	ip_nclimit_t *iplimit = NULL;
	
	do {
		if (0 == ht->rs.cost) 
			break;

		/* calculate rate for limit */		
		rateinfo_recalc(&ht->rs, ht->now);
		if (ht->rs.credit > ht->rs.cost) {
			ht->rs.credit -= ht->rs.cost;
			break;
		} else {
			/* calculate current overlimit rate for pring log */
			ht->stat.diff = ht->now - ht->stat.log_prev_timer;
			nclimit_print_log(ht,iplimit, POLICY_LOG);
			ht->stat.log_prev_timer = ht->now;

			/* Change msm state. */
			ht->match = false;
			ht->hotdrop = true;
			ht->next_state = NCLIMIT_MSM_DONE;
			break;
		}
	} while (0);

	return (ht->match);
}

/* Check new connlimit for perIP */
static int
nclimit_msm_perip(const struct sk_buff *skb, struct xt_action_param *par)
{
	xt_nclimit_info_t *info = (xt_nclimit_info_t *)par->matchinfo;
	xt_nclimit_htable_t *ht = info->hinfo;
	ip_nclimit_t *iplimit = NULL;

	do {
		if (0 == ht->rp.cost)
			break;
		
		ht->ip = (union nf_inet_addr)ip_hdr(skb)->saddr;
		ht->match = nclimit_check_perip_limit(ht, &iplimit, ht->now);
		if (true != ht->match) {
			/* calculate perip overlimit rate for print log */
			iplimit->stat.diff = ht->now - iplimit->stat.log_prev_timer;
			nclimit_print_log(ht, iplimit, PERIP_LOG);

			/* Change msm state. */
			ht->match = false;
			ht->hotdrop = true;
			ht->next_state = NCLIMIT_MSM_DONE;
			break;
		}
	} while (0);

	return (ht->match);
}

/*
 * the state table and each action
 */

struct {
	int (*action)(const struct sk_buff *skb, struct xt_action_param *par);
	int next_state;
} nclimit_state_table[] = {
	[NCLIMIT_MSM_INIT]       = {nclimit_msm_init,       NCLIMIT_MSM_PRECHECK },
	[NCLIMIT_MSM_PRECHECK]       = {nclimit_msm_precheck,       NCLIMIT_MSM_POLICY },
	[NCLIMIT_MSM_POLICY]  = {nclimit_msm_policy,  NCLIMIT_MSM_PERIP },
	[NCLIMIT_MSM_PERIP]= {nclimit_msm_perip,NCLIMIT_MSM_DONE },

	[NCLIMIT_MSM_DONE]        = {NULL,                   NCLIMIT_MSM_DONE},
};
 
/* 
 * msm: match state machine
 */
static bool nclimit_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	int match = true;
	xt_nclimit_info_t *info = (xt_nclimit_info_t*)par->matchinfo;
	xt_nclimit_htable_t *ht = info->hinfo;

	spin_lock_bh(&ht->lock);

	ht->now = jiffies;
	while (ht->state != NCLIMIT_MSM_DONE) {
		ht->next_state = nclimit_state_table[ht->state].next_state;
		
		match = nclimit_state_table[ht->state].action(skb, par);

		if (true == match) {

			/* some functions change the next state, see the state table */
			ht->state = ht->next_state;
		} else if (false == match) {

			/* no match result, force state chane to done */
			ht->state = NCLIMIT_MSM_DONE;
		} else {

			/* bad result, force state change to done */
			match = true;
			ht->state = NCLIMIT_MSM_DONE;
		}
	}
	
	ht->state = NCLIMIT_MSM_INIT;
	par->hotdrop = ht->hotdrop;

	spin_unlock_bh(&ht->lock);

	return match;
}

static xt_nclimit_htable_t *nclimit_htable_find_get(struct net *net,
		const char *name,
		u_int8_t family)
{
	struct nclimit_net *nclimit_net = nclimit_pernet(net);
	xt_nclimit_htable_t *hinfo = NULL;
	struct hlist_node *pos = NULL;

	hlist_for_each_entry(hinfo, pos, &nclimit_net->htables, hnode) {
		if (hinfo && hinfo->pde && 
		    !strncmp(name, hinfo->pde->name, strlen(name)) &&
		    hinfo->family == family) {
			hinfo->use++;
			return hinfo;
		}
	}
	return NULL;
}

static void 
nclimit_free_rcu(struct rcu_head *head)
{
	ip_nclimit_t *iplimit = container_of(head, ip_nclimit_t, rcu);
	kfree(iplimit);
}

static void
nclimit_free(xt_nclimit_htable_t *ht, ip_nclimit_t *iplimit)
{
	hlist_del_rcu(&iplimit->hnode);
	call_rcu_bh(&iplimit->rcu, nclimit_free_rcu);
	ht->count--;
}

static bool nclimit_select_all(const xt_nclimit_htable_t *ht,
		      const ip_nclimit_t *he)
{
	return true;
}
static bool nclimit_select_gc(const xt_nclimit_htable_t *ht,
		      const ip_nclimit_t *he)
{
	return time_after_eq(jiffies, he->expires);
}

static void nclimit_htable_cleanup(xt_nclimit_htable_t *ht,
			bool (*nclimit_select_gc)(const xt_nclimit_htable_t *ht, const ip_nclimit_t *he))
{
	int i = 0;
	ip_nclimit_t *iplimit;
	struct hlist_node *pos, *n;

	spin_lock_bh(&ht->lock);
	for (i = 0; i < SIP_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(iplimit, pos, n, &ht->head[i], hnode) {
			if ((*nclimit_select_gc)(ht, iplimit))
				nclimit_free(ht, iplimit);
		}
	}
	spin_unlock_bh(&ht->lock);
	return ;
}

static void nclimit_htable_gc(unsigned long htlong)
{
	xt_nclimit_htable_t *ht = (xt_nclimit_htable_t *)htlong;

	/* do some things */
	nclimit_htable_cleanup(ht, nclimit_select_gc);

	ht->timer.expires = jiffies + (20 * HZ);
	add_timer(&ht->timer);
}

static int nclimit_htable_create(struct net *net, xt_nclimit_info_t *info, 
				 connlimit_cfg_t *cfg, u_int8_t family)
{
	struct nclimit_net *nclimit_net = nclimit_pernet(net);
	xt_nclimit_htable_t *hinfo = NULL;
	int i = 0;

	hinfo = kzalloc(sizeof(xt_nclimit_htable_t), GFP_ATOMIC);
	if (hinfo == NULL)
		return -ENOMEM;
	info->hinfo = hinfo;

	for (i = 0; i < SIP_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&hinfo->head[i]);

	spin_lock_init(&hinfo->lock);
	strlcpy(hinfo->name, info->pf_name, sizeof(hinfo->name));
	hinfo->use = 1;
	hinfo->net = net;
	hinfo->family = family;
	nclimit_update_rateinfo(hinfo, cfg);
	hinfo->pde = proc_create_data(hinfo->name, 0, 
			(family == NFPROTO_IPV4) ?
			nclimit_net->ipt_nclimit : nclimit_net->ip6t_nclimit,
			&nclimit_file_ops, hinfo);
	
	if (hinfo->pde == NULL) {
		kfree(hinfo);
		return -ENOMEM;
	}
	
	setup_timer(&hinfo->timer, nclimit_htable_gc, (unsigned long)hinfo);
	hinfo->timer.expires = jiffies + (HZ * 20);
	add_timer(&hinfo->timer);
	
	hlist_add_head(&hinfo->hnode, &nclimit_net->htables);
	return 0;
}

static int nclimit_mt_check(const struct xt_mtchk_param *par)
{
	int ret = 0;
	connlimit_cfg_t *cfg = NULL;
	xt_nclimit_info_t *info = par->matchinfo;
	struct net *net = par->net;

	ret = nf_ct_l3proto_try_module_get(par->family);
	if (ret < 0) {
		printk("cannot load conntrack support for "
		       "address family %u\n", par->family);
		return ret;
	}

	info->obj_addr = connlimit_find_obj(info->name);
	if (0 == info->obj_addr)
		return -ENOMEM;

	rcu_read_lock();
	cfg = connlimit_get_cfg_rcu(info->obj_addr);
	if (NULL == cfg) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	rcu_read_unlock();
	mutex_lock(&nclimit_mutex);
	info->hinfo = nclimit_htable_find_get(net, info->pf_name, par->family);
	if (NULL == info->hinfo) {
		ret = nclimit_htable_create(net, info,cfg, par->family);
		if (ret != 0) {
			mutex_unlock(&nclimit_mutex);
			rcu_read_lock();
			return ret;
		}
	}
	mutex_unlock(&nclimit_mutex);
	rcu_read_lock();

	return 0;
}

static void htable_remove_proc_entry(xt_nclimit_htable_t *hinfo)
{
	struct nclimit_net *nclimit_net = nclimit_pernet(hinfo->net);
	struct proc_dir_entry *parent;

	if (hinfo->family == NFPROTO_IPV4)
		parent = nclimit_net->ipt_nclimit;
	else
		parent = nclimit_net->ip6t_nclimit;

	if (parent != NULL)
		remove_proc_entry(hinfo->name, parent);
}

static void nclimit_htable_destroy(xt_nclimit_htable_t *hinfo)
{
	del_timer_sync(&hinfo->timer);
	htable_remove_proc_entry(hinfo);
	nclimit_htable_cleanup(hinfo, nclimit_select_all);
	kfree(hinfo);

	return ;
}

static void nclimit_htable_put(xt_nclimit_htable_t *hinfo)
{
	if (--hinfo->use == 0) { 
		hlist_del(&hinfo->hnode);
		nclimit_htable_destroy(hinfo);
	}
	
	return ;
}

static void nclimit_mt_destroy(const struct xt_mtdtor_param *par)
{
	xt_nclimit_info_t *info = par->matchinfo;

	mutex_lock(&nclimit_mutex);
	connlimit_release_obj(info->obj_addr);
	nclimit_htable_put(info->hinfo);
	mutex_unlock(&nclimit_mutex);
//	nf_ct_l3proto_module_put(par->family);

	return ;
}

static struct xt_match nclimit_mt_reg[] __read_mostly = {
	{
		.name		= "nclimit",
		.family		= NFPROTO_UNSPEC,
		.checkentry	= nclimit_mt_check,
		.match		= nclimit_mt,
		.destroy	= nclimit_mt_destroy,
		.matchsize	= sizeof(xt_nclimit_info_t),
		.me		= THIS_MODULE,
	},
};

/* PROC stuff */
static void *nclimit_seq_start(struct seq_file *s, loff_t *pos)
{
	xt_nclimit_htable_t *ht = (xt_nclimit_htable_t *)s->private;
	unsigned int *bucket;

	spin_lock_bh(&ht->lock);

	if (*pos >= SIP_HASH_SIZE)
		return NULL;

	bucket = kzalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	if (ht) {
		seq_printf( s, "name=%-16s use=%-8d credit=%-6u "
				"credit_cap=%-6u cost=%-6u "
				"rp_credit=%-6u rp_credit_cap=%-6u rp_cost=%-6u\n",
				ht->name,ht->use,
				ht->rs.credit, ht->rs.credit_cap, ht->rs.cost,
				ht->rp.credit, ht->rp.credit_cap, ht->rp.cost);
	}

	*bucket = *pos;
	return bucket;
}

static void *nclimit_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= SIP_HASH_SIZE) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void nclimit_seq_stop(struct seq_file *s, void *v)
{
	xt_nclimit_htable_t *ht = (xt_nclimit_htable_t *)s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock_bh(&ht->lock);
}

static int nclimit_seq_show(struct seq_file *s, void *v)
{
	xt_nclimit_htable_t *ht = (xt_nclimit_htable_t *)s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct hlist_node *pos = NULL;
	ip_nclimit_t *iplimit = NULL;

	if (!hlist_empty(&ht->head[*bucket])) {
		hlist_for_each_entry(iplimit, pos, &ht->head[*bucket], hnode) {
			seq_printf(s, "ip_node = %-16pI4 hash = %u\n", 
				&(iplimit->ip),
				(unsigned int)*bucket);
		}
	}	

	return 0;
}

static const struct seq_operations nclimit_seq_ops = {
	.start = nclimit_seq_start,
	.next  = nclimit_seq_next,
	.stop  = nclimit_seq_stop,
	.show  = nclimit_seq_show
};

static int nclimit_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &nclimit_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode)->data;
	}
	return ret;
}

static const struct file_operations nclimit_file_ops = {
	.owner   = THIS_MODULE,
	.open    = nclimit_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static int __net_init nclimit_net_init(struct net *net)
{
	struct nclimit_net *nclimit_net = nclimit_pernet(net);
	INIT_HLIST_HEAD(&nclimit_net->htables);
	
	nclimit_dir = proc_mkdir("nclimit", proc_leadsec);
	if (!nclimit_dir)
		return -ENOMEM;

	nclimit_net->ipt_nclimit = proc_mkdir("ipt_nclimit", nclimit_dir);
	if (!nclimit_net->ipt_nclimit)
		return -ENOMEM;
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
	nclimit_net->ip6t_nclimit = proc_mkdir("ip6t_nclimit", nclimit_dir);
	if (!nclimit_net->ip6t_nclimit) {
		remove_proc_entry("ipt_nclimit", net->proc_net);
		return -ENOMEM;
	}
#endif
	return 0;
}

static void __net_exit nclimit_net_exit(struct net *net)
{
	
	remove_proc_entry("ipt_nclimit", nclimit_dir);
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
	remove_proc_entry("ip6t_nclimit", nclimit_dir);
#endif
	remove_proc_entry("nclimit", proc_leadsec);
	return ;
}

static struct pernet_operations nclimit_net_ops = {
	.init	= nclimit_net_init,
	.exit	= nclimit_net_exit,
	.id	= &nclimit_net_id,
	.size	= sizeof(struct nclimit_net),
};

/* PROC stuff end */
static int __init xt_nclimit_init( void )
{
	int ret = 0;

	ret = register_pernet_subsys(&nclimit_net_ops);
	if (ret <0)
		return ret;

	ret = xt_register_matches(nclimit_mt_reg, ARRAY_SIZE(nclimit_mt_reg));
	if (0 != ret) {
		printk(KERN_ERR "Reigister iptables match xt_nclimit failed.\n");
		goto unreg_subsys;
	}
	return ret;

unreg_subsys:
	unregister_pernet_subsys(&nclimit_net_ops);
	return ret;
}

static void __exit xt_nclimit_fint( void )
{
	xt_unregister_matches(nclimit_mt_reg, ARRAY_SIZE(nclimit_mt_reg));	
	unregister_pernet_subsys(&nclimit_net_ops);
	return ;
}

module_init(xt_nclimit_init);
module_exit(xt_nclimit_fint);
