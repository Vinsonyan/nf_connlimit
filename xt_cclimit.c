/* Kernel module to match cclimit parameters. */

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
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/utsname.h>

#include "xt_cclimit.h"
#include "class_core.h"

MODULE_LICENSE( "GPL" );
MODULE_DESCRIPTION( "x_tables cclimit match module" );
MODULE_ALIAS( "ipt_cclimit" );
MODULE_ALIAS( "ip6t_cclimit" );

struct cclimit_net {
	struct hlist_head	htables;
	struct proc_dir_entry	*ipt_cclimit;
	struct proc_dir_entry	*ip6t_cclimit;
};

static int cclimit_net_id;
static inline struct cclimit_net *cclimit_pernet(struct net *net)
{
	return net_generic(net, cclimit_net_id);
}

static DEFINE_SPINLOCK(cclimit_lock);

struct proc_dir_entry *cclimit_dir = NULL;
static const struct file_operations cclimit_file_ops;

static void 
cclimit_print_log4(union nf_inet_addr addrsrc, unsigned int overlimit, const char *tbuff)
{
	printk(KERN_INFO "gettextkey(devid=0 date=\"%%s\" dname=\"themis\" logtype=28 "
			 "pri=5 ver=0.3.0 mod=%%s act=%%s  "
			 "dsp_msg=\" host: %%s's address group concurrent connect over limit,"
			 "over_limit=%%s \" fwlog=0);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%pI4);"
			 "gettextval(%lu);\n",
			 tbuff,"flowcontrol","drop",&(addrsrc.ip), (unsigned long)overlimit);//&(addrsrc->ip),shareconncount->log_count);
	return ;
}

static void 
cclimit_print_log6(union nf_inet_addr addrsrc, unsigned int overlimit, const char *tbuff)
{
	printk(KERN_INFO "gettextkey(devid=0 date=\"%%s\" dname=\"themis\" logtype=28 "
			 "pri=5 ver=0.3.0 mod=%%s act=%%s  "
			 "dsp_msg=\" host: %%s's address group concurrent connect over limit,"
			 "over_limit=%%s \" fwlog=0);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%s);"
			 "gettextval(%pI4);"
			 "gettextval(%lu);\n",
			 tbuff,"flowcontrol","drop",&(addrsrc.ip), (unsigned long)overlimit);//&(addrsrc->ip),shareconncount->log_count);
	return ;
}

static void
cclimit_print_log(xt_cclimit_htable_t *ht, u_int32_t ip)
{
	char tbuff[64] = {0};

	if (0 == ht->log || !(net_ratelimit()))
		return ;
	
	connlimit_get_time(tbuff);

	if (NFPROTO_IPV4 == ht->family)
		cclimit_print_log4((union nf_inet_addr)ip, atomic_read(&ht->overlimit), tbuff);
	else if (NFPROTO_IPV6 == ht->family)
		cclimit_print_log6((union nf_inet_addr)ip, atomic_read(&ht->overlimit), tbuff);
	return ;
}

static __inline__ void cclimit_perip_get(ip_cclimit_t *sip_count)
{
	atomic_inc(&(sip_count->ip_count)); 
	return ;
}

static __inline__ void cclimit_perip_put(ip_cclimit_t *sip_count)
{
	if (sip_count && atomic_dec_and_test(&(sip_count->ip_count))) {
		hlist_del(&sip_count->hnode);
		kfree(sip_count);
		sip_count = NULL;
	}
	return ;
}

static __inline__ void cclimit_policy_get(xt_cclimit_htable_t *hinfo)
{
	atomic_inc(&hinfo->policy_count);
	return ;
}

static __inline__ void cclimit_policy_put(xt_cclimit_htable_t *hinfo)
{
	if (hinfo && atomic_read(&hinfo->policy_count))
		atomic_dec(&hinfo->policy_count);
	return ;
}

static int 
cclimit_msm_init(const struct sk_buff *skb, struct xt_action_param *par)
{
	connlimit_cfg_t *cfg = NULL;
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;

	ht->cfg = connlimit_get_cfg_rcu(info->obj_addr);
	if (NULL == cfg) {
		ht->match = -1;
		goto out;
	}

	ht->match = true;
	ht->hotdrop = false;

out:
	return (ht->match);
}

static int 
cclimit_msm_precheck(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;

	if (0 == ht->cfg->limitp && 0 == ht->cfg->limits) 
		goto out;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_confirmed(ct)) 
		goto out;
	
	return (ht->match);
out:	
	ht->next_state = CCLIMIT_MSM_DONE;
	return (ht->match);
}

static int 
cclimit_msm_prebuild(const struct sk_buff *skb, struct xt_action_param *par)
{
	ip_cclimit_t *ip_cclimit = NULL, *cur = NULL;
	struct hlist_node *next = NULL;
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;
	union nf_inet_addr sip = (union nf_inet_addr)ip_hdr(skb)->saddr;
	u_int32_t hash = connlimit_ip_hash(sip, ht->family);

	hlist_for_each_entry(cur, next, &ht->hhead[hash], hnode) {
		if (nf_inet_addr_cmp(&cur->sip, &sip)) {
			ip_cclimit = cur;
			break;
		}
	}

	if (NULL == ip_cclimit) {
		ip_cclimit = kzalloc(sizeof(ip_cclimit_t), GFP_ATOMIC);
		if (NULL == ip_cclimit) {
			printk(KERN_ERR "check_update_perip_count:" 
				"Alloc memory for perip count failed.\n");
			ht->match = -1;
			goto out;
		}
		ip_cclimit->sip = sip;
		atomic_set(&ip_cclimit->ip_count, 0);
		hlist_add_head(&ip_cclimit->hnode, &ht->hhead[hash]);
	}

	ht->ip_ptr = ip_cclimit;
	cclimit_policy_get(ht);
	cclimit_perip_get(ip_cclimit);

out:
	return (ht->match);
}

static int 
cclimit_msm_policy(const struct sk_buff *skb, struct xt_action_param *par)
{
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;

	if (0 == ht->cfg->limits)
		goto out;

	if (ht->cfg->limits < atomic_read(&ht->policy_count)) {
		ht->match = false;
		ht->hotdrop = true;
		atomic_inc(&ht->overlimit);
		ht->next_state = CCLIMIT_MSM_DESTROY;
		cclimit_print_log(ht, ip_hdr(skb)->saddr);
	}

out:
	return (ht->match);
}

static int 
cclimit_msm_perip(const struct sk_buff *skb, struct xt_action_param *par)
{
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;
	ip_cclimit_t *ip_cclimit = ht->ip_ptr;

	if (0 == ht->cfg->limitp ||
			(ht && NULL == ht->ip_ptr)) 
		goto out;

	if (ht->cfg->limitp < atomic_read(&ip_cclimit->ip_count)) {
		ht->match = false;
		ht->hotdrop = true;
		atomic_inc(&ip_cclimit->overlimit);
		ht->next_state = CCLIMIT_MSM_DESTROY;
		cclimit_print_log(ht, ip_hdr(skb)->saddr);
	}
	
out:
	return (ht->match);
}

static int 
cclimit_msm_ct_extend(const struct sk_buff *skb, struct xt_action_param *par)
{
	nfct_cclimit_t *cclimit = NULL;	
	xt_cclimit_info_t *info = (xt_cclimit_info_t *)par->matchinfo;
	xt_cclimit_htable_t *ht = info->hinfo;

	/* embedded cclimit conntrack extend to ct. */
	cclimit = nfct_cclimit((struct nf_conn *)skb->nfct);
	if (NULL == cclimit) {
		cclimit = nf_ct_ext_add((struct nf_conn *)skb->nfct, 
				NF_CT_EXT_CCLIMIT, 
				GFP_ATOMIC_LEADSEC);
		if (NULL == cclimit) {
			printk("Failed to add CCLIMIT extension\n");
			goto out;
		}
	}

	cclimit->ip = (union nf_inet_addr)ip_hdr(skb)->saddr;
	cclimit->addr = (unsigned long)ht->self_addr;
	cclimit->ip_limit_addr = (unsigned long)ht->ip_ptr;
	ht->next_state = CCLIMIT_MSM_DONE;

	return (ht->match);
out:
	ht->next_state = CCLIMIT_MSM_DESTROY;
	return (ht->match);
}

static int 
cclimit_msm_fint(const struct sk_buff *skb, struct xt_action_param *par)
{
	xt_cclimit_info_t *info = (xt_cclimit_info_t*)par->matchinfo;
	xt_cclimit_htable_t *ht = (xt_cclimit_htable_t *)info->hinfo;	

	if (true == ht->match || NULL == ht->ip_ptr)
		goto out;

	cclimit_policy_put(ht);
	cclimit_perip_put(ht->ip_ptr);

out:
	return (ht->match);
}

struct {
	int (*action)(const struct sk_buff *skb, struct xt_action_param *par);
	int next_state;
} cclimit_state_table[] = {

	[CCLIMIT_MSM_INIT]       = {cclimit_msm_init,       CCLIMIT_MSM_PERCHECK },
	[CCLIMIT_MSM_PERCHECK]       = {cclimit_msm_precheck,       CCLIMIT_MSM_PREBUILD },
	[CCLIMIT_MSM_PREBUILD]  = {cclimit_msm_prebuild,  CCLIMIT_MSM_POLICY },
	[CCLIMIT_MSM_POLICY]= {cclimit_msm_policy,CCLIMIT_MSM_PERIP },
	[CCLIMIT_MSM_PERIP]= {cclimit_msm_perip,CCLIMIT_MSM_EXTEND },
	[CCLIMIT_MSM_EXTEND]= {cclimit_msm_ct_extend,CCLIMIT_MSM_DESTROY },
	[CCLIMIT_MSM_DESTROY]= {cclimit_msm_fint,CCLIMIT_MSM_DONE },

	[CCLIMIT_MSM_DONE]        = {NULL,                   CCLIMIT_MSM_DONE},
};

static bool cclimit_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	int match = true;
	unsigned more_allowed;
	xt_cclimit_info_t *info = (xt_cclimit_info_t*)par->matchinfo;
	xt_cclimit_htable_t *ht = (xt_cclimit_htable_t *)info->hinfo;

	rcu_read_lock();
	spin_lock_bh(&ht->lock);
	more_allowed = CCLIMIT_MSM_DONE + 1;
	while (ht->state != CCLIMIT_MSM_DONE && --more_allowed) {
		ht->next_state = cclimit_state_table[ht->state].next_state;

		match = cclimit_state_table[ht->state].action(skb, par);

		if (true == match || false ==  match) {
			/* some functions change the next state, see the state table */
			ht->state = ht->next_state;
		} else {
			/* bad result, force state change to done */
			match = true;
			ht->state = CCLIMIT_MSM_DONE;
		}
	}

	ht->state = CCLIMIT_MSM_INIT;
	par->hotdrop = ht->hotdrop;

	spin_unlock_bh(&ht->lock);
	rcu_read_unlock();

	return match;
}

static xt_cclimit_htable_t *cclimit_htable_find_get(struct net *net,
		const char *name,
		u_int8_t family)
{
	struct cclimit_net *cclimit_net = cclimit_pernet(net);
	xt_cclimit_htable_t *hinfo = NULL;
	struct hlist_node *pos = NULL;

	hlist_for_each_entry(hinfo, pos, &cclimit_net->htables, hnode) {
		if (hinfo && hinfo->pde && 
		    !strncmp(name, hinfo->pde->name, strlen(name)) &&
		    hinfo->family == family) {
			hinfo->use++;
			return hinfo;
		}
	}
	return NULL;
}

static int cclimit_htable_create(struct net *net, xt_cclimit_info_t *info, 
		u_int8_t family)
{
	struct cclimit_net *cclimit_net = cclimit_pernet(net);
	xt_cclimit_htable_t *hinfo = NULL;
	int i = 0;

	hinfo = kzalloc(sizeof(xt_cclimit_htable_t), GFP_ATOMIC);
	if (hinfo == NULL)
		return -ENOMEM;
	info->hinfo = hinfo;

	for (i = 0; i < SIP_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&hinfo->hhead[i]);

	strncpy(hinfo->name, info->ruleid, sizeof(hinfo->name));
	spin_lock_init(&hinfo->lock);
	hinfo->match = true;
	hinfo->use = 1;
	hinfo->self_addr = (unsigned long)hinfo;
	hinfo->net = net;
	hinfo->family = family;
	hinfo->pde = proc_create_data(hinfo->name, 0, 
			(family == NFPROTO_IPV4) ?
			cclimit_net->ipt_cclimit : cclimit_net->ip6t_cclimit,
			&cclimit_file_ops, hinfo);
	
	if (hinfo->pde == NULL) {
		kfree(hinfo);
		return -ENOMEM;
	}
	
	hlist_add_head(&hinfo->hnode, &cclimit_net->htables);
	
	return 0;
}

static int cclimit_mt_check(const struct xt_mtchk_param *par)
{
	int ret = 0;
	xt_cclimit_info_t *info = par->matchinfo;
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

	spin_lock_bh(&cclimit_lock);
	info->hinfo = cclimit_htable_find_get(net, info->ruleid, par->family);
	if (NULL == info->hinfo) {
		ret = cclimit_htable_create(net, info, par->family);
		if (0 != ret) {
			spin_unlock_bh(&cclimit_lock);
			return ret;
		}
			
	}
	spin_unlock_bh(&cclimit_lock);

	return 0;
}

static void htable_remove_proc_entry(xt_cclimit_htable_t *ht)
{
	struct cclimit_net *cclimit_net = cclimit_pernet(ht->net);
	struct proc_dir_entry *parent;

	if (ht->family == NFPROTO_IPV4)
		parent = cclimit_net->ipt_cclimit;
	else
		parent = cclimit_net->ip6t_cclimit;

	if (parent != NULL)
		remove_proc_entry(ht->name, parent);
}

static inline int uncclimit(struct nf_conntrack_tuple_hash *i, xt_cclimit_htable_t *ht)
{
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(i);
	nfct_cclimit_t *cclimit = nfct_cclimit(ct);	

	if ((NULL == cclimit) || 
	   ((cclimit && (0 == cclimit->addr))))
		return 0;

	cclimit->addr = 0;
	cclimit->ip_limit_addr = 0;

	return 0;
}

static void __cclimit_htable_destroy(xt_cclimit_htable_t *ht, struct net *net)
{
	struct nf_conntrack_tuple_hash *h;
	const struct hlist_nulls_node *nn;
	unsigned int i;

	/* XXX ????  loop all of conntrack tuple hash and clean conn cclimit extend.
	   Why clear unconfirmed conn's cclimit extend??? */
	hlist_nulls_for_each_entry(h, nn, &net->ct.unconfirmed, hnnode)
		uncclimit(h, ht);

	for (i = 0; i < net->ct.htable_size; i++) {
		hlist_nulls_for_each_entry(h, nn, &net->ct.hash[i], hnnode)
			uncclimit(h, ht);
	}

	return ;
}

static void cclimit_htable_destroy(xt_cclimit_htable_t *ht)
{
	struct net *net;
	unsigned int i;
	ip_cclimit_t *node = NULL;
	struct hlist_node *prev = NULL, *next = NULL;
	
	htable_remove_proc_entry(ht);

	for (i = 0; i < SIP_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(node, prev, next, &ht->hhead[i], hnode) {
			hlist_del(&node->hnode);
			kfree(node);
			node = NULL;
		}
	}

	spin_lock_bh(&nf_conntrack_lock);
	for_each_net(net)
		__cclimit_htable_destroy(ht, net);
	spin_unlock_bh(&nf_conntrack_lock);
	
	kfree(ht);
	ht = NULL;			
	return ;
}

static void cclimit_htable_put(xt_cclimit_htable_t *ht)
{
	if (--ht->use == 0) { 
		hlist_del(&ht->hnode);
		cclimit_htable_destroy(ht);
	}
	
	return ;
}

static void cclimit_mt_destroy(const struct xt_mtdtor_param *par)
{
	xt_cclimit_info_t *info = par->matchinfo;

	connlimit_release_obj(info->obj_addr);
	spin_lock_bh(&cclimit_lock);
	cclimit_htable_put(info->hinfo);
	spin_unlock_bh(&cclimit_lock);
	
	return ;
}

static struct xt_match cclimit_mt_reg[] __read_mostly = {
	{
		.name		= "cclimit",
		.family		= NFPROTO_UNSPEC,
		.checkentry	= cclimit_mt_check,
		.match		= cclimit_mt,
		.destroy	= cclimit_mt_destroy,
		.matchsize	= sizeof(xt_cclimit_info_t),
		.me		= THIS_MODULE,
	},
};

/* if cclimit extend addr exist then loop iphash table dec ip_hash count and policy_count. */
static void nf_cclimit_cleanup_conntrack(struct nf_conn *ct)
{
	xt_cclimit_htable_t *ht = NULL;
	ip_cclimit_t *ip_cclimit = NULL;
	nfct_cclimit_t *cclimit = NULL;
	
	spin_lock_bh(&cclimit_lock);
	
	cclimit = nf_ct_ext_find(ct, NF_CT_EXT_CCLIMIT);
	if (NULL == cclimit || (0 == cclimit->addr))
		return ;

	ht = (xt_cclimit_htable_t *)cclimit->addr;
	spin_lock_bh(&ht->lock);
	
	ip_cclimit = (ip_cclimit_t*)cclimit->ip_limit_addr;
	cclimit_perip_put(ip_cclimit);
	cclimit_policy_put(ht);
	
	spin_unlock_bh(&ht->lock);
	spin_unlock_bh(&cclimit_lock);
	
	return;
}

static struct nf_ct_ext_type cclimit_extend __read_mostly = {
	.len		= sizeof(nfct_cclimit_t),
	.align		= __alignof__(nfct_cclimit_t),
	.destroy	= nf_cclimit_cleanup_conntrack,
	.id		= NF_CT_EXT_CCLIMIT,
	.flags	= NF_CT_EXT_F_PREALLOC,
};

/* PROC stuff */
static void *cclimit_seq_start(struct seq_file *s, loff_t *pos)
{
	xt_cclimit_htable_t *hinfo = (xt_cclimit_htable_t *)s->private;
	unsigned int *bucket;

	spin_lock_bh(&hinfo->lock);
	if (*pos >= SIP_HASH_SIZE)
		return NULL;

	bucket = kzalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	if (hinfo) {
		seq_printf(s, "name=%-16suse=%-8dself=0x%-12xcount=%u.\n",
				hinfo->name,
				hinfo->use,
				(unsigned int)hinfo->self_addr,
				atomic_read(&hinfo->policy_count));
	}

	*bucket = *pos;
	return bucket;
}

static void *cclimit_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= SIP_HASH_SIZE) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void cclimit_seq_stop(struct seq_file *s, void *v)
{
	xt_cclimit_htable_t *hinfo = (xt_cclimit_htable_t *)s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock_bh(&hinfo->lock);
}

static int cclimit_seq_show(struct seq_file *s, void *v)
{
	xt_cclimit_htable_t *hinfo = (xt_cclimit_htable_t *)s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct hlist_node *pos = NULL;
	ip_cclimit_t *ip_count = NULL;

	if (!hlist_empty(&hinfo->hhead[*bucket])) {
		hlist_for_each_entry(ip_count, pos, &hinfo->hhead[*bucket], hnode) {
			seq_printf(s, "ip_node = %-16pI4 curcount = %-12u hash = %u\n", 
				&(ip_count->sip), 
				atomic_read(&ip_count->ip_count),
				(unsigned int)*bucket);
		}
	}

	return 0;
}

static const struct seq_operations cclimit_seq_ops = {
	.start = cclimit_seq_start,
	.next  = cclimit_seq_next,
	.stop  = cclimit_seq_stop,
	.show  = cclimit_seq_show
};

static int cclimit_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &cclimit_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;
		sf->private = PDE(inode)->data;
	}
	return ret;
}

static const struct file_operations cclimit_file_ops = {
	.owner   = THIS_MODULE,
	.open    = cclimit_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

static int __net_init cclimit_net_init(struct net *net)
{
	struct cclimit_net *cclimit_net = cclimit_pernet(net);
	INIT_HLIST_HEAD(&cclimit_net->htables);
	
	cclimit_dir = proc_mkdir("cclimit", proc_leadsec);
	if (!cclimit_dir)
		return -ENOMEM;

	cclimit_net->ipt_cclimit = proc_mkdir("ipt_cclimit", cclimit_dir);
	if (!cclimit_net->ipt_cclimit)
		return -ENOMEM;
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
	cclimit_net->ip6t_cclimit = proc_mkdir("ip6t_cclimit", cclimit_dir);
	if (!cclimit_net->ip6t_cclimit) {
		remove_proc_entry("ipt_cclimit", net->proc_net);
		return -ENOMEM;
	}
#endif
	return 0;
}

static void __net_exit cclimit_net_exit(struct net *net)
{
	
	remove_proc_entry("ipt_cclimit", cclimit_dir);
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
	remove_proc_entry("ip6t_cclimit", cclimit_dir);
#endif
	remove_proc_entry("cclimit", proc_leadsec);
	return ;
}

static struct pernet_operations ccllimit_net_ops = {
	.init	= cclimit_net_init,
	.exit	= cclimit_net_exit,
	.id	= &cclimit_net_id,
	.size	= sizeof(struct cclimit_net),
};

/* PROC stuff end */
static int __init xt_cclimit_init( void )
{
	int ret = 0;

	ret = register_pernet_subsys(&ccllimit_net_ops);
	if (ret <0)
		return ret;

	ret = nf_ct_extend_register(&cclimit_extend);
	if (ret < 0) {
		printk(KERN_ERR "xt_cclimit: Unable to register extension.\n");
		goto unreg_subsys;
	}

	ret = xt_register_matches(cclimit_mt_reg, ARRAY_SIZE(cclimit_mt_reg));
	if (0 != ret) {
		printk(KERN_ERR "Reigister iptables match xt_cclimit failed.\n");
		goto unreg_ct_extend;
	}

	return ret;

unreg_ct_extend:
	nf_ct_extend_unregister(&cclimit_extend);
unreg_subsys:
	unregister_pernet_subsys(&ccllimit_net_ops);
	return ret;
}

static void __exit xt_cclimit_fint( void )
{
	xt_unregister_matches(cclimit_mt_reg, ARRAY_SIZE(cclimit_mt_reg));	
	nf_ct_extend_unregister(&cclimit_extend);
	unregister_pernet_subsys(&ccllimit_net_ops);
	return ;
}

module_init(xt_cclimit_init);
module_exit(xt_cclimit_fint);
