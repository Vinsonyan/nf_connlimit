/*
 * Tcp transparent proxy
 *
 * Copyright (c) 2015 Leadsec <Leadsec>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/skbuff.h>
#include <linux/sysctl.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_protocol.h>
#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_ip.h>
#include <linux/utsname.h>

#include "../../bridge/br_private.h"
//#include <linux/br_private.h>
#include "nf_proxy_tcp.h"

#ifdef CONFIG_UTM
#include <net/netfilter/utm_extend.h>
#endif  /* CONFIG_UTM */

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "Tcp transparent proxy modules" );

DEFINE_MUTEX(tproxy_lock);

#ifdef NF_PROXY_IPTABLES
tproxy_port_set_t *port_sets = NULL;
#endif	/* NF_PROXY_IPTABLES */
static struct nf_conn *tmp_ct = NULL;

static int debug_config = 0;
static int debug_pre = 0;
static int debug_output = 0;
static int debug_seq = 0;
static int debug_br = 0;
#ifdef NF_PROXY_IPTABLES
static int debug_fwd = 0;
#endif

static inline
void tproxy_print_tuple(const struct sk_buff *skb, int debug, char *func)
{
	const struct tcphdr *th;
	struct tcphdr _tcph;
	const struct iphdr *iph = ip_hdr(skb);

	if (!iph) return ;

	th = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_tcph), &_tcph);
	if (!th) return ;

	tproxy_print(debug, "[%s:] src=%pI4 dst=%pI4 sport=%u dport = %u.\n",
			func, &iph->saddr, &iph->daddr, 
			th ? ntohs(th->source) : 0,
			th ? ntohs(th->dest) : 0);
	return ;
}

static inline
struct net *tproxy_net(void)
{
	return &init_net;
}

static inline void tproxy_set_skb_mark(struct sk_buff *skb, int mark)
{
	skb->mark = mark; return ;
}

static inline int tproxy_set_connid(struct sk_buff *pskb, unsigned int hooknum)
{
	int action = NF_ACCEPT;
	
	if (pskb->nfct !=NULL)
		goto out;

	atomic_inc(&tmp_ct->ct_general.use);
	pskb->nfct = &tmp_ct->ct_general;
	pskb->nfctinfo = IP_CT_NEW;

out:
	return action;
}

static unsigned int nf_tproxy_localout(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
	struct sock *sk = skb->sk;
	bool transparent = true;

	if (!sk) goto out;

	transparent = ((sk->sk_state != TCP_TIME_WAIT &&
				inet_sk(sk)->transparent) ||
			(sk->sk_state == TCP_TIME_WAIT &&
			 inet_twsk(sk)->tw_transparent));

	if (!transparent)
		goto out;

	tproxy_print_tuple(skb, debug_output, "nf_tproxy_localout");
	return tproxy_set_connid(skb, hooknum);
out:
	return NF_ACCEPT;
}

static inline int tproxy_lookup_conntrack(struct sk_buff *skb)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h = NULL;
	int ret = 0;

	memset(&tuple, 0, sizeof(tuple));
        if (!nf_ct_get_tuplepr(skb,
                               skb_network_offset(skb),
                               PF_INET, &tuple)) {
		ret = -1;
                goto out;
        }

	tproxy_print_tuple(skb, debug_pre, "tproxy_lookup_conntrack");
	h = nf_conntrack_find_get(tproxy_net(), NF_CT_TPROXY_ZONE, &tuple); 
	if (!h) {
		ret = -2;
		goto out;
	}
	
	if (NF_CT_DIRECTION(h) != IP_CT_DIR_REPLY) {
		ret = -3;
		goto out;
	}
out:
	tproxy_print(debug_pre, "[%s:] return value[%d]\n", __func__, ret);
	if (h) nf_ct_put(nf_ct_tuplehash_to_ctrack(h));
	return ret;
}

static inline struct net_device *tproxy_bridge_parent(const struct net_device *dev)
{
	struct net_bridge_port *port = rcu_dereference(dev->br_port);

	return port ? port->br->dev : NULL;
}

static inline struct nf_bridge_info *tproxy_nf_bridge_alloc(struct sk_buff *skb)
{
	skb->nf_bridge = kzalloc(sizeof(struct nf_bridge_info), GFP_ATOMIC);
	if (likely(skb->nf_bridge))
		atomic_set(&(skb->nf_bridge->use), 1);

	return skb->nf_bridge;
}

static struct net_device *tproxy_setup_broute(struct sk_buff *skb)
{
	struct nf_bridge_info *nf_bridge = skb->nf_bridge;

	if (skb->pkt_type == PACKET_OTHERHOST) {
		skb->pkt_type = PACKET_HOST;
		nf_bridge->mask |= BRNF_PKT_TYPE;
	}

	nf_bridge->mask |= BRNF_BRIDGED;
	nf_bridge->physindev = skb->dev;
	skb->dev = tproxy_bridge_parent(skb->dev);

	return skb->dev;
}

static unsigned int nf_tproxy_connid_pre(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
	int err;
#ifdef NF_PROXY_BRIDGE
	struct net_bridge_port *port;
#endif	/* NF_PROXY_BRIDGE */

	err = tproxy_lookup_conntrack(skb);
	if (err != 0) {
		err = -1;
		goto out;
	}

#ifdef NF_PROXY_BRIDGE
	if (NULL != (port = rcu_dereference(skb->dev->br_port))) {
		nf_bridge_put(skb->nf_bridge);
		if (!tproxy_nf_bridge_alloc(skb)) {
			tproxy_print(debug_pre, "BUG[%s]: bridge alloc nf_bridge failed.\n", __func__);
			return NF_ACCEPT;
		}
	
		if(!tproxy_setup_broute(skb)) {
			tproxy_print(debug_pre, "BUG[%s]: tproxy setup broute failed.\n", __func__);
			return NF_ACCEPT;
		}

		tproxy_print(debug_pre, "%s dev[%s].\n", __func__, skb->dev->name);
	} 
#endif	/* NF_PROXY_BRIDGE */

	tproxy_print_tuple(skb, debug_pre, "nf_tproxy_connid_pre");
	return tproxy_set_connid(skb, hooknum);
	
out:
	tproxy_print(debug_pre, "err[%d]\n", err);	
	return NF_ACCEPT;
}	

static unsigned int nf_tproxy_route_pre(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	u16 zone;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out;

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY)
		goto out;

	zone = nf_ct_zone(ct);
	if (zone != NF_CT_TPROXY_ZONE)
		goto out;

	tproxy_set_skb_mark(skb, SKB_PROUTE_MARK);
out:
	tproxy_print(debug_pre, "%s mark_set[%u].\n",__func__, skb->mark);
	return NF_ACCEPT;
}

#ifdef NF_PROXY_IPTABLES
static int tproxy_lookup_port(u_int16_t port, struct sk_buff *skb)
{
	int ret = 0, i = 0;
	int num = port_sets->num;
	tproxy_port_t *port_set = (tproxy_port_t*)port_sets->port_set;

	rcu_read_lock();
	for (i = 0; i < num; i++)
		if (port_set[i].match_port == ntohs(port)) {
			skb->mark = port_set[i].proxy_flags;
			ret = 1;	
			break;
		}

	rcu_read_unlock();
	return ret;
}

static int tproxy_is_proxy_pkt(struct sk_buff *skb)
{
	int ret = 0;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
	const struct iphdr *ip;
#ifdef CONFIG_UTM
	struct utm_ct_policy *ucp = NULL;
#endif

	if (NULL == skb) {
		ret = 1;
		goto no_proxy_fwd;
	}

	ip = ip_hdr(skb);
	if (ip && ip->protocol != IPPROTO_TCP) {
		ret = 2;
		goto no_proxy_fwd;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || (IP_CT_DIR_REPLY == CTINFO2DIR(ctinfo))) {
		ret = 3;
		goto no_proxy_fwd;
	}

#ifdef CONFIG_UTM
	spin_lock_bh(&ct->lock);
	if ( NULL == (ucp = nf_ct_utm_policy_find(ct))) {
		spin_unlock_bh(&ct->lock);
		ret = 4;
		goto no_proxy_fwd;
	}

	if (!ucp->avpolicy) {
		spin_unlock_bh(&ct->lock);
		ret = 5;
		goto no_proxy_fwd;
	}
	spin_unlock_bh(&ct->lock);
#endif

	th = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_tcph), &_tcph);
	if (th == NULL) {
		pr_debug("nf_tproxy_hook:Dropping evil TCP offset=0 tinygram.\n");
		ret = 6;
		goto no_proxy_fwd;
	}

	if (!(tproxy_lookup_port(th->dest, skb))) {
		ret = 7;
		goto no_proxy_fwd;
	}

no_proxy_fwd:
	return ret;
}

static void skb_release_head_state(struct sk_buff *skb)
{
	skb_dst_drop(skb);
#ifdef CONFIG_XFRM
	secpath_put(skb->sp);
#endif
	if (skb->destructor) {
		WARN_ON(in_irq());
		skb->destructor(skb);
	}
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_conntrack_put(skb->nfct);
	nf_conntrack_put_reasm(skb->nfct_reasm);
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(skb->nf_bridge);
#endif
	/* XXX: IS this still necessary? - JHS */
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
#endif
#endif
}

static void tproxy_unlink_skb_from_network(struct sk_buff *skb)
{
	if (skb->nf_bridge && skb->nf_bridge->physindev)
		skb->dev = skb->nf_bridge->physindev;

	skb_release_head_state(skb);
	return ;
}

static unsigned int tproxy_forward_rercv(unsigned int hooknum,
				      struct sk_buff *skb,
				      const struct net_device *in,
				      const struct net_device *out,
				      int (*okfn)(struct sk_buff *))
{
        /* Determine whether you need deliver to proxy */
        if (tproxy_is_proxy_pkt(skb))
		return NF_ACCEPT;

        /* unlink the conntrack?? and dst or others from network system */
        tproxy_unlink_skb_from_network(skb);
        netif_rx(skb);
        return NF_STOLEN;
}
#else	/* NF_PROXY_IPTABLES */
static unsigned int tproxy_forward_rercv(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}

#endif	/* NF_PROXY_IPTABLES */

static struct nf_hook_ops nf_tproxy_ops[] __read_mostly = {
	{
		.hook		= nf_tproxy_localout,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_RAW - 1,
#if LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9)
		.enable         = HOOK_DISABLE,
		.hookname       = "tproxy_localout",
#endif	/* LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9) */
	},
	{
		.hook		= nf_tproxy_connid_pre,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_RAW - 1,
#if LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9)
		.enable         = HOOK_DISABLE,
		.hookname       = "tproxy_prerouting1",
#endif	/* LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9) */
	},
	{
		.hook		= nf_tproxy_route_pre,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_MANGLE + 1,
#if LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9)
		.enable         = HOOK_DISABLE,
		.hookname       = "tproxy_prerouting2",
#endif	/* LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9) */
	},
	{
                .hook           = tproxy_forward_rercv,          
                .owner          = THIS_MODULE, 
                .pf             = NFPROTO_IPV4,
                .hooknum        = NF_INET_FORWARD,
                .priority       = NF_IP_PRI_LAST,
#if LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9)
                .enable = HOOK_ENABLE,
                .hookname = "tproxy_forward",
#endif	/* LEADSEC_VERSION_CODE >= LEADSEC_VERSION(3,6,0,9) */
        },
};

struct tcpudphdr {
	__be16 src;
	__be16 dst;
};

static bool
ebt_conntrack_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct iphdr *ih;
	struct iphdr _iph;
	const struct tcpudphdr *pptr;
	struct tcpudphdr _ports;
	const struct nf_conntrack_tuple_hash *h = NULL;
	struct nf_conntrack_tuple tuple;
	bool match = true;
	const struct ebt_connid_info *info = par->matchinfo;

	ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (NULL == ih) {
		match = false;
		goto out;
	}
	
	if (ih->protocol != IPPROTO_TCP) {
		match = false;
		goto out;
	}

	pptr = skb_header_pointer(skb, ih->ihl*4,
			sizeof(_ports), &_ports);

	if (NULL == pptr) {
		match = false;
		goto out;
	}

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = ih->saddr;
	tuple.src.u.tcp.port = pptr->src;
	tuple.dst.u3.ip = ih->daddr;
	tuple.dst.u.tcp.port = pptr->dst;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = IPPROTO_TCP;
	
	tproxy_print(debug_br, "src=0x%x, sp=%u, dst=0x%x, dp=%u.\n", 
			ntohl(tuple.src.u3.ip), ntohl(tuple.src.u.tcp.port),
			ntohl(tuple.dst.u3.ip), ntohl(tuple.dst.u.tcp.port));
	
	h = nf_conntrack_find_get(tproxy_net(), info->zone_id, &tuple);
	if (!h) {
		match = false;
		goto out;
	} 

	if (NF_CT_DIRECTION(h) != IP_CT_DIR_REPLY) {
		match = false;
		goto out;
	}
	
out:
	if (h) nf_ct_put(nf_ct_tuplehash_to_ctrack(h));
	tproxy_print(debug_br, "[%s:] match %u.\n",__func__, match);
	return match;
}

static int ebt_conntrack_mt_check(const struct xt_mtchk_param *par)
{
	const struct ebt_connid_info *info = par->matchinfo;

	if (info->invert != 0 && info->invert != 1)
		return -EINVAL;

	if (info->zone_id < 0 || info->zone_id > 65535)
		return -EINVAL;

	return 0;
}

/* Ebtables matchs */
static struct xt_match ebt_conntrack_mt_reg __read_mostly = {
	.name		= "ctzone",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.match		= ebt_conntrack_mt,
	.checkentry	= ebt_conntrack_mt_check,
	.matchsize	= sizeof(struct ebt_connid_info),
	.me		= THIS_MODULE,
};

#ifdef NF_PROXY_IPTABLES
static int tproxy_create_port_sets(void)
{
	port_sets = kzalloc(sizeof(tproxy_port_set_t), GFP_KERNEL);
	if (!port_sets) {
		printk("Can't alloc memory for port_sets.\n");
		return -1;
	}

	return 0;
}

static void tproxy_release_port_sets(void)
{
        if (port_sets && port_sets->port_set) {
                kfree(port_sets->port_set);    
		rcu_assign_pointer(port_sets->port_set, NULL);
	}

        if (port_sets) kfree(port_sets);     
        return ;
}

static int do_tproxy_set_ports_cmd(void __user *user, unsigned len)
{
        int ret = 0;          
        int i = 0;
	tproxy_port_req_t *req = NULL;
        tproxy_port_t *old_set = NULL, *new_set = NULL;

	if (len < sizeof(req)) {
		printk("port_sets information len is invalid.");
		return -ENOPROTOOPT;
	}

        req = (tproxy_port_req_t*)kzalloc(len, GFP_KERNEL);
        if (!req) {
                printk("tproxy_set_ctl: Alloc memory for tproxy_port_req_t failed.\n");
                return -ENOMEM;
        }

	ret = copy_from_user(req, user, len);
        if ( 0 != ret ) {     
                printk( "Can not copy information from userspace to kernel!\n" );
                ret = -EINVAL;
                goto free_req;
        }

	if (len != sizeof(tproxy_port_req_t) + (req->num * sizeof(tproxy_port_t))) {
		printk("port_sets information len is invalid.\n");
		ret = -EINVAL;
		goto free_req;
	}
        
        if (0 != req->num) {  
                new_set = kzalloc(sizeof(tproxy_port_t) * req->num, GFP_KERNEL);
                if (!new_set) {                
                        printk("Tproxy: Can't alloc memory for tproxy_port_t.\n");
                        ret = -ENOMEM; 
                        goto free_req;
                }
        }

        memcpy(new_set, req->port_set, sizeof(tproxy_port_t) * req->num);
        old_set = port_sets->port_set;       
        port_sets->num = req->num;  
        rcu_assign_pointer(port_sets->port_set, new_set);
        
        for (i =0 ; i < port_sets->num; i++) 
                tproxy_print(debug_config, "%u %u %u.\n", 
                                port_sets->port_set[i].listen_port,  
                                port_sets->port_set[i].match_port,   
                                port_sets->port_set[i].proxy_flags); 

        if (old_set) {
                synchronize_rcu();             
                kfree(old_set);                
                old_set = NULL;                
        }

free_req:
	if (req) kfree(req);
	if (new_set) kfree(new_set);
	return ret;
}

static int do_tproxy_unset_ports_cmd(void __user *user, unsigned len)
{
	return 0;
}

static int do_tproxy_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	s32 ret = -EINVAL;

	if (((u32)cmd) >= SO_PROXY_SET_MAX || ((u32)cmd) < SO_PROXY_BASE) return ret;

	mutex_lock(&tproxy_lock);		
	switch (cmd) {
	case SO_PROXY_SET_PORT:
		ret = do_tproxy_set_ports_cmd(user,len);
		break;

	case SO_PROXY_UNSET_PORT:
		ret = do_tproxy_unset_ports_cmd(user, len);
		break;
		
	default:
		break;
	}
	mutex_unlock(&tproxy_lock);

	return ret;
}

#else	/* NF_PROXY_IPTABLES */

static int tproxy_create_port_sets(void)
{
	return 0;
}

static void tproxy_release_port_sets(void)
{
	return ;
}

static int do_tproxy_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	return 0;
}
#endif	/* NF_PROXY_IPTABLES */

static int do_tproxy_get_tuple(struct sock *sk, void __user *user, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = inet->inet_rcv_saddr;
	tuple.src.u.tcp.port = inet->inet_sport;
	tuple.dst.u3.ip = inet->inet_daddr;
	tuple.dst.u.tcp.port = inet->inet_dport;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = sk->sk_protocol;

	/* We only do TCP and SCTP at the moment: is there a better way? */
	if (sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_SCTP) {
		tproxy_print(debug_config, "SO_ORIGINAL_DST: Not a TCP/SCTP socket\n");
		return -ENOPROTOOPT;
	}

	if ((unsigned int) *len < sizeof(struct sockaddr_in)) {
		tproxy_print(debug_config, "SO_ORIGINAL_DST: len %d not %Zu\n",
			 *len, sizeof(struct sockaddr_in));
		return -EINVAL;
	}

	h = nf_conntrack_find_get(sock_net(sk), NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		sk_tuple_t stream;
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

		stream.family = AF_INET;
		stream.c.ip = ntohl(ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.src.u3.ip);
		stream.client_port = ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.src.u.tcp.port);

		stream.s.ip = ntohl(ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u3.ip);
		stream.server_port = ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL]
			.tuple.dst.u.tcp.port);
		
		tproxy_print(debug_config, "SO_GET_TUPLE_BY_SK: %pI4 %u\n",
			 &stream.c.ip, ntohs(stream.client_port));
		nf_ct_put(ct);
		if (copy_to_user(user, &stream, sizeof(stream)) != 0)
			return -EFAULT;
		else
			return 0;
	}
	tproxy_print(debug_config, "SO_ORIGINAL_DST: Can't find %pI4/%u-%pI4/%u.\n",
		 &tuple.src.u3.ip, ntohs(tuple.src.u.tcp.port),
		 &tuple.dst.u3.ip, ntohs(tuple.dst.u.tcp.port));
	return -ENOENT;
}

#ifdef NF_PROXY_IPTABLES
static int do_tproxy_show_port_sets(void __user *user, int *len)
{
	return 0;
}
#else	/* NF_PROXY_IPTABLES */
static int do_tproxy_show_port_sets(void __user *user, int *len)
{
	return 0;
}
#endif	/* NF_PROXY_IPTABLES */

static int do_tproxy_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	s32 ret = -EINVAL;
	
	if (((u32)cmd) >= SO_PROXY_GET_MAX || ((u32)cmd) < SO_PROXY_BASE) return ret;

	switch (cmd) {
	case SO_PROXY_GET_TUPLE:
		ret = do_tproxy_get_tuple(sk, user, len);
		break;

	case SO_PROXY_PROTO_EXIST:
	case SO_PROXY_PORT_SHOW:
		ret = do_tproxy_show_port_sets(user, len);
		break;

	default:
		break;
	}

	return ret;
}

static struct nf_sockopt_ops proxy_tcp_sockopts = {
	.pf			= PF_INET,
	.set_optmin	= SO_PROXY_BASE,
	.set_optmax	= SO_PROXY_SET_MAX,
	.set		= do_tproxy_set_ctl,
	.get_optmin	= SO_PROXY_BASE,
	.get_optmax	= SO_PROXY_GET_MAX,
	.get		= do_tproxy_get_ctl,
	.owner		= THIS_MODULE,
};

#ifdef CONFIG_NF_CONNTRACK_ZONES
static int tproxy_create_conn_zone(void)
{
	struct nf_conntrack_tuple t;
	int ret = 0;

	ret = nf_ct_l3proto_try_module_get(AF_INET);
	if (ret < 0)
		goto err1;

	memset(&t, 0, sizeof(t));
	tmp_ct = nf_conntrack_alloc(tproxy_net(), NF_CT_TPROXY_ZONE, &t, &t, GFP_KERNEL);
	ret = PTR_ERR(tmp_ct);
	if (IS_ERR(tmp_ct))
		goto err2;

	ret = 0;
	__set_bit(IPS_TEMPLATE_BIT, &tmp_ct->status);
	__set_bit(IPS_CONFIRMED_BIT, &tmp_ct->status);
	
	return 0;
	
err2:
	nf_ct_l3proto_module_put(AF_INET);
err1:
	return ret;
}

static void tproxy_destroy_conn_zone(void)
{
	nf_ct_put(tmp_ct);
}

#else
static int tproxy_create_conn_zone(void)
{
	return 0;
}

static void tproxy_destroy_conn_zone(void)
{
        return ;
}

#endif	/* CONFIG_NF_CONNTRACK_ZONES */

#ifdef CONFIG_PROC_FS
#ifdef NF_PROXY_IPTABLES
static void * tproxy_ports_seq_start( struct seq_file *seq, loff_t *pos )
{
	int num = port_sets->num;

	if (!(*pos)) {
		seq_puts(seq, "match_port     listen_port       BYTE(S)        proto_flags \n");
	}

	rcu_read_lock();
	return *pos >= num ? NULL: pos;
}

static void * tproxy_ports_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return ++(*pos) >= port_sets->num ? NULL: pos;
}

static void  tproxy_ports_seq_stop(struct seq_file *seq, void *v)
{
	rcu_read_unlock();
	return ;
}

static int tproxy_ports_seq_show(struct seq_file *seq, void *v)
{
	tproxy_port_t *set = port_sets->port_set;

	loff_t *pos = v;
	if ( NULL == v )
		return 0;

	seq_printf(seq, "%u      %u       %u\n", set[*pos].match_port,
		   set[*pos].listen_port, set[*pos].proxy_flags);

	return 0;
}
#else	/* NF_PROXY_IPTABLES */
static void * tproxy_ports_seq_start( struct seq_file *seq, loff_t *pos )
{
	return NULL;
}
static void * tproxy_ports_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}
static void  tproxy_ports_seq_stop(struct seq_file *seq, void *v)
{
	return ;
}

static int tproxy_ports_seq_show(struct seq_file *seq, void *v)
{
	return 0;
}
#endif	/* NF_PROXY_IPTABLES */

static const struct seq_operations tproxy_seq_ops = {
	.start	= tproxy_ports_seq_start,
	.next       = tproxy_ports_seq_next,
	.stop       = tproxy_ports_seq_stop,
	.show      = tproxy_ports_seq_show,
};

static int tproxy_ports_seq_open( struct inode *inode, struct file *file )
{
	return seq_open(file, &tproxy_seq_ops);
}

static const struct file_operations tproxy_file_fops = {
	.owner          = THIS_MODULE,
	.open		= tproxy_ports_seq_open,
	.read         	= seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

struct proc_dir_entry *proc_tproxy = NULL;

static int __net_init 
tproxy_net_init(struct net *net)
{
	struct proc_dir_entry *entry = NULL;

	if (!proc_leadsec) {
		return -ENOMEM;
	}
	
	proc_tproxy = proc_mkdir("tproxy", proc_leadsec);
	if (!proc_tproxy)
		return -ENOMEM;

	entry = proc_create_data("proxy_port_sets", S_IRUGO, proc_tproxy, &tproxy_file_fops, NULL);
	if (!entry)
		return -ENOMEM;

	proc_symlink("debug_config", proc_tproxy, TPROXY_PROC_PATH"/debug_config");
	proc_symlink("debug_pre", proc_tproxy, TPROXY_PROC_PATH"/debug_pre");
	proc_symlink("debug_output", proc_tproxy, TPROXY_PROC_PATH"/debug_output");
	proc_symlink("debug_seq", proc_tproxy, TPROXY_PROC_PATH"/debug_seq");
	proc_symlink("debug_br", proc_tproxy, TPROXY_PROC_PATH"/debug_br");
#ifdef NF_PROXY_IPTABLES
	proc_symlink("debug_fwd", proc_tproxy, TPROXY_PROC_PATH"/debug_fwd");
#endif	/* NF_PROXY_IPTABLES */
		
	return 0;
}

static void __net_exit 
tproxy_net_exit(struct net *net)
{
	remove_proc_entry("proxy_port_sets", proc_tproxy);
#ifdef NF_PROXY_IPTABLES
	remove_proc_entry("debug_fwd", proc_tproxy);
#endif	/* NF_PROXY_IPTABLES */
	remove_proc_entry("debug_config",proc_tproxy);
	remove_proc_entry("debug_pre", proc_tproxy);
	remove_proc_entry("debug_output", proc_tproxy);
	remove_proc_entry("debug_seq", proc_tproxy);
	remove_proc_entry("debug_br", proc_tproxy);

	remove_proc_entry("tproxy", proc_leadsec);
	return ;
}

static struct pernet_operations tproxy_net_ops = {
	.init = tproxy_net_init,
	.exit = tproxy_net_exit,
};

static int
tproxy_read_proc_init(void)
{
	return register_pernet_subsys(&tproxy_net_ops);
}

static void
tproxy_read_proc_exit(void)
{
	unregister_pernet_subsys(&tproxy_net_ops);
}

#else	/* CONFIG_PROC_FS */

static int
tproxy_read_proc_init(void)
{
	return 0;
}

static void
tproxy_read_proc_exit(void)
{
	return;
}

#endif	/* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
struct ctl_table_header *tproxy_sysctl_header = NULL;

static ctl_table tproxy_sysctl_table[] = {
	{
		.procname		= "debug_config",
		.data			= &debug_config,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
		
	},
	{
		.procname		= "debug_pre",
		.data			= &debug_pre,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler		= &proc_dointvec,
		
	},
	{
		.procname		= "debug_output",
		.data			= &debug_output,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "debug_seq",
		.data			= &debug_seq,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname		= "debug_br",
		.data			= &debug_br,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},
#ifdef NF_PROXY_IPTABLES
	{
		.procname		= "debug_fwd",
		.data			= &debug_fwd,
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
	},

#endif

	{ }
};

static ctl_table tproxy_chiledir_table[] = {
	{
		.procname	= "tproxy",
		.mode		= 0555,
		.child		= tproxy_sysctl_table,
	},
	{ }
};

static ctl_table tproxy_root_table[] = {
	{
		.procname	= "leadsec",
		.mode		= 0555,
		.child		= tproxy_chiledir_table,
	},
	{ }
};

static int tproxy_sysctl_init(void)
{
	tproxy_sysctl_header = register_sysctl_table(tproxy_root_table);
	if (NULL == tproxy_sysctl_header)
		return -ENOMEM;

	return 0;
}

static void tproxy_sysctl_fint(void)
{
	unregister_sysctl_table(tproxy_sysctl_header);
	return ;
}
#else	/* CONFIG_SYSCTL */

static int tproxy_sysctl_init( void )
{
	return 0;
}

static void tproxy_sysctl_fint( void )
{
	return ;
}

#endif	/* CONFIG_SYSCTL */

static int 
tproxy_proc_init(void)
{
	int ret = 0;

	ret = tproxy_sysctl_init();
	if ( ret != 0 )
		return ret;

	ret = tproxy_read_proc_init();
	if (ret != 0)
		goto unreg_sysctl;

	return ret;

unreg_sysctl:
	tproxy_sysctl_fint();
	
	return ret;
}

static void
tproxy_proc_exit(void)
{
	tproxy_read_proc_exit();
	tproxy_sysctl_fint();
}

int __init nf_tproxy_init(void)
{
	int ret = -1;

	ret = tproxy_create_conn_zone();
	if (ret < 0) {
		printk("[nf_tproxy_init:] create conntrack zone failed.\n");
		goto out;
	}

	ret = tproxy_create_port_sets();
	if (ret < 0) {
		printk("Alloc memory for port_sets failed.\n");
		goto free_template_ct;
	}
	
	ret = nf_register_hooks(nf_tproxy_ops,
			ARRAY_SIZE(nf_tproxy_ops));
	if (ret < 0) {
		printk("[nf_tproxy_init:] Register nf_hooks failed.\n");
		goto free_port_sets;
	}

	ret = nf_register_sockopt(&proxy_tcp_sockopts);
	if (ret < 0) {
		printk("[nf_proxy_tcp_init:] can't register hooks.\n");
		goto unreg_nf_hooks;
	}

	ret = xt_register_match(&ebt_conntrack_mt_reg);
	if (ret < 0) {
		printk("[nf_proxy_tcp_init:] register nf_brige matchs failed.\n");
		goto unreg_nf_sockopt;
	}

	ret = tproxy_proc_init();
	if ( ret != 0 )
		goto unreg_xt_matchs;

	return ret;
	
unreg_xt_matchs:
	xt_unregister_match(&ebt_conntrack_mt_reg);	
unreg_nf_sockopt:
	nf_unregister_sockopt(&proxy_tcp_sockopts);
unreg_nf_hooks:
	nf_unregister_hooks(nf_tproxy_ops, ARRAY_SIZE(nf_tproxy_ops));
free_port_sets:
	tproxy_release_port_sets();
free_template_ct:
	tproxy_destroy_conn_zone();
out:
	return ret;
}

static void __exit nf_tproxy_fint(void)
{
	tproxy_proc_exit();
	nf_unregister_sockopt(&proxy_tcp_sockopts);
	nf_unregister_hooks(nf_tproxy_ops, ARRAY_SIZE(nf_tproxy_ops));
	xt_unregister_match(&ebt_conntrack_mt_reg);
	tproxy_release_port_sets();
	tproxy_destroy_conn_zone();
	return ;
}

module_init(nf_tproxy_init);
module_exit(nf_tproxy_fint);
