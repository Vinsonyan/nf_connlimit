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

#include "connlimit.h"
#include "class_core.h"

MODULE_LICENSE( "GPL" );
MODULE_DESCRIPTION( "connlimit network object module" );
MODULE_ALIAS( "ipt_connlimit" );
MODULE_ALIAS( "ip6t_connlimit" );

HLIST_HEAD(connlimit_list);
DEFINE_MUTEX(class_lock);

#define BRUST	HZ
#define MAX_CPJ (0xFFFFFFFF / (HZ*60*60*24))

/* Repeated shift and or gives us all 1s, final shift and add 1 gives
 * us the power of 2 below the theoretical max, so GCC simply does a
 * shift. */
#define _POW2_BELOW2(x) ((x)|((x)>>1))
#define _POW2_BELOW4(x) (_POW2_BELOW2(x)|_POW2_BELOW2((x)>>2))
#define _POW2_BELOW8(x) (_POW2_BELOW4(x)|_POW2_BELOW4((x)>>4))
#define _POW2_BELOW16(x) (_POW2_BELOW8(x)|_POW2_BELOW8((x)>>8))
#define _POW2_BELOW32(x) (_POW2_BELOW16(x)|_POW2_BELOW16((x)>>16))
#define POW2_BELOW32(x) ((_POW2_BELOW32(x)>>1) + 1)

#define CREDITS_PER_JIFFY POW2_BELOW32(MAX_CPJ)

void 
connlimit_get_time(char *tbuff)
{
        struct timespec ts;
        ts = CURRENT_TIME_SEC;

        CONNLIMIT_SHOW_TIME(ts.tv_sec + 8*60*60, tbuff);
        return ;
}
EXPORT_SYMBOL(connlimit_get_time);

static __inline__ void
connlimit_item_put(connlimit_item_t *item)
{
	if (item && atomic_dec_and_test(&item->refcnt)) {
		hlist_del(&item->hnode);
		if (item->cfg) netobj_kfree(item->cfg, sizeof(connlimit_cfg_t));
		item->cfg = NULL;	
		netobj_kfree(item, sizeof(connlimit_item_t));
	}
	return ;
}

static __inline__ void
connlimit_item_get(connlimit_item_t *item)
{
	if (item) atomic_inc(&item->refcnt);
	return ;
}

unsigned int 
connlimit_ip_hash(union nf_inet_addr u, u_int8_t family)
{
        if (family == NFPROTO_IPV4)
                return (ntohl(u.ip) & SIP_HASH_MASK);
        else
                return 0;
                
        return 0;
}
EXPORT_SYMBOL(connlimit_ip_hash);

unsigned long
connlimit_find_obj(const char *name)
{
	struct hlist_node *pos = NULL;
	connlimit_item_t *item = NULL, *found = NULL;

	mutex_lock(&class_lock);
	hlist_for_each_entry(item, pos, &connlimit_list, hnode) {
		if (!(strncmp(item->name, name, CONNLIMIT_NAME_LEN))) {
			connlimit_item_get(item);
			found = item;
			break;
		}
	}
	mutex_unlock(&class_lock);

	return (found ? (unsigned long)found : 0);
}
EXPORT_SYMBOL(connlimit_find_obj);

void
connlimit_release_obj(unsigned long addr)
{
	connlimit_item_t *item = NULL;

	mutex_lock(&class_lock);
	if (0 == addr)
		goto unlock;

	item = (connlimit_item_t *)addr;
	connlimit_item_put(item);

unlock:
	mutex_unlock(&class_lock);
	return ;
}
EXPORT_SYMBOL(connlimit_release_obj);

connlimit_cfg_t *
connlimit_get_cfg_rcu(unsigned long addr)
{
	connlimit_item_t *item = NULL;
	if (0 == addr)
		return NULL;

	item = (connlimit_item_t *)addr;
	return rcu_dereference(item->cfg);
}
EXPORT_SYMBOL(connlimit_get_cfg_rcu);

static int connlimit_construct_item(connlimit_request_t *request)
{
	int ret = 0;
	struct hlist_node *p = NULL;
	connlimit_item_t *item = NULL;
	connlimit_cfg_t *cfg = NULL;

	hlist_for_each_entry(item, p, &connlimit_list, hnode) {
		if (!(strncmp(item->name, request->name, 
				 	 CONNLIMIT_NAME_LEN))) {
			ret = -EEXIST;
			goto out;
		}
	}

	cfg = netobj_kzalloc(sizeof(connlimit_cfg_t), GFP_KERNEL);
	if (!cfg) {
		printk("connlimit_construct_item:memory insufficient");
		ret = -ENOMEM;
		goto out;
	}

	memcpy(cfg, &request->cfg, sizeof(connlimit_cfg_t));
	/* reclac rateinfo */
	cfg->rp.credit = HZ * cfg->avgp;
	cfg->rp.credit_cap = HZ * cfg->avgp;
	cfg->rp.cost = HZ;

	cfg->rs.credit = HZ * cfg->avgs;
	cfg->rs.credit_cap = HZ * cfg->avgs;
	cfg->rs.cost = HZ;

	item = netobj_kzalloc(sizeof(connlimit_item_t), GFP_KERNEL);
	if (NULL == item) {
		printk("connlimit: Alloc connlimit_item_t failed.\n");
		ret = -ENOMEM;
		goto out;
	}
	
	strlcpy(item->name, request->name, sizeof(item->name));
	atomic_set(&item->refcnt, 1);
	item->cfg = cfg;

	hlist_add_head(&item->hnode, &connlimit_list);
	return ret;
out:
	if (cfg)
		netobj_kfree(cfg, sizeof(connlimit_cfg_t));

	return ret;
}

static int connlimit_modify_item(connlimit_request_t *request)
{
	int ret = 0;
	struct hlist_node *p = NULL;
	connlimit_item_t *pos = NULL, *item = NULL;
	connlimit_cfg_t *new_cfg = NULL, *old_cfg = NULL;

	new_cfg = netobj_kzalloc(sizeof(connlimit_cfg_t), GFP_KERNEL);
	if (NULL == new_cfg) {
		printk("connlimit: Alloc connlimit_info_t failed.\n");
		ret = -ENOMEM;
		goto out;
	}
	
	memcpy(new_cfg, &request->cfg, sizeof(connlimit_cfg_t));
	/* reclac rateinfo */
	new_cfg->rp.credit = HZ * new_cfg->avgp;
	new_cfg->rp.credit_cap = HZ * new_cfg->avgp;
	new_cfg->rp.cost = HZ;

	new_cfg->rs.credit = HZ * new_cfg->avgs;
	new_cfg->rs.credit_cap = HZ * new_cfg->avgs;
	new_cfg->rs.cost = HZ;

	hlist_for_each_entry(pos, p, &connlimit_list, hnode) {
		if (pos && (0 == (strncmp(pos->name, request->name, CONNLIMIT_NAME_LEN)))) {
			item = pos;
			break;
		}
	}

	if (NULL == item) {
		printk("connlimit_modify: name not exist!\n");
		goto out;
	}

	old_cfg = rcu_dereference(item->cfg);
	rcu_assign_pointer(item->cfg, new_cfg);
	if (old_cfg) {
		synchronize_rcu();
		netobj_kfree(old_cfg, sizeof(connlimit_cfg_t));
	}

	return ret;
out:
	if (new_cfg)
		netobj_kfree(new_cfg, sizeof(connlimit_cfg_t));
	
	return ret;
}

static int connlimit_destruct_item(const char *name)
{
	int ret = 0;
	connlimit_item_t *item = NULL, *pos = NULL; 
	struct hlist_node *p = NULL, *n = NULL;

	hlist_for_each_entry_safe(pos, p, n, &connlimit_list, hnode) {
		if (0 == (strncmp(pos->name, name, 
				CONNLIMIT_NAME_LEN))) {
			item = pos;
			break;
		}
	}

	if ((NULL == item) || 
	    (item && 1 != atomic_read(&item->refcnt))) {
		printk("connlimit_destruct_item:delete connlimit object failed.\n");
		ret = -EEXIST;
		goto out;
	}
	
	connlimit_item_put(item);
out:
	return ret;
}

static int do_add_connlimit_cmd(void __user *user, int *len)
{
	int ret = 0;
	connlimit_request_t request;

	if (*len != sizeof(connlimit_request_t)) {
		printk("connlimit object information len is invalid"
			"kernel len [%zd] != user len [%d].\n", 
			sizeof(connlimit_request_t), *len);
		ret = -ENOPROTOOPT;
		goto out;
	}

	ret = copy_from_user(&request, user, *len);
	if (0 != ret) {
		printk("connlimit object copy from user to kernel failed.\n");
		goto out;
	}

	ret = connlimit_construct_item(&request);
	if (0 != ret) {
		printk("Construct connlimit object failed.\n");
		goto out;
	}
out:
	return ret;
	
}

static int do_modify_connlimit_cmd(void __user *user, int *len)
{
	int ret = 0;
	connlimit_request_t request;

	if (*len != sizeof(connlimit_request_t)) {
		printk("connlimit object information len is invalid"
			"kernel len [%zd] != user len [%d].\n", 
			sizeof(connlimit_request_t), *len);
		ret = -ENOPROTOOPT;
		goto out;
	}

	ret = copy_from_user(&request, user, *len);
	if (0 != ret) {
		printk("connlimit object copy from user to kernel failed.\n");
		goto out;
	}

	ret = connlimit_modify_item(&request);
	if (0 != ret) {
		printk("Construct connlimit object failed.\n");
		goto out;
	}
out:
	return ret;
}

static int do_delete_connlimit_cmd(void __user *user, int *len)
{
	int ret = 0;
	char name[CONNLIMIT_NAME_LEN] = {0};

	if (*len != sizeof(name)) {
		printk("connlimit object information len is invalid"
			"kernel len [%zd] != user len [%d].\n", 
			sizeof(name), *len);
		ret = -ENOPROTOOPT;
		goto out;
	}

	ret = copy_from_user(name, user, *len);
	if (0 != ret) {
		printk("delete connlimit object failed.\n");
		goto out;
	}

	ret =  connlimit_destruct_item(name);
	if (0 != ret) {
		printk("destruct connlimit item failed.\n");
		goto out;
	}
	
out:
	return ret;
}

static int do_show_connlimit_cmd( void __user *user, int *len )
{
	return 0;
}

static int do_exist_connlimit_cmd(void __user *user, int *len)
{
	return 0;
}

static sockopt_array connlimit_object_sockopt[] = {
	/* SET */
	{
		.id = CONNLIMIT_OBJ_ADD,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_add_connlimit_cmd,
	},
	{
		.id = CONNLIMIT_OBJ_MODIFY,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_modify_connlimit_cmd,
	},
	{
		.id = CONNLIMIT_OBJ_DELETE,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_delete_connlimit_cmd,
	},
	/* GET */
	{
		.id = CONNLIMIT_OBJ_SHOW,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_show_connlimit_cmd,
	},
	{
		.id = CONNLIMIT_OBJ_EXIST,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_exist_connlimit_cmd,
	},

	{},
};

/* Seq file and sysctl for Debug configureation */

#ifdef CONFIG_PROC_FS
static void *
connlimit_obj_seq_start( struct seq_file *seq, loff_t *pos )
{
/*
	seq_printf(seq, "Name       avgs    avgp    limits   "
			"limitp   rp_credit rp_cap rp_cost   "
			"rs_credit   rp_cap   rp_cost   refcnt(policy)");
*/	
	mutex_lock(&class_lock);
	return seq_hlist_start( &connlimit_list, *pos );
}

static void *
connlimit_obj_seq_next( struct seq_file *seq, void *v, loff_t *pos )
{
	return seq_hlist_next(v, &connlimit_list, pos);
}

static void 
connlimit_obj_seq_stop( struct seq_file *seq, void *v )
{
	mutex_unlock(&class_lock);
	return;
}

static int 
connlimit_obj_seq_show( struct seq_file *seq, void *v )
{
	connlimit_cfg_t *cfg = NULL;
	char buf[] = ""; 
	const connlimit_item_t *p = hlist_entry(v, connlimit_item_t, hnode);
	
	cfg = rcu_dereference(p->cfg);
	if (NULL == cfg)
		return 0;

	seq_printf(seq,  "%-12s %-8u %-8u %-8u %-8u perip = <%-8u %-8u  %u> %8s"
				      "policy = <%-8u %-8u %u>  %8s refcnt = <%2d>\n",
		  		 	p->name, cfg->avgs, cfg->avgp,
		   			cfg->limits, cfg->limitp, cfg->rp.credit,
		   			cfg->rp.credit_cap, cfg->rp.cost, buf,
		   			cfg->rs.credit, cfg->rs.credit_cap,
		   			cfg->rs.cost, buf, atomic_read(&p->refcnt));

	return 0;
}

static const struct seq_operations connlimit_obj_seq_ops = {
	.start          = connlimit_obj_seq_start,
	.next           = connlimit_obj_seq_next,
	.stop           = connlimit_obj_seq_stop,
	.show         = connlimit_obj_seq_show,
};

static int 
connlimit_obj_seq_open( struct inode *inode, struct file *file )
{
	return seq_open( file, &connlimit_obj_seq_ops );
}

const struct file_operations connlimit_obj_list_fops = {
	.owner          = THIS_MODULE,
	.open		= connlimit_obj_seq_open,
	.read         	= seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

struct proc_dir_entry *proc_connlimit;
static int __net_init 
connlimit_net_init( struct net *net )
{
	proc_connlimit = proc_mkdir("connlimit", proc_netobj);
	if ( !proc_connlimit )
		return -ENOMEM;

	if ( !proc_create_data( "connlimit", S_IRUGO, proc_connlimit, &connlimit_obj_list_fops, NULL ) )
		goto remove_connlimit;

	return 0;
	
remove_connlimit:
	remove_proc_entry( "connlimit", proc_netobj );
	return -ENOMEM;
}

static void __net_exit 
connlimit_net_exit( struct net *net )
{
	remove_proc_entry("connlimit", proc_connlimit);
	remove_proc_entry("connlimit",proc_netobj);
	return ;
}

static struct pernet_operations connlimit_net_ops = {
	.init = connlimit_net_init,
	.exit = connlimit_net_exit,
};

int
connlimit_obj_readproc_init( void )
{
	return register_pernet_subsys( &connlimit_net_ops );
}

void
connlimit_obj_readproc_exit( void )
{
	unregister_pernet_subsys( &connlimit_net_ops );
}

#else	/* CONFIG_PROC_FS */

int
connlimit_obj_readproc_init( void )
{
	return 0;
}

void
connlimit_obj_readproc_exit( void )
{
	return ;
}

#endif	/* CONFIG_PROC_FS */

int connlimit_obj_proc_init( void )
{
	return connlimit_obj_readproc_init();
}

void connlimit_obj_proc_fint( void )
{
	connlimit_obj_readproc_exit();
	return ;
}

static int __init connlimit_init( void )
{
	int ret = 0;
	ret = connlimit_obj_proc_init();
	if (0 != ret)
		goto out;

	ret = netobj_sockopts_register(connlimit_object_sockopt);	
	if (0 != ret)
		goto unreg_proc;

	ret = xt_nclimit_init();
	if (0 != ret) {
		printk("[connlimit]: Initiation nclimit match faile.\n");
		goto unreg_sockopt;
	}

	ret = xt_cclimit_init();
	if (0 != ret) {
		printk("[connlimit]:Initiation cclimit match failed.\n");
		goto unreg_nclimit;
	}

	return ret;

unreg_nclimit:
	xt_nclimit_fint();
unreg_sockopt:
	netobj_sockopts_unregister(connlimit_object_sockopt);
unreg_proc:
	connlimit_obj_proc_fint();
out:
	return ret;
}

static void __exit connlimit_fint( void )
{
	netobj_sockopts_unregister(connlimit_object_sockopt);
	connlimit_obj_proc_fint();
	xt_cclimit_fint();
	xt_nclimit_fint();
	return ;
}

module_init(connlimit_init);
module_exit(connlimit_fint);

