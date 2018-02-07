/* Kernel module to netobj parameters. */

/* (C) 2013 LeadSec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netfilter.h>
#include <net/netfilter/fastpath/fastpath.h>
#include <net/net_namespace.h>
#include "class_core.h"

static LIST_HEAD( class_list );
DEFINE_MUTEX( class_lock );
EXPORT_SYMBOL_GPL( class_lock );
static mem_info_t mem_info;

sockopt_func sockopt_get_func[NET_OBJECT_GET_MAX-NET_OBJECT_BASE] = {NULL};
sockopt_func sockopt_set_func[NET_OBJECT_SET_MAX-NET_OBJECT_BASE] = {NULL};

/* Register socketopt functions */
int netobj_sockopts_register( sockopt_array *sockopts  )
{
	u32 index;
	sockopt_func *func_list;

	while ( sockopts->id ) {
		if ( sockopts->id < NET_OBJECT_BASE ) return -1;
		if ( sockopts->method ) {
			if ( sockopts->id >= NET_OBJECT_SET_MAX ) return -1;
			func_list = sockopt_set_func;
		} else {
			if ( sockopts->id >= NET_OBJECT_GET_MAX ) return -1;
			func_list = sockopt_get_func;
		}

		index = sockopts->id - NET_OBJECT_BASE;
		if ( func_list[index] || !sockopts->sockopt_proc ) 
			return -1;

		func_list[index] = sockopts->sockopt_proc;
		sockopts++;
	}

	return 0;

}

void netobj_sockopts_unregister(sockopt_array *sockopts)
{
	u32 index;
	sockopt_func *func_list;
	
	while ( sockopts->id ) {
		if ( sockopts->id < NET_OBJECT_BASE ) break;
		if ( sockopts->method ) {
			if ( sockopts->id >= NET_OBJECT_SET_MAX ) break;
			func_list = sockopt_set_func;
		}
		else {
			if ( sockopts->id >= NET_OBJECT_GET_MAX ) break;
			func_list = sockopt_get_func;
		}
		index = sockopts->id - NET_OBJECT_BASE;

		if ( !func_list[index] || !sockopts->sockopt_proc ) break;
		func_list[index] = NULL;
		sockopts++;
	}
	
	return ;
}

int
register_class_item( class_item_t *me )
{
	int err;
	class_item_t *ptr = NULL;
	
	ASSERT( me != NULL );
	
	mutex_lock( &class_lock );
	list_for_each_entry( ptr, &class_list, list ) {
		if ( strncmp(ptr->class_name, me->class_name, MAX_CLASS_NAME_LEN) == 0 ) {
			mutex_unlock( &class_lock );
			return -EEXIST;
		}
	}
	
	if ( me->sockopts ) {
		err = netobj_sockopts_register( me->sockopts );
		if ( err != 0 )
			goto unlock;
	}

	list_add_rcu( &me->list, &class_list );

unlock:
	mutex_unlock( &class_lock );

	return 0;
}

void
unregister_class_item( class_item_t *me )
{
	ASSERT( me != NULL );

	mutex_lock( &class_lock );
	list_del_rcu( &me->list );
	if ( me->sockopts ) 
		netobj_sockopts_unregister( me->sockopts );
		
	mutex_unlock( &class_lock );
	synchronize_rcu();
	return;
}

static int netobj_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	s32 ret = -EINVAL;
	u32 index;
	
	if ( ((u32)cmd) >= NET_OBJECT_SET_MAX ) return ret;
	
	index = cmd - NET_OBJECT_BASE;
	mutex_lock( &class_lock );
	if ( sockopt_set_func[index] ) {
		ret = sockopt_set_func[index](user, (int *)&len);
	}

	mutex_unlock( &class_lock );
	if (cmd == ADDR_GROUP_OBJ_MODIFY 
			|| cmd == SERVICE_OBJ_MODIFY
			|| cmd == SERV_GROUP_OBJ_MODIFY
			|| cmd == SECZONE_OBJ_SZ_SET
			|| cmd == TIMEOBJ_OBJ_SET
			|| cmd == TIMEGRP_OBJ_SET ) {
		if (GET_STATE_FLAG(ENABLE_RULE_FIRST))
			GLOBAL_TIME_STAMP_INC();
	}

	return ret;
}

static int netobj_get_ctl( struct sock *sk, int cmd, void __user *user, int *len )
{
	s32 ret = -EINVAL;
	u32 index;
	
	if ( ((u32)cmd) >= NET_OBJECT_GET_MAX ) return -EINVAL;
	
	ret = -EINVAL;
	index = cmd-NET_OBJECT_BASE;
	mutex_lock( &class_lock );
	if ( sockopt_get_func[index] ) {
		ret = sockopt_get_func[index](user, len);
	}
	mutex_unlock( &class_lock );
	return ret;
}

static struct nf_sockopt_ops netobj_sockopts = {
	.pf		= PF_INET,
	.get_optmin	= NET_OBJECT_BASE,
	.get_optmax	= NET_OBJECT_GET_MAX,
	.get		= netobj_get_ctl,
	.set_optmin	= NET_OBJECT_BASE,
	.set_optmax	= NET_OBJECT_SET_MAX,
	.set		= netobj_set_ctl,
	.owner		= THIS_MODULE,
};

/* Iptables callback */
	void
bind_class_item( class_item_t *me )
{
	if ( me )
		atomic_inc( &me->refcnt );
	return ;
}

	void
release_class_item( class_item_t *me )
{
	if ( me )
		atomic_dec( &me->refcnt );
	return ;
}

	class_item_t *
find_class_item( const char *class_name )
{
	class_item_t *ptr = NULL;
	class_item_t *result = NULL;

	ASSERT( class_name != NULL );

	rcu_read_lock();
	list_for_each_entry_rcu( ptr, &class_list, list ) {
		if ( strncmp(ptr->class_name, class_name, MAX_CLASS_NAME_LEN) == 0 ) {
			bind_class_item( ptr );
			result = ptr;
			break;
		}
	}
	rcu_read_unlock();
	return result;
}

/* Provide Api for each netobj match */
int
ipt_class_checkentry( void *matchinfo )
{
	class_match_t *class_info = ( class_match_t * )matchinfo;
	class_item_t *class_ptr = NULL;

	ASSERT( class_info != NULL );

	mutex_lock( &class_lock );
	/* Loopup class_item and bind it by class_name  */
	class_ptr = find_class_item( class_info->class_name );
	if ( !class_ptr ) { 
		mutex_unlock( &class_lock );
		printk( "Can't find class_item [%s] point addr.\n", class_info->class_name );
		return -EADDRNOTAVAIL;
	}
	
	class_info->class_ptr = class_ptr;

	/* Find and bind object */
	class_info->obj_addr = class_ptr->find_object( class_info->obj_name, class_info->flags );
	if ( !class_info->obj_addr ) {
		printk( "Can't find object [%s] addr!\n", class_info->obj_name );
		mutex_unlock( &class_lock );
		return -EADDRNOTAVAIL;
	}
	mutex_unlock( &class_lock );

	return 0;
}

void
ipt_class_destroy( void *matchinfo )
{
	class_match_t *class_info = ( class_match_t * )matchinfo;
	class_item_t *class_item = class_info->class_ptr;
	
	mutex_lock( &class_lock );
	class_item->release_object( class_info->obj_addr );
	release_class_item( class_item );
	mutex_unlock( &class_lock );
	return ;
}

void*
netobj_kzalloc( size_t size, gfp_t flags )
{
	void *p = netobj_kmalloc( size, flags );
	if ( NULL == p )
		return NULL;
	memset( p, size, 0 );
	return p;
}

void *
netobj_kmalloc( size_t size, gfp_t flags )
{
	void *p = NULL;
	size_t realsize = 0;
	mem_info_t *cfg = &mem_info;

	if ( size <= PAGE_SIZE ) {
		realsize = kmalloc_size( size );
		if ( cfg->total_alloc_realsize + realsize > cfg->mem_max_size && cfg->mem_max_size != 0 ) {
			printk( "netobj alloc memory over %lu," 
				"please increase by /proc/sys\n", (unsigned long)cfg->mem_max_size );	
			return NULL;
		}
		p = kzalloc( size, flags );
	} else if ( size <= PAGE_SIZE * 1024 ){
		realsize = getpages_size( size );
		if ( cfg->total_alloc_realsize + realsize > cfg->mem_max_size && cfg->mem_max_size != 0 ) {
			printk( "netobj alloc memory over %lu," 
				"please increase by /proc/sys\n", (unsigned long)cfg->mem_max_size );	
			return NULL;
		}
		p = (void *)__get_free_pages( flags, get_order(size) );
		
	} else {
		realsize = PAGE_ALIGN( size );
		if ( cfg->total_alloc_realsize + realsize > cfg->mem_max_size && cfg->mem_max_size != 0 ) {
                        printk( "netobj alloc memory over %lu,"
                                "please increase by /proc/sys\n", (unsigned long)cfg->mem_max_size );
                        return NULL;
                }
		p = __vmalloc( size, flags, PAGE_KERNEL );
	}
	
	if ( NULL == p )
		return NULL;
	
        if ( (size > PAGE_SIZE) && (size <= PAGE_SIZE * 1024) ) {
                cfg->getpages_size += size;
               	cfg->getpages_realsize += realsize;
                cfg->getpages_number++;
	}
        
	if ( size > PAGE_SIZE * 1024 ) {
		cfg->vmalloc_size += size;
		cfg->vmalloc_realsize += realsize;
		cfg->vmalloc_number++;
	}

        cfg->total_alloc_size += size;
        cfg->total_alloc_realsize += realsize;
	return p;
}

void
netobj_kfree( const void *p, size_t size )
{
	size_t realsize;
	mem_info_t *cfg = &mem_info;

        if ( size <= PAGE_SIZE ) {
                kfree( p );
                realsize = kmalloc_size( size );
        } else if ( size <= PAGE_SIZE * 1024 ){
                free_pages( (unsigned long)p, get_order(size) );
                realsize = getpages_size( size );
                cfg->getpages_size -= size;
                cfg->getpages_realsize -= realsize;
                cfg->getpages_number--;
        } else {
		vfree( p );
		realsize = kmalloc_size( size );
		cfg->vmalloc_size -= size;
		cfg->vmalloc_realsize -= realsize;
		cfg->vmalloc_number--;
	}

        cfg->total_alloc_size -= size;
        cfg->total_alloc_realsize -= realsize;
	return ;
}

/* For proc and sysctl and so on... */
#ifdef CONFIG_PROC_FS

struct proc_dir_entry *proc_netobj = NULL;

static int __net_init 
netobj_net_init( struct net *net )
{
	if ( !proc_leadsec ) {
		return -ENOMEM;
	}
	
	proc_netobj = proc_mkdir( "netobj", proc_leadsec );
	if ( !proc_netobj )
		return -ENOMEM;

	proc_symlink( "memory_max", proc_netobj, NETOBJ_PROC_PATH"/memory_max" );
	proc_symlink( "memory_info", proc_netobj, NETOBJ_PROC_PATH"/memory_info" );
	proc_symlink( "memory_use", proc_netobj, NETOBJ_PROC_PATH"/memory_use" );
		
	return 0;
}

static void __net_exit 
netobj_net_exit( struct net *net )
{
	remove_proc_entry( "memory_info", proc_netobj );
	remove_proc_entry( "memory_max", proc_netobj );
	remove_proc_entry( "memory_use", proc_netobj );

	remove_proc_entry( "netobj", proc_leadsec );
	return ;
}

static struct pernet_operations netobj_net_ops = {
	.init = netobj_net_init,
	.exit = netobj_net_exit,
};

static int
netobj_read_proc_init( void )
{
	return register_pernet_subsys( &netobj_net_ops );
}

static void
netobj_read_proc_exit( void )
{
	unregister_pernet_subsys( &netobj_net_ops );
}

#else	/* CONFIG_PROC_FS */

static int
netobj_read_proc_init( void )
{
	return 0;
}

static void
netobj_read_proc_exit( void )
{
	return;
}

#endif	/* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
struct ctl_table_header *netobj_sysctl_header = NULL;

static int netobj_sysctl_mem_info(ctl_table *ctl, int write,
                           void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int pos = 0, len = 0;
	char *info = mem_info.memory_info;
	const int max_size = sizeof( mem_info.memory_info );

	if (!*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	len = scnprintf( info + pos, max_size - pos, 
		"Max memory for netobj module:\t%zd", mem_info.mem_max_size );
	if ( !len  )
		goto done;
	pos += len;

	len = scnprintf( info + pos, max_size - pos, 
		"\nTotal memory for allocated:\t%zd", mem_info.total_alloc_realsize );
	if ( !len )
		goto done;
	pos += len;

	len = scnprintf( info + pos, max_size - pos,
		"\nTotal memory for use:\t%zd", mem_info.total_alloc_size );
	if ( !len )
		goto done;
	pos += len;

	len = scnprintf( info + pos, max_size - pos,
		"\nTotal getpages number:\t%d", mem_info.getpages_number );
	if ( !len )
		goto done;
	pos += len;

	len = scnprintf( info + pos, max_size - pos,
		"\nTotal vmalloc number:\t%d\n", mem_info.vmalloc_number );
	if ( !len )
		goto done;

doit:
	return proc_dostring( ctl, write, buffer, lenp, ppos );

done:
	printk( "Too small!!!\n" );
	goto doit;
}

static ctl_table netobj_sysctl_table[] = {
	{
		.procname		= "memory_max",
		.data			= &mem_info.mem_max_size,
		.maxlen			= sizeof( mem_info.mem_max_size ),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
		
	},
	{
		.procname		= "memory_info",
		.data			= &mem_info.memory_info,
		.maxlen			= sizeof( mem_info.memory_info ),
		.mode			= 0444,
		.proc_handler		= &netobj_sysctl_mem_info,
		
	},
	{
		.procname		= "memory_use",
		.data			= &mem_info.total_alloc_size,
		.maxlen			= sizeof( mem_info.total_alloc_size ),
		.mode			= 0444,
		.proc_handler	= &proc_dointvec,
	},
	{ }
};

static ctl_table netobj_chiledir_table[] = {
	{
		.procname	= "netobj",
		.mode		= 0555,
		.child		= netobj_sysctl_table,
	},
	{ }
};

static ctl_table netobj_root_table[] = {
	{
		.procname	= "leadsec",
		.mode		= 0555,
		.child		= netobj_chiledir_table,
	},
	{ }
};

static int netobj_sysctl_init( void )
{
	netobj_sysctl_header = register_sysctl_table( netobj_root_table );
	if ( NULL == netobj_sysctl_header )
		return -ENOMEM;

	return 0;
}

static void netobj_sysctl_fint( void )
{
	unregister_sysctl_table( netobj_sysctl_header );
	return ;
}

#else	/* CONFIG_SYSCTL */

static int netobj_sysctl_init( void )
{
	return 0;
}

static void netobj_sysctl_fint( void )
{
	return ;
}

#endif	/* CONFIG_SYSCTL */

static int 
netobj_proc_init( void )
{
	int ret = 0;

	
	ret = netobj_sysctl_init();
	if ( ret != 0 )
		return ret;

	ret = netobj_read_proc_init();
	if ( ret != 0 )
		goto unreg_sysctl;

	return ret;

unreg_sysctl:
	netobj_sysctl_fint();
	
	return ret;
}

static void
netobj_proc_exit( void )
{
	netobj_read_proc_exit();
	netobj_sysctl_fint();
}

static int __init
class_init( void )
{
	int ret = 0;

	ret = nf_register_sockopt( &netobj_sockopts );
	if ( ret != 0 )
		return ret;

	ret = netobj_proc_init();
	if ( ret != 0 )
		goto unreg_sockopt;

	/* Initialize configuration for memory statistics */
	memset( &mem_info, 0, sizeof(mem_info_t) );

	return ret;

unreg_sockopt:
	nf_unregister_sockopt( &netobj_sockopts );
	return ret;
}

static void __exit
class_fint( void )
{
	netobj_proc_exit();
	nf_unregister_sockopt( &netobj_sockopts );
	return ;
}

module_init( class_init );
module_exit( class_fint );

/* Export global variable */
EXPORT_SYMBOL_GPL( class_list );
EXPORT_SYMBOL_GPL( mem_info );
#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL_GPL( proc_netobj );
#endif

EXPORT_SYMBOL( register_class_item );
EXPORT_SYMBOL( unregister_class_item );
EXPORT_SYMBOL( netobj_sockopts_register );
EXPORT_SYMBOL( netobj_sockopts_unregister );
EXPORT_SYMBOL( find_class_item );
EXPORT_SYMBOL( bind_class_item );
EXPORT_SYMBOL( release_class_item );
EXPORT_SYMBOL( ipt_class_checkentry );
EXPORT_SYMBOL( ipt_class_destroy );
EXPORT_SYMBOL( netobj_kmalloc );
EXPORT_SYMBOL( netobj_kzalloc );
EXPORT_SYMBOL( netobj_kfree );
MODULE_LICENSE("GPL");

