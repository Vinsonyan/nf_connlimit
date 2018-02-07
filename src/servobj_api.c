/* Kernel module to servobj parameters. */

/* (C) 2013 LeadSec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ip.h>

#include "class_core.h"
#include "servobj.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "service object kernel module" );

LIST_HEAD( servobj_list );

/* Socketopt operation functions */
int
servobj_construct_item( servobj_request_t *req )
{
	int ret = 0;
	size_t len = 0;
	servobj_item_t *object = NULL;
	servobj_info_t *new_info = NULL;
	u16 proto = 0;

	proto = req->serv_info.proto;

	list_for_each_entry( object, &servobj_list, list ) {
		if ( strncmp(object->name, req->name, MAX_OBJ_NAME_LEN) == 0 ) {
			duprintf( "servobj [%s] already exist!\n ", object->name );
			ret = -EEXIST;
			break;
		}
	}

	if ( ret != 0 )
		goto unlock;

	len = sizeof( servobj_info_t );
	new_info = netobj_kzalloc( len, GFP_ATOMIC );
	if ( !new_info )
		goto unlock;

	memcpy( new_info, &req->serv_info, sizeof(servobj_info_t) );	
	
	atomic_inc( &servobj_class.cfg.cur_size );
	if ( servobj_class.cfg.max_size &&
			unlikely(atomic_read(&servobj_class.cfg.cur_size) > servobj_class.cfg.max_size) ) {
		duprintf( "table full, droping request!\n" );
		atomic_dec( &servobj_class.cfg.cur_size );
		ret = -ENOMEM;
		goto unlock;
	}

	object = netobj_kmalloc( sizeof(servobj_item_t), GFP_ATOMIC );
	if ( object == NULL ) {
		duprintf( "Alloc memory for servobj failed!\n" );
		ret = -ENOMEM;
		atomic_dec( &servobj_class.cfg.cur_size );
		goto unlock;
	}

	object->size = sizeof( servobj_item_t );
	strncpy( object->name, req->name, MAX_OBJ_NAME_LEN );
	INIT_LIST_HEAD( &object->list );
	atomic_set( &object->refcnt, 0 );
	object->info = new_info;
	list_add( &object->list, &servobj_list );

	return ret;

unlock:
	if ( new_info )
		netobj_kfree( new_info, sizeof(servobj_info_t) );

	return ret;
}

static  inline int 
__servobj_destruct_item( servobj_item_t **object )
{
	int ret = 0;

	if ( *object == NULL )
		return -1;

	if ( (atomic_read( &(*object)->refcnt)) != 0 ) {
		duprintf( "Destruct servobj_item failed because refcnt is no-zero!\n" );
		return -EBUSY;
	}

	if ( (*object)->info )
		netobj_kfree( (*object)->info, sizeof(servobj_info_t) );

	netobj_kfree( *object, (*object)->size );
	*object = NULL;
	atomic_dec( &servobj_class.cfg.cur_size );
		
	return ret;
}

int
servobj_destruct_item( const char *name )
{
	servobj_item_t *object, *next;
	int ret = -ENOENT;

	list_for_each_entry_safe( object, next, &servobj_list, list ) {
		if ( strncmp(object->name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			if ( 0 != (atomic_read(&object->refcnt)) )
				break;
			list_del( &object->list );
			ret = __servobj_destruct_item( &object );
			if ( ret != 0 ) {
				duprintf( "Destruct servobj item failed!\n" );
				list_add( &object->list, &servobj_list );
			}
			break;
		}
	}

	return ret;
}

static inline int
__servobj_modify_item( servobj_item_t *object, servobj_info_t *new_info )
{
	servobj_info_t *old_info = NULL;
	ASSERT( object == NULL );
	ASSERT( new_info == NULL );

	old_info = rcu_dereference( object->info );
	rcu_assign_pointer( object->info, new_info );
	
	if ( old_info ) {
		synchronize_rcu();
		kfree( old_info );
	}
	
	return 0;
}

int
servobj_modify_item( servobj_request_t *info )
{
	servobj_item_t *object = NULL;
	servobj_info_t *new_info = NULL;
	int ret = -ENOENT;

	new_info = netobj_kzalloc( sizeof(servobj_info_t), GFP_KERNEL );
	if ( !new_info )
		return ret;

	memcpy( new_info, &info->serv_info, sizeof(servobj_info_t) );

	list_for_each_entry( object, &servobj_list, list  ) {
		if ( strncmp(object->name, info->name, MAX_OBJ_NAME_LEN) == 0 ) {
			ret = __servobj_modify_item( object, new_info );
			break;
		}
	}

	return ret;
}

int
servobj_flush_item( void )
{
	servobj_item_t *object, *next;
	int ret = -ENOENT;

	list_for_each_entry_safe( object, next, &servobj_list, list ) {
		if ( 0 != (atomic_read(&object->refcnt)) )
			break;
		list_del( &object->list );
		ret = __servobj_destruct_item( &object );
		if ( ret != 0 ) {
			list_add( &object->list, &servobj_list );
			duprintf( "Flush all servobj falied.\n" );
			break;
		}
	}

	return ret;
}

/* sockopt get functions */
int
servobj_exist_item( const char *name )
{
	int ret = 0;
	servobj_item_t *item;

	list_for_each_entry( item, &servobj_list, list ) {
		if ( strncmp(item->name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			ret = 1;
			break;
		}
	}


	return ret;
}

int
servobj_show_item( servobj_request_t *req )
{
	servobj_item_t *cur = NULL;
	int ret = -1;

	list_for_each_entry( cur, &servobj_list, list ) {
		if ( strncmp(cur->name, req->name, MAX_OBJ_NAME_LEN) == 0 ) {
			//memcpy( &req->serv_info, cur->info, sizeof(servobj_info_t) );
			req->serv_info = *cur->info;
			ret = 0;
			break;
		}	
	}

	return ret;
}

/* Class item operation functions */
servobj_item_t * 
service_find_obj( const char *name )
{
	servobj_item_t *object = NULL;
	servobj_item_t *result = NULL;
	
	list_for_each_entry( object, &servobj_list, list ) {
		if ( strncmp(object->name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			atomic_inc( &object->refcnt );
			result = object;
			break;
		}
	}

	return result;
}

void
service_release_obj( servobj_item_t *object )
{
	ASSERT( object == NULL );
	if ( object ) atomic_dec( &object->refcnt );
	return ;
}

int
service_match_func( servobj_item_t *object, const pkt_info_t *pkt_info )
{
	int match = 0;
	servobj_info_t *info = rcu_dereference(object->info);

	if ( !info )
		return match;

	rcu_read_lock();
	if ( info->proto != pkt_info->l3proto && info->proto != pkt_info->l4proto )
		goto unlock;

	switch ( info->proto ) {
	case IPPROTO_IP:
	case IPPROTO_IPV6:
		if ( info->proto == pkt_info->l3proto )
			match = 1;
		goto unlock;

	case IPPROTO_TCP:
		{
			const struct tcphdr *th;
			struct tcphdr _tcph;
			u16 sport, dport;
			th = skb_header_pointer( pkt_info->skb, pkt_info->thoff, sizeof(_tcph), &_tcph );
			if ( !th ) 
				goto unlock;
		
		 	sport = th->source;
			dport = th->dest;
			if ( ntohs(sport) < info->option.port.srcstart ||
				ntohs(sport) > info->option.port.srcend )
				goto unlock;
			if ( ntohs(dport) < info->option.port.dststart ||
				ntohs(dport) > info->option.port.dstend )
				goto unlock;
		}
		break;

	case IPPROTO_UDP:
		{
			const struct udphdr *uh;
			struct udphdr _udph;
			u16 sport, dport;
			uh = skb_header_pointer( pkt_info->skb, pkt_info->thoff, sizeof(_udph), &_udph );
			if ( !uh ) 
				goto unlock;
		
			sport = uh->source;
			dport = uh->dest;
			if ( ntohs(sport) < info->option.port.srcstart ||
				ntohs(sport) > info->option.port.srcend )
				goto unlock;
			if ( ntohs(dport) < info->option.port.dststart ||
				ntohs(dport) > info->option.port.dstend )
				goto unlock;
			
		}
		break;

	case IPPROTO_ICMP:
		{
			const struct icmphdr *icmph;
			struct udphdr _icmph;
			icmph = skb_header_pointer( pkt_info->skb, pkt_info->thoff, sizeof(_icmph), &_icmph );
			if ( !icmph ) 
				goto unlock;

			if ( info->option.icmp.flags & SERVICE_ICMP_TYPE_VALID ) {
				if ( info->option.icmp.type != icmph->type )
					goto unlock;
			}
			if ( info->option.icmp.flags & SERVICE_ICMP_CODE_VALID ) {
				if ( info->option.icmp.code[0] > icmph->code ||
					info->option.icmp.code[1] < icmph->code)
					goto unlock;
			}
		}
		break;

	case IPPROTO_ICMPV6:
		{
			const struct icmp6hdr *icmpv6h;
			struct udphdr _icmpv6h;
			icmpv6h = skb_header_pointer( pkt_info->skb, pkt_info->thoff, sizeof(_icmpv6h), &_icmpv6h );
			if ( !icmpv6h )
				goto unlock;
			
			if ( info->option.icmp.flags & SERVICE_ICMP_TYPE_VALID ) {
				if ( info->option.icmp.type != icmpv6h->icmp6_type )
					goto unlock;
			}
			if ( info->option.icmp.flags & SERVICE_ICMP_CODE_VALID ) {
				if ( info->option.icmp.code[0] > icmpv6h->icmp6_code ||
					info->option.icmp.code[1] < icmpv6h->icmp6_code)
					goto unlock;
			}
		}
		break;
		
	default:
		break;
			
	}
	match = 1;
	
unlock:
	rcu_read_unlock();
	return match;
}


/* Seq file and sysctl for Debug configureation */

#ifdef CONFIG_PROC_FS
static void *
service_obj_seq_start( struct seq_file *seq, loff_t *pos )
{
	loff_t n = *pos;

	if ( !n )
		seq_puts( seq, "Servobj list:\n Name tcp | udp srcport  dstport refcnt \n"
			    "Name icmp proto code type refcnt\n"
			    "Name other proto\n\n" );

	mutex_lock( &class_lock );
	return seq_list_start( &servobj_list, *pos );
}

static void *
service_obj_seq_next( struct seq_file *seq, void *v, loff_t *pos )
{
	return seq_list_next( v, &servobj_list, pos );
}

static void 
service_obj_seq_stop( struct seq_file *seq, void *v )
{
	mutex_unlock( &class_lock );
	return;
}

static int 
service_obj_seq_show( struct seq_file *seq, void *v )
{
	const servobj_item_t *p = list_entry( v, servobj_item_t, list );
	char sbuf[12] = {0}, dbuf[12] = {0};
	
	switch ( p->info->proto ) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		sprintf( sbuf, "%u-%u", p->info->option.port.srcstart, p->info->option.port.srcend );
		sprintf( dbuf, "%u-%u", p->info->option.port.dststart, p->info->option.port.dstend );
		seq_printf( seq, "%-16s%-8u%-16s%-16s%8d\n",p->name, p->info->proto, sbuf, dbuf,
			atomic_read(&p->refcnt) );
		break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		sprintf( sbuf, "%u", p->info->option.icmp.type );
		sprintf( dbuf, "%u-%u", p->info->option.icmp.code[0], p->info->option.icmp.code[1] );
		seq_printf( seq, "%-16s%-8u%-16s%-16s%8d\n",p->name, p->info->proto, sbuf,
			dbuf, atomic_read(&p->refcnt) );
		break;

	default:
		seq_printf( seq, "%-16s%-8u%d\n", p->name, p->info->proto, atomic_read(&p->refcnt) );
		break;
	}

	return 0;
}

static const struct seq_operations service_obj_seq_ops = {
	.start          = service_obj_seq_start,
	.next           = service_obj_seq_next,
	.stop           = service_obj_seq_stop,
	.show         	= service_obj_seq_show,
};

static int 
service_obj_seq_open( struct inode *inode, struct file *file )
{
	return seq_open( file, &service_obj_seq_ops );
}

const struct file_operations service_obj_list_fops = {
	.owner          = THIS_MODULE,
	.open		= service_obj_seq_open,
	.read         	= seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

struct proc_dir_entry *proc_servobj;
static int __net_init 
service_net_init( struct net *net )
{
	proc_servobj = proc_mkdir( "servobj", proc_netobj );
	if ( !proc_servobj )
		return -ENOMEM;

	if ( !proc_create_data( "service", S_IRUGO, proc_servobj, &service_obj_list_fops, NULL ) )
		goto remove_servobj;

	proc_symlink( "max_size", proc_servobj, PROC_SERVOBJ"/max_size" );
	proc_symlink( "cur_size", proc_servobj, PROC_SERVOBJ"/cur_size"  );

	return 0;
	
remove_servobj:
	remove_proc_entry( "servobj", proc_netobj );
	return -ENOMEM;
}

static void __net_exit 
service_net_exit( struct net *net )
{
	remove_proc_entry( "max_size", proc_servobj );
	remove_proc_entry( "cur_size", proc_servobj );
	remove_proc_entry( "service", proc_servobj );
	remove_proc_entry( "servobj",proc_netobj  );
	return ;
}

static struct pernet_operations service_net_ops = {
	.init = service_net_init,
	.exit = service_net_exit,
};

int
service_obj_readproc_init( void )
{
	return register_pernet_subsys( &service_net_ops );
}

void
service_obj_readproc_exit( void )
{
	unregister_pernet_subsys( &service_net_ops );
}

#else	/* CONFIG_PROC_FS */

int
service_obj_readproc_init( void )
{
	return 0;
}

void
service_obj_readproc_exit( void )
{
	return ;
}

#endif	/* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
struct ctl_table_header *service_obj_sysctl_header = NULL;

static ctl_table service_obj_sysctl_table[] = {
	{
		.procname		= "max_size",
		.data			= &servobj_class.cfg.max_size,
		.maxlen			= sizeof( servobj_class.cfg.max_size ),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
		
	},
	{
		.procname		= "cur_size",
		.data			= &servobj_class.cfg.cur_size,
		.maxlen			= sizeof( servobj_class.cfg.cur_size ),
		.mode			= 0444,
		.proc_handler		= &proc_dointvec,
		
	},
	{ }
};

static ctl_table service_obj_chiledir_table[] = {
	{
		.procname	= "servobj",
		.mode		= 0555,
		.child		= service_obj_sysctl_table,
	},
	{ }
};

static ctl_table service_obj_netobj_table[] = {
	{
		.procname	= "netobj",
		.mode		= 0555,
		.child		= service_obj_chiledir_table,
	},
	{ }
};

static ctl_table service_obj_root_table[] = {
	{
		.procname	= "leadsec",
		.mode		= 0555,
		.child		= service_obj_netobj_table,
	},
	{ }
};

static int service_obj_sysctl_init( void )
{
	service_obj_sysctl_header = register_sysctl_table( service_obj_root_table );
	if ( NULL == service_obj_sysctl_header )
		return -ENOMEM;

	return 0;
}

static void service_obj_sysctl_fint( void )
{
	unregister_sysctl_table( service_obj_sysctl_header );
	return ;
}

#else	/* CONFIG_SYSCTL */

static int service_obj_sysctl_init( void )
{
	return 0;
}

static void service_obj_sysctl_fint( void )
{
	return ;
}

#endif	/* CONFIG_SYSCTL */

int service_obj_proc_init( void )
{
	int ret = 0;

	ret = service_obj_sysctl_init();
	if ( 0 != ret )
		return ret;

	ret = service_obj_readproc_init();
	if ( 0 != ret )
		goto unreg_sysctl;

	return ret;
unreg_sysctl:
	service_obj_sysctl_fint();
	return ret;
}

void service_obj_proc_fint( void )
{
	service_obj_readproc_exit();
	service_obj_sysctl_fint();
	return ;
}

EXPORT_SYMBOL( servobj_construct_item );
EXPORT_SYMBOL( servobj_destruct_item );
EXPORT_SYMBOL( servobj_modify_item );
EXPORT_SYMBOL( servobj_flush_item );
EXPORT_SYMBOL( servobj_exist_item );
EXPORT_SYMBOL( servobj_show_item );

EXPORT_SYMBOL( service_find_obj );
EXPORT_SYMBOL( service_release_obj );
EXPORT_SYMBOL( service_match_func );
EXPORT_SYMBOL( service_obj_proc_init );
EXPORT_SYMBOL( service_obj_proc_fint );
