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

#include "class_core.h"
#include "servobj.h"
#include "servgrp.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "service group object kernel module" );

static LIST_HEAD( servgrp_list );
static class_item_t *servobj_classitem = NULL;

static int 
service_grp_check_limit( u32 size )
{
	int ret = 0;
	
	if ( servgrp_class.cfg.max_size &&
	    unlikely(atomic_read(&servgrp_class.cfg.cur_size) > servgrp_class.cfg.max_size) ) {
		duprintf( "servgrp tables size full current size(%d) greater than maxsize(%d)",
		atomic_read(&servgrp_class.cfg.cur_size), servgrp_class.cfg.max_size );
		ret = -ENOMEM;
		goto out;
	}

	if ( servgrp_class.cfg.max_number &&
	    unlikely(size > servgrp_class.cfg.max_number) ) {
		duprintf( "servobj number(%d) greater than maxnum(%d)",size, servgrp_class.cfg.max_number );
		ret = -ENOMEM;
		goto out;
	}

out:
	return ret;
}

/* Socketopt API */
static servgrp_item_t *
__service_grp_construct_item( const char *name, servgrp_cell_t *cells, u32 num_cell )
{
	int ret = 0;
	u32 i = 0, j = 0;
	size_t len = 0;
	servgrp_item_t *new_grp = NULL;
	servgrp_unit_t *new_cells = NULL;

	/* Check size of service groups whether or not over limit */
	atomic_inc( &servgrp_class.cfg.cur_size );
	if ( 0 != service_grp_check_limit(num_cell) ) {
		atomic_dec( &servgrp_class.cfg.cur_size );
		ret = -ENOMEM;
		return NULL;
	}

	if ( num_cell != 0 ) {
		len = sizeof(servgrp_unit_t) + sizeof(servgrp_elem_t) * num_cell;
		new_cells = netobj_kzalloc( len, GFP_ATOMIC );
		if ( new_cells == NULL ) {
			duprintf( "When construct servgrp alloc servgrp_unit_t struct failed.\n" );
			return NULL;
		}
		new_cells->size = len;
		new_cells->num_cell = num_cell;
	}
	
	for ( i = 0; i < num_cell; i++ ) {
		strncpy( new_cells->elem[i].name, cells[i].serv_name, MAX_OBJ_NAME_LEN );
		/* find and bind service object(s) */
		new_cells->elem[i].obj_addr = servobj_classitem->find_object( cells[i].serv_name, 0 );
		if ( new_cells->elem[i].obj_addr == 0 ) {
			duprintf( "Lookup servobj_item ponint addr failed.\n" );
			ret = -ENOENT;
			goto free_cells;
		}
	}
	
	len = sizeof(servgrp_item_t);
	new_grp = netobj_kzalloc( len, GFP_ATOMIC );
	if ( new_grp == NULL ) {
		ret = -ENOMEM;
		goto free_cells;
	}
	new_grp->size = len;

	strncpy( new_grp->name, name, MAX_OBJ_NAME_LEN );
	INIT_LIST_HEAD( &new_grp->list );
	atomic_set( &new_grp->refcnt, 0 );
	new_grp->cells = new_cells;

free_cells:
	if ( ret != 0 ) {
		for ( j = 0; j < i; j++ ) {
			servobj_classitem->release_object( new_cells->elem[j].obj_addr );
			new_cells->elem[j].obj_addr = 0;
		}
	}

	if ( ret != 0 ) {
		if ( num_cell != 0 ) {
			netobj_kfree( new_cells, new_cells->size );
			new_cells = NULL;
		}
	}

	return new_grp;
}

int
service_grp_construct_item( const char *name, servgrp_cell_t *cells, u32 num_cell )
{
	int ret = 0;
	servgrp_item_t *cur = NULL;

	list_for_each_entry( cur, &servgrp_list, list ) {
		if ( strncmp(cur->name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			duprintf( "This servgrp name is realdy exist!\n" );
			ret = -EEXIST;
			break;
		}
	}

	if ( ret == 0 ) {
		servgrp_item_t *new_item = __service_grp_construct_item( name, cells, num_cell );
		if ( new_item == NULL ) {
			duprintf( "Cnstruct servgrp item failed.\n" );
			ret = -ENOMEM;
		} else 
			list_add( &new_item->list, &servgrp_list );
	}

	return ret;
}

static int
__service_grp_destruct_item( servgrp_item_t **group )
{
	int i = 0;
	servgrp_unit_t *cells = (*group)->cells;
	if ( atomic_read( &(*group)->refcnt ) != 0 ) {
		duprintf( "destruct_item: Can not Delete servgrp item because item refcnt not-zero!\n" );
		return -EBUSY;
	}

	if (!cells) 
		goto free_group;

	for ( i = 0; i < cells->num_cell; i++ ) {
		servobj_classitem->release_object( cells->elem[i].obj_addr );
		cells->elem[i].obj_addr = 0;
	}

	netobj_kfree( cells, cells->size );
	cells = NULL;

free_group:
	atomic_dec( &servgrp_class.cfg.cur_size );
	netobj_kfree( *group, (*group)->size );
	*group = NULL;

	return 0;
}

int
service_grp_destruct_item( const char *name )
{
	int ret = -ENOENT;
	servgrp_item_t *group = NULL, *next = NULL;

	list_for_each_entry_safe( group, next, &servgrp_list, list ) {
		if ( strncmp(group->name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			if ( 0 != (atomic_read(&group->refcnt)) )
				break;
			list_del( &group->list );
			ret = __service_grp_destruct_item( &group );
			if ( ret != 0 ) {
				list_add( &group->list, &servgrp_list );
				duprintf( "Destruct_grp: Delete servgrp_item failed!\n" );
				}
			break;
		}
	}

	return ret;
}

static inline int
__service_grp_modify_item( servgrp_item_t *grp, servgrp_cell_t *cells, u32 num_cell )
{
	int ret = 0;
	servgrp_unit_t *old_cell = NULL, *new_cell = NULL;
	int i = 0, j = 0, m = 0;
	size_t len = 0;
	u32 old_num_cell = 0;

	if ( 0 != service_grp_check_limit(num_cell) ) {
		ret = -ENOMEM;
		return ret;
	}

	if ( num_cell != 0 ) {
		len = sizeof(servgrp_unit_t) + sizeof(servgrp_elem_t)* num_cell;
		new_cell = netobj_kzalloc( len, GFP_ATOMIC );
		if ( new_cell == NULL ) {
			duprintf( "_modify_grp_item: Alloc memory for servgrp_unit_t failed!\n" );
			return -ENOMEM;
		}
		new_cell->size = len;
		new_cell->num_cell = num_cell;
	}

	for ( i = 0; i < num_cell; i++ ) {
		strncpy( new_cell->elem[i].name, cells[i].serv_name, MAX_OBJ_NAME_LEN );
		/* find and bind service object(s) */
		new_cell->elem[i].obj_addr = servobj_classitem->find_object( new_cell->elem[i].name, 0 );

		if ( new_cell->elem[i].obj_addr == 0 ) {
			duprintf( "_modify_grp_item: Find the servobj addr failed!\n" );
			ret = -ENOENT;
			goto free_cell;
		}
	}

	old_cell = grp->cells;
	old_cell ? (old_num_cell = old_cell->num_cell) : (old_num_cell = 0);
	rcu_assign_pointer( grp->cells, new_cell );

	/* Destruct old servgrp_unit_t  */
	for ( m = 0; m < old_num_cell; m++ ) {
		servobj_classitem->release_object( old_cell->elem[m].obj_addr );
		old_cell->elem[i].obj_addr = 0;
	}

	if ( old_cell != NULL ) {
		synchronize_rcu();
		netobj_kfree( old_cell, old_cell->size );
		old_cell = NULL;
	}

free_cell:
	if ( ret != 0 )	{
		for ( j = 0; j < i; j++ ) {
			servobj_classitem->release_object( new_cell->elem[j].obj_addr );
			new_cell->elem[j].obj_addr = 0;
		}
	}
	
	if ( ret != 0 ) {
		if ( num_cell != 0 ) {
			netobj_kfree( new_cell, new_cell->size );
			new_cell = NULL;
		}
	}

	return ret;
}

int 
service_grp_modify_item( const char *grp_name, servgrp_cell_t *cells, u32 num_cell )
{
	int ret = -ENOENT;
	servgrp_item_t *cur = NULL;

	list_for_each_entry( cur, &servgrp_list, list ) {
		if ( strncmp(cur->name, grp_name, MAX_OBJ_NAME_LEN) == 0 ) {
			ret = __service_grp_modify_item( cur, cells, num_cell );
			if ( ret != 0 ) {
				duprintf( "Service_grp_modify_item: Modify grp_item failed!\n" );
			}

			break;
		}
	}
	
	return ret;
}

int
service_grp_flush_item( void ) 
{
	int ret = 0;
	servgrp_item_t *group = NULL;
	servgrp_item_t *next = NULL;

	list_for_each_entry_safe( group, next, &servgrp_list, list ) {
		if ( 0 != (atomic_read(&group->refcnt)) )
			break;
		ret = __service_grp_destruct_item( &group );
		if ( ret != 0 ) {
			duprintf( "servgrp_flush_item: Flush all servgrp_item failed!\n" );
			break;
		}
	}

	return ret;
}

int
service_grp_exist_item( const char *grp_name )
{
	int exist = 0;
	servgrp_item_t *group = NULL;

	list_for_each_entry( group, &servgrp_list, list ) {
		if ( strncmp(group->name, grp_name, MAX_OBJ_NAME_LEN) == 0 ) {
			exist = 1;
			break;
		}
	}

	return exist;
}

int
service_grp_count_item( const char *grp_name, int *count )
{
	int ret = -ENOENT;
	servgrp_item_t *group = NULL;

	list_for_each_entry( group, &servgrp_list, list ) {
		if ( strncmp(group->name, grp_name, MAX_OBJ_NAME_LEN ) == 0 ) {
			if ( !group->cells ) {
				*count = 0;
				ret = 0;
				break;
			}
			ret = 0;
			*count = group->cells->num_cell;
			break;
		}
	}

	return ret;
}

static int
__service_grp_show_item( servgrp_item_t *grp, servgrp_cell_t **unit, u32 *num_cell )
{
	int ret = 0;
	u32 i = 0;
	size_t len = 0;
	const servgrp_unit_t *cells = NULL;	
	
	ASSERT( NULL != grp );
	ASSERT( NULL != unit && NULL == (*unit) );
	ASSERT( NULL != num_cell );

	cells = rcu_dereference( grp->cells );
	if ( !cells ) {
		*num_cell = 0;
		goto unlock;
	}

	if ( cells->num_cell != 0 ) {
		len = sizeof(servgrp_cell_t) * cells->num_cell;
		(*unit) = netobj_kzalloc( len, GFP_ATOMIC );
		if ( *unit == NULL ) {
			ret = -ENOMEM;
			duprintf( "__service_grp_show_item: Alloc memory for servgrp_cell_t failed!\n" );
			goto unlock;
		}
		(*unit)->size = len;
	}

	for ( i = 0; i < cells->num_cell; i++ ) { 
		strncpy( (*unit)[i].serv_name, cells->elem[i].name, MAX_OBJ_NAME_LEN );
	}

	*num_cell = cells->num_cell;

unlock:
	return ret;
}

int 
service_grp_show_item( const char *grp_name, servgrp_cell_t **cells, u32 *num_cell )
{
	int ret = -ENOENT;
	servgrp_item_t *cur = NULL;


	list_for_each_entry( cur, &servgrp_list, list ) {
		if ( strncmp(grp_name, cur->name, MAX_OBJ_NAME_LEN) == 0 ) {
			ret = __service_grp_show_item( cur, cells, num_cell );
			if ( ret != 0 ) 
				duprintf( "Servgrp_show_item: Show servgrp_item failed!\n" );

			goto unlock;
		}
	}

unlock:
	return ret;
}

/* servgrp_item operation functions */
servgrp_item_t * 
service_grp_find_obj( const char *name )
{
	servgrp_item_t *servgrp = NULL;
	servgrp_item_t *result = NULL;

	list_for_each_entry( servgrp, &servgrp_list, list ) {
		if ( strncmp(name, servgrp->name, MAX_OBJ_NAME_LEN) == 0 ) {
			atomic_inc( &servgrp->refcnt );
			result = servgrp;
			break;
		}
	}

	return result;
}

void
service_grp_release_obj( servgrp_item_t *group )
{
	ASSERT( group == NULL );
	if ( group ) atomic_dec( &group->refcnt );
	return ;
}

int
service_grp_match_func( servgrp_item_t *group, const pkt_info_t *pkt_info )
{
	int i = 0;
	int len = 0;
	int match = 0;
	const servgrp_unit_t *cells = NULL;

	ASSERT( group == NULL );

	rcu_read_lock();
	cells = rcu_dereference( group->cells );
	if ( !cells )
		return match;

	for ( i = 0; i < cells->num_cell; i++ ) {
		match = servobj_classitem->do_stuff( cells->elem[i].obj_addr, MATCH_PKT_SERVICE, (void*)pkt_info, &len );
		if ( match < 0 ) {
			match = 0;
			break;
		}

		if ( match != 0 )
			break;
	}
	rcu_read_unlock();

	return match;
}

/* Initializa function */
int
servict_grp_init_class( class_item_t *servgrp_item )
{
	servobj_classitem = find_class_item( "servobj" );

	if ( servobj_classitem == NULL ) {
		duprintf( "INit find servobj_classitem failed!\n" );
		return -1;
	}

	try_module_get( servobj_classitem->owner );
	bind_class_item( servobj_classitem );

	return 0;
}

/* Finish function */
void
service_grp_fint_class( void )
{
	int ret = 0;
	ret = service_grp_flush_item();
	if ( ret != 0 ) 
		duprintf( "Can not flush all servgrp item!\n" );

	module_put( servobj_classitem->owner );
	release_class_item( servobj_classitem );

	return;
}

#ifdef CONFIG_PROC_FS
static void *
service_grp_seq_start( struct seq_file *seq, loff_t *pos )
{
        loff_t n = *pos;

        if ( !n )
                seq_puts( seq, "Service group list:\n" );

        mutex_lock( &class_lock );
        return seq_list_start( &servgrp_list, *pos );
};

static void *
service_grp_seq_next( struct seq_file *seq, void *v, loff_t *pos )
{
        return seq_list_next( v, &servgrp_list, pos );
}

static void 
service_grp_seq_stop( struct seq_file *seq, void *v )
{
        mutex_unlock( &class_lock );
}

static int 
service_grp_seq_show( struct seq_file *seq, void *v )
{
	int i = 0;
	const servgrp_unit_t *cells = NULL;
	const servgrp_item_t *p = list_entry( v, servgrp_item_t, list );

	cells = rcu_dereference( p->cells );
	
	/* if cells is NULL then num_cell(s) is zero */
	seq_printf( seq, "Name:%-12sNum_cell(s):"
			 "%-12uRefcnt(s):%-5d\n",
			 p->name, 
			 cells ? cells->num_cell : 0, 
			 atomic_read(&p->refcnt) );

	if ( !cells )
		return 0;

	for ( i = 0; i < cells->num_cell; i++ )
		seq_printf( seq, "%s\t0x%lx\n",
			cells->elem[i].name, 
			cells->elem[i].obj_addr );

	seq_printf( seq, "\n" );

	return 0;
}

static const struct seq_operations service_grp_seq_ops = {
        .start          = service_grp_seq_start,
        .next           = service_grp_seq_next,
        .stop           = service_grp_seq_stop,
        .show           = service_grp_seq_show,
};

static int
service_grp_seq_open( struct inode *inode, struct file *file )
{
        return seq_open( file, &service_grp_seq_ops );
}


const struct file_operations service_grp_list_fops = {
        .owner          = THIS_MODULE,
        .open           = service_grp_seq_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = seq_release,
};

struct proc_dir_entry *proc_servgrp = NULL;
static int __net_init 
service_grp_net_init( struct net *net )
{
	proc_servgrp = proc_mkdir( "servgrp", proc_netobj );
	if ( !proc_servgrp )
		return -ENOMEM;

	if ( !proc_create_data( "servgrp_info", S_IRUGO, proc_servgrp, &service_grp_list_fops, NULL ) )
		goto remove_servgrp_proc;

	proc_symlink( "max_size", proc_servgrp, PROC_SERVGRP"/max_size" );
	proc_symlink( "cur_size", proc_servgrp, PROC_SERVGRP"/cur_size"  );
	proc_symlink( "max_number", proc_servgrp, PROC_SERVGRP"/max_number"  );

	return 0;
	
remove_servgrp_proc:
	remove_proc_entry( "servgrp", proc_netobj );
	return -ENOMEM;
}

static void __net_exit
service_grp_net_exit( struct net *net )
{
	remove_proc_entry( "max_size", proc_servgrp );
	remove_proc_entry( "cur_size", proc_servgrp );
	remove_proc_entry( "max_number", proc_servgrp );
	remove_proc_entry( "servgrp_info", proc_servgrp );

	remove_proc_entry( "servgrp", proc_netobj );
	return ;
}

static struct pernet_operations service_grp_net_ops = {
        .init = service_grp_net_init,
        .exit = service_grp_net_exit,
};

int
service_grp_readproc_init( void )
{
        return register_pernet_subsys( &service_grp_net_ops );
}

void
service_grp_readproc_exit( void )
{
        unregister_pernet_subsys( &service_grp_net_ops );
}

#else   /* CONFIG_PROC_FS */

int
service_grp_readproc_init( void )
{
        return 0;
}

void
service_grp_readproc_exit( void )
{
        return ;
}

#endif  /* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
struct ctl_table_header *service_grp_sysctl_header = NULL;

static ctl_table service_grp_sysctl_table[] = {
	{
		.procname		= "max_size",
		.data			= &servgrp_class.cfg.max_size,
		.maxlen			= sizeof( servgrp_class.cfg.max_size ),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
		
	},
	{
		.procname		= "cur_size",
		.data			= &servgrp_class.cfg.cur_size,
		.maxlen			= sizeof( servgrp_class.cfg.cur_size ),
		.mode			= 0444,
		.proc_handler		= &proc_dointvec,
		
	},
	{
		.procname		= "max_number",
		.data			= &servgrp_class.cfg.max_number,
		.maxlen			= sizeof( servgrp_class.cfg.max_number ),
		.mode			= 0644,
		.proc_handler	= &proc_dointvec,
		
	},
	{
		.procname		= "cur_number",
		.data			= &servgrp_class.cfg.cur_number,
		.maxlen			= sizeof( servgrp_class.cfg.cur_number ),
		.mode			= 0444,
		.proc_handler		= &proc_dointvec,
		
	},
	{ }
};

static ctl_table service_grp_chiledir_table[] = {
	{
		.procname	= "servgrp",
		.mode		= 0555,
		.child		= service_grp_sysctl_table,
	},
	{ }
};

static ctl_table service_grp_netobj_table[] = {
	{
		.procname	= "netobj",
		.mode		= 0555,
		.child		= service_grp_chiledir_table,
	},
	{ }
};

static ctl_table service_grp_root_table[] = {
	{
		.procname	= "leadsec",
		.mode		= 0555,
		.child		= service_grp_netobj_table,
	},
	{ }
};

static int service_grp_sysctl_init( void )
{
	service_grp_sysctl_header = register_sysctl_table( service_grp_root_table );
	if ( NULL == service_grp_sysctl_header )
		return -ENOMEM;

	return 0;
}

static void service_grp_sysctl_fint( void )
{
	unregister_sysctl_table( service_grp_sysctl_header );
	return ;
}

#else	/* CONFIG_SYSCTL */

static int service_grp_sysctl_init( void )
{
	return 0;
}

static void service_grp_sysctl_fint( void )
{
	return ;
}

#endif	/* CONFIG_SYSCTL */

int service_grp_proc_init( void )
{
	int ret = 0;

	ret = service_grp_sysctl_init();
	if ( 0 != ret )
		return -ENOMEM;

	ret = service_grp_readproc_init();
	if ( 0 != ret )
		goto unreg_sysctl;

	return ret;
unreg_sysctl:
	service_grp_sysctl_fint();
	return ret;
}

void service_grp_proc_exit( void )
{
	service_grp_sysctl_fint();
	service_grp_readproc_exit();
	return ;
}

EXPORT_SYMBOL_GPL( service_grp_find_obj );
EXPORT_SYMBOL_GPL( service_grp_release_obj );
EXPORT_SYMBOL_GPL( service_grp_match_func );

EXPORT_SYMBOL_GPL( servict_grp_init_class );
EXPORT_SYMBOL_GPL( service_grp_fint_class );

EXPORT_SYMBOL_GPL( service_grp_construct_item );
EXPORT_SYMBOL_GPL( service_grp_destruct_item );
EXPORT_SYMBOL_GPL( service_grp_modify_item );
EXPORT_SYMBOL_GPL( service_grp_flush_item );
EXPORT_SYMBOL_GPL( service_grp_exist_item );
EXPORT_SYMBOL_GPL( service_grp_count_item );
EXPORT_SYMBOL_GPL( service_grp_show_item );
EXPORT_SYMBOL_GPL( service_grp_proc_init );
EXPORT_SYMBOL_GPL( service_grp_proc_exit );

