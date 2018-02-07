/* Kernel module to addr_range parameters. */

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
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <net/ip.h>

#include "class_core.h"
#include "addr_group.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "addr group object kernel module" );

unsigned int addr_group_rlp_enable __read_mostly = 1;

static struct hlist_head *addr_group_head = NULL;
//static DEFINE_MUTEX( addr_group_lock );

#ifdef ADDR_GROUP_RLP
addr_group_rlp_t *g_gen_spec = NULL;
EXPORT_SYMBOL_GPL(g_gen_spec);
#endif

#define ADDR_GROUP_HASH_SHIFT       12
#define ADDR_GROUP_HASH_SIZE        ( 1 << ADDR_GROUP_HASH_SHIFT )
#define ADDR_GROUP_HASH_MASK        ( ADDR_GROUP_HASH_SIZE - 1 )

static addr_group_cell_t *
addr_group_get_cell_rcu( const addr_group_item_t *group )
{
	return rcu_dereference( group->cells );
}

static inline u32
addr_group_name_hash( const char *str )
{
        u_int32_t hash = 0 ;
        u_int32_t x = 0 ;

        while ( *str ) {
                hash = ( hash << 4 ) + ( *str ++ );
                if  ( (x = hash & 0xF0000000L ) != 0 ) {
                        hash ^= ( x >> 24 );
                        hash &=  ~ x;
                }
        }
        return ( hash & ADDR_GROUP_HASH_MASK );
}

/* Initiation hash head for save addr_group_item */
s32
addr_group_hash_init( void )
{
	u32 i = 0;
	addr_group_head = kzalloc( ADDR_GROUP_HASH_SIZE * sizeof(struct hlist_head), GFP_KERNEL );
	if ( NULL == addr_group_head ) {
		duprintf( KERN_ERR, "Kzalloc memory for stat info failed!\n" );
		return -ENOMEM;
	}

        for ( i =0; i < ADDR_GROUP_HASH_SIZE; i++ ) {
                INIT_HLIST_HEAD( &addr_group_head[i] );
        }
#ifdef ADDR_GROUP_RLP
	g_gen_spec = kzalloc( sizeof(addr_group_rlp_t), GFP_KERNEL );
#endif
	return 0;
}

void 
addr_group_hash_fint( void )
{
	kfree( addr_group_head );
#ifdef ADDR_GROUP_RLP
	kfree( g_gen_spec );
#endif
	return ;
}

/* Class item operation */
addr_group_item_t *
find_addr_group_obj( const char *group_name, u8 flags )
{
	addr_group_item_t *group = NULL;
	struct hlist_node *pos = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry(group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			atomic_inc( &group->refcnt );
			return group;
		}
	}

	return NULL;
}

void
bind_addr_group_obj( addr_group_item_t *group )
{
	return ;	
}

void 
release_addr_group_obj( addr_group_item_t *group )
{
	ASSERT( group != NULL && atomic(&group->refcnt) != 0 );
	if ( group ) atomic_dec( &group->refcnt );
	return ;
}

/* Add addr group object */
static struct addr_group_item* 
construct_addr_group_item( const char * group_name, 
			   const addr_group_unit_t * cells, 
			   u32 num_cell )
{
	u32 i = 0;
	s32 ret = -1;
	addr_group_item_t *new_group = NULL;
	addr_group_cell_t *new_cells = NULL;	
	size_t size = 0;

	/* 1. Alloc struct addr_group_list new_cells  and addr_group_line_t if num_cell is not 0 */
	if ( 0 != num_cell ) {
		size = sizeof(addr_group_cell_t) + (sizeof(addr_group_line_t) * num_cell);
		new_cells = (addr_group_cell_t *)netobj_kzalloc( size, GFP_ATOMIC );
		if ( NULL == new_cells ) {
			duprintf( KERN_ERR, "insufficient memory!!\n" );
			return NULL;
		}
		new_cells->size = size;
		new_cells->num_cell = num_cell;
	}

	/* 2. Alloc(Initiation) addr_group_rlp_t tree struct for cells if new_cells is not NULL; */
#ifdef ADDR_GROUP_RLP
	if ( NULL != new_cells ) {
		ret = addr_group_rlp_init( (struct rlp_spec **)&new_cells->rlp, 1 );
		if ( 0 != ret ) {
			duprintf( KERN_ERR, "Initiation addr group rlp tree failed!\n" );
			goto free_group_cell;
		}
	}
#endif
	/* 3. Insert iprange for addr_group_line_t and addr_group_rlp_t */
	for ( i = 0; i < num_cell; i++ ) {
		new_cells->line[i].left = cells[i].left;
		new_cells->line[i].right = cells[i].right;
#ifdef ADDR_GROUP_RLP
		/* Rlp tree insert */
		ret = addr_group_rlp_insert( (struct rlp_spec **)&new_cells->rlp, cells[i].left.ip, cells[i].right.ip, 0 );
		if ( 0 != ret ) {
			duprintf( KERN_ERR, "Insert value to rlp tree failed!\n" );
			goto free_group_rlp;
		}
#endif
	}

	/* 4. Alloc addr_group_item_t */
	size = sizeof(addr_group_item_t);
	new_group = netobj_kzalloc( size, GFP_ATOMIC );
	if ( NULL == new_group ) {
		duprintf( KERN_ERR, "Alloc addr_group_item_t insufficient memory!!\n" );
		goto free_group_rlp;
	}
	new_group->size = size;

	/* 4. Initialize&&populate addr_group_item_t */
	strncpy( new_group->group_name, group_name, MAX_OBJ_NAME_LEN );
	atomic_set( &new_group->refcnt, 0 );
	new_group->cells = new_cells;

	/* Alloc stats struct for percpu */
	new_group->stats = alloc_percpu( struct addr_group_stat );
	if ( !new_group->stats ) {
		ret = -ENOMEM;
		goto free_group;
	}

	return new_group;

free_group:
	if ( new_group )
		netobj_kfree( new_group, new_group->size );

free_group_rlp:
	if ( new_cells && new_cells->rlp )
		netobj_kfree( new_cells->rlp, 
		    ((struct rlp_spec*)(new_cells->rlp))->size );
	
free_group_cell:
	if ( 0 != num_cell &&  NULL != new_cells )
		netobj_kfree( new_cells, new_cells->size );

	return new_group;
}

s32 
construct_addr_group_obj( const char* group_name, 
			  const addr_group_unit_t* cells, 
			  u32 num_cell )
{
	s32 ret = 0;
	addr_group_item_t *group = NULL;
	struct hlist_node *pos = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry(group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			duprintf( KERN_ERR, "addr group name [%s] exist!\n", group_name );
			ret = -EEXIST;
			break;
		}		
	}

	if ( 0 == ret ) {
		addr_group_item_t *new_group = NULL;
		new_group = construct_addr_group_item( group_name, cells, num_cell );
		if ( NULL == new_group ) {
			duprintf( KERN_ERR, "Can not construct addr_group_item no memory!\n" );
			ret = -ENOMEM;
		} else {
			hlist_add_head( &new_group->hnode, &addr_group_head[hash] );
		}
	}
	
	return ret;
}

/* Delete addr group object */
static s32
destruct_addr_group_item( addr_group_item_t **group )
{
	if ( atomic_read(&(*group)->refcnt) != 0 ) {
		duprintf( KERN_ERR,"can not destruct the addr_group item, referenct count is no-zero!\n" );
		return -EBUSY;
	}

	/* free stat struct for percpu */
	if ( *group )
		free_percpu( (*group)->stats );

#ifdef ADDR_GROUP_RLP
	if ( (NULL!= (*group)->cells) && NULL != (*group)->cells->rlp ) {
		netobj_kfree( (*group)->cells->rlp , ((struct rlp_spec *)((*group)->cells->rlp))->size );
		(*group)->cells->rlp = NULL;
	}
#endif
	/* if have cells free it */
	if ( NULL != (*group)->cells ){
		netobj_kfree( (*group)->cells , (*group)->cells->size );
		(*group)->cells = NULL;
	}
	
	/* free group_item */
	netobj_kfree( *group, (*group)->size );
	*group=NULL;

	return 0;
}

s32
destruct_addr_group_obj( const char *group_name )
{
	s32 ret = -ENOENT;
	addr_group_item_t *group = NULL;
	struct hlist_node *pos = NULL, *next = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry_safe( group, pos, next, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			if ( 0 != (atomic_read(&group->refcnt)) )
				break;
			hlist_del( &group->hnode );
			ret = destruct_addr_group_item( &group );
			if ( 0 != ret ) {
				duprintf( KERN_ERR, "Can not destruct the addr_group_item!\n" );
				hlist_add_head( &group->hnode, &addr_group_head[hash] );
			}
			break;
		}
	}

	return ret;
}

static void
addr_group_free_cells_rcu( struct rcu_head *head )
{
	addr_group_cell_t *cells = container_of( head, addr_group_cell_t, rcu);

#ifdef ADDR_GROUP_RLP
	if ( cells->rlp ) {
		netobj_kfree( cells->rlp, ((struct rlp_spec *)cells->rlp)->size );
		cells->rlp = NULL;
	}
#endif
	if ( cells ) {
		netobj_kfree( cells, cells->size );
		cells = NULL;
	}
}

static s32
modify_addr_group_item( addr_group_item_t *group,  const addr_group_unit_t *unit, u32 num_cell )
{
	s32 ret=0;
	addr_group_cell_t* new_cells=NULL;
	u32 i = 0;        
	addr_group_cell_t* old_cells=NULL;
	u32 old_num_cells=0;
	size_t size = 0;

	/* 1. allocate new cells memory when num is not 0 */
	if ( 0 != num_cell ) {
		size = sizeof(addr_group_cell_t) + (sizeof(addr_group_line_t) * num_cell);
		new_cells = (addr_group_cell_t *)netobj_kzalloc( size, GFP_ATOMIC );
		if ( NULL == new_cells ) {
			duprintf( KERN_ERR, "Modify group_item insufficient memory!\n" );
			return -ENOMEM;
		}
		new_cells->size = size;
		new_cells->num_cell = num_cell;
	}

	/* 2.  Alloc(Initiation) addr_group_rlp_t tree struct for cells if new_cells is not NULL; */ 
#ifdef ADDR_GROUP_RLP
	if ( NULL != new_cells ) {
		ret = addr_group_rlp_init( (struct rlp_spec **)&new_cells->rlp, 1 );
		if ( 0 != ret ) {
			duprintf( KERN_ERR, "Initiation addr group rlp tree failed!\n" );
			goto free_group_cell;
		}
	}
#endif

	/* 3. Insert iprange for addr_group_line_t and addr_group_rlp_t */
	for ( i = 0; i < num_cell; i++ ) {
		new_cells->line[i].left = unit[i].left;
		new_cells->line[i].right = unit[i].right;

#ifdef ADDR_GROUP_RLP
		/* Rlp tree insert */
		ret = addr_group_rlp_insert( (struct rlp_spec **)&new_cells->rlp, unit[i].left.ip, unit[i].right.ip, 0 );
		if ( 0 != ret ) {
			duprintf( KERN_ERR, "Insert value to rlp tree failed!\n" );
			goto free_group_rlp;
		}
#endif
	}

	/* 4. Replace group->cells and cells->num_cell */
	old_cells = addr_group_get_cell_rcu( group );
	old_cells ? (old_num_cells = old_cells->num_cell) : (old_num_cells = 0);

	rcu_assign_pointer( group->cells, new_cells );

	/* 5. free old_cells */
	if ( 0 != old_num_cells ) {
		ASSERT( NULL != old_cells );
		call_rcu( &old_cells->rcu, addr_group_free_cells_rcu );
	}

	return ret;

free_group_rlp:
	if ( new_cells && new_cells->rlp )
		netobj_kfree( new_cells->rlp, 
		    ((struct rlp_spec*)new_cells->rlp)->size );	
free_group_cell:
	if ( new_cells )
		netobj_kfree( new_cells, new_cells->size );

	return ret;
}

/* Modify addr group object */
s32
modify_addr_group_obj( const char* group_name, const addr_group_unit_t* cells, u32 num_cell )
{
	s32 ret = 0;
	addr_group_item_t *group = NULL;
	struct hlist_node *pos = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry( group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			ret = modify_addr_group_item( group, cells, num_cell );
			if ( 0 != ret )
				duprintf( KERN_ERR, "Can not modify the addr_group_item!!" );

			break;
		}
	}
	
	return ret;
}

/* Flush addr group object */
s32
flush_addr_group_obj( void )
{
	s32 ret = 0;
	u32 i = 0;
	struct hlist_node *pos = NULL, *next = NULL;
	addr_group_item_t *group = NULL;

	for ( i = 0; i < ADDR_GROUP_HASH_SIZE; i++ ) {
		hlist_for_each_entry_safe( group, pos, next, &addr_group_head[i], hnode ) {
			if ( 0 != atomic_read(&group->refcnt) )
				break;
			hlist_del( &group->hnode );
			ret = destruct_addr_group_item( &group );
			if ( 0 != ret ) {
				duprintf( KERN_ERR, "can not destruct some addr_group_item!\n" );
				hlist_add_head( &group->hnode, &addr_group_head[i] );
			}
		}
	}

	return ret;	
}

/* socketopt get operation */
s32 addr_group_obj_exist( const char* group_name )
{
	s32 exist = 0;
	struct hlist_node *pos = NULL;
	addr_group_item_t *group = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry( group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			exist = 1;
			break;
		}
	}
	return exist;
}

s32 addr_group_obj_get_count( const char *group_name, u32 *count )
{
	s32 ret = -ENOENT;
	struct hlist_node *pos = NULL;
	addr_group_item_t *group = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry( group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			addr_group_cell_t *cells = addr_group_get_cell_rcu( group );
			if ( !cells ) {
				*count = 0;
				ret = 0;
				break;
			}

			*count = cells->num_cell;
			ret = 0;
			break;
		}		
	}
	return ret;
}

static s32
addr_group_obj_show_item( addr_group_item_t *group, addr_group_unit_t **unit, u32 *num_cell )
{
	s32 ret = 0;
	u32 i = 0;
	size_t size = 0;
	addr_group_cell_t *cells = NULL;

	ASSERT( NULL != group );
	ASSERT( NULL != unit && NULL == (*unit) );
	ASSERT( NULL != num_cell );

	cells = addr_group_get_cell_rcu( group );
	if ( !cells ) {
		*num_cell = 0;
		goto out;
	}

	size = sizeof(addr_group_unit_t) * cells->num_cell;
	(*unit) = (addr_group_unit_t *)netobj_kzalloc( size, GFP_ATOMIC );
	if ( NULL == (*unit) ) {
		ret = -ENOMEM;
		duprintf( KERN_ERR,"addr group show item insufficient memory!!\n" );
		goto out;
	}
	(*unit)->size = size;

	for ( i = 0; i < cells->num_cell; i++ ) {
		(*unit)[i].left = cells->line[i].left;
		(*unit)[i].right = cells->line[i].right;
	}

	*num_cell = cells->num_cell;
	
out:
	return ret;
}

s32 
addr_group_obj_show( const char *group_name, addr_group_unit_t **unit, u32 *num_cell )
{
	s32 ret = -ENOENT;
	struct hlist_node *pos = NULL;
	addr_group_item_t *group = NULL;
	u32 hash = addr_group_name_hash( group_name );

	hlist_for_each_entry( group, pos, &addr_group_head[hash], hnode ) {
		if ( group && 0 == strncmp(group->group_name, group_name, MAX_OBJ_NAME_LEN) ) {
			ret = addr_group_obj_show_item( group, unit, num_cell );
			if ( 0 != ret )
				duprintf( KERN_ERR, "can not show the addr_group item!\n" );
		}
	
	}

	return ret;
}

/* iptables match */
s32  addr_group_matchv4_func( addr_group_item_t *group, const u32 *ip4 )
{
	s32 match = 0;
	u32 i = 0;
	bool m = 0;
	u32 ip = *ip4;
	addr_group_cell_t *cells = NULL;

	ASSERT( group != NULL );

	rcu_read_lock();
	cells = addr_group_get_cell_rcu( group );
	if ( !cells )
		return match;

#ifdef ADDR_GROUP_RLP
	if ( !addr_group_rlp_enable )
		goto slow_path;

	/* rlp match time complexity is O(log2n) */
	match = addr_group_rlp_find( (struct rlp_spec*)cells->rlp, *ip4 );
	if ( -1 != match ) 
		return match;
#endif
slow_path:
	/* Slow path */
	this_cpu_inc( group->stats->rlp_invalid );
	for ( i = 0; i < cells->num_cell; i++ ) {
		prefetch( cells );
		m = ntohl(ip) < ntohl(cells->line[i].left.ip);
		m |= ntohl(ip) > ntohl(cells->line[i].right.ip);
		m ^= !!(0 & ADDROBJ_INV);
		if ( !m ) {
			match = 1;
			break;
		}
	}

	return match;
}

s32
addr_group_matchv6_func( addr_group_item_t *group, const struct in6_addr *ip6 )
{
	s32 match = 0;
	
	return match;
}

/* Seq file and sysctl for Debug configureation */

#ifdef CONFIG_PROC_FS

static void *
addr_group_seq_start( struct seq_file *seq, loff_t *pos )
{
	loff_t n = *pos;
	if ( !n ) 
		seq_puts( seq, "addr group object list:\n" );

	mutex_lock( &class_lock );
	return *pos >= ADDR_GROUP_HASH_SIZE ? NULL : pos;
}

static void *
addr_group_seq_next( struct seq_file *seq, void *v, loff_t *pos )
{
	(*pos)++;
	return *pos >= ADDR_GROUP_HASH_SIZE ? NULL : pos;
}

static void 
addr_group_seq_stop( struct seq_file *seq, void *v )
{
	mutex_unlock( &class_lock );
	return;
}

static u32
addr_group_read_stats( addr_group_item_t *group )
{
	unsigned int refcnt = 0;
	int cpu;
	for_each_possible_cpu( cpu ) {
		const addr_group_stat_t *stats 
			= per_cpu_ptr( group->stats, cpu );

		refcnt += stats->rlp_invalid;
	}
	return refcnt;
}

static int 
addr_group_seq_show( struct seq_file *seq, void *v )
{
	addr_group_item_t *group = NULL;
	struct hlist_node *npos = NULL;
	addr_group_cell_t *cells;
	u32 i = 0;
	u32 num_cell = 0;

	loff_t *pos = v;
	if( v == NULL ) {
		return 0;
	}

	rcu_read_lock();
	hlist_for_each_entry( group, npos, &addr_group_head[*pos], hnode ) {
		cells = addr_group_get_cell_rcu( group );
		if ( cells ) num_cell = cells->num_cell;
		seq_printf( seq, "Name: %s  Family: %s Cur_s: %u, Refcnt %u Error: %u \n\n",
			group->group_name,
			(group->family == 0) ? "ipv4" : "ipv6",  
			cells ? cells->num_cell : 0, 
			atomic_read(&group->refcnt), 
			addr_group_read_stats(group) );

		for ( i = 0; i < num_cell; i++ ) 
			seq_printf( seq, "left = %-16pI4 right = %pI4\n", 
				&cells->line[i].left, 
				&cells->line[i].right );
	}
	rcu_read_unlock();

	return 0;
}

static const struct seq_operations addr_group_seq_ops = {
	.start          = addr_group_seq_start,
	.next           = addr_group_seq_next,
	.stop           = addr_group_seq_stop,
	.show         	= addr_group_seq_show,
};

static int 
addr_group_seq_open( struct inode *inode, struct file *file )
{
	return seq_open( file, &addr_group_seq_ops );
}

const struct file_operations add_group_list_fops = {
	.owner          = THIS_MODULE,
	.open		= addr_group_seq_open,
	.read         	= seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

/* Addr group rlp seq show */

static void *
addr_group_rlp_seq_start( struct seq_file *seq, loff_t *pos )
{
	loff_t n = *pos;
	if ( !n ) 
		seq_puts( seq, "addr group rlp tree:\n" );

	mutex_lock( &class_lock );
	return *pos >= ADDR_GROUP_HASH_SIZE ? NULL : pos;
}

static void *
addr_group_rlp_seq_next( struct seq_file *seq, void *v, loff_t *pos )
{
	(*pos)++;
	return *pos >= ADDR_GROUP_HASH_SIZE ? NULL : pos;
}

static void 
addr_group_rlp_seq_stop( struct seq_file *seq, void *v )
{
	mutex_unlock( &class_lock );
	return;
}

static int 
addr_group_rlp_seq_show( struct seq_file *seq, void *v )
{
	addr_group_item_t *group = NULL;
	struct hlist_node *npos = NULL;
	addr_group_cell_t *cells;
	rlp_error stat;
	u_int32_t key = 0, ip4 = 0;
	struct locate_inf inf;

	loff_t *pos = v;
	if( v == NULL ) {
		return 0;
	}

	rcu_read_lock();
	hlist_for_each_entry( group, npos, &addr_group_head[*pos], hnode ) {
		cells = addr_group_get_cell_rcu( group );

		seq_printf( seq, "Name: %s  Family: %s Cur_s: %u, Refcnt %u, Error %u\n",
				group->group_name, 
				(group->family == 0) ? "ipv4" : "ipv6",  
				cells ? cells->num_cell : 0, 
				atomic_read(&group->refcnt),
				addr_group_read_stats(group) );

		if ( !cells ) continue;

		do {
			stat = rlp_locate( (struct rlp_spec *)cells->rlp, &inf, key );
			if ( RLP_ERR == stat ) 
				return 0;

			ip4 = htonl( inf.key );
			seq_printf( seq, "%-16pI4 0x%-12x ", &ip4, inf.key );

			if ( *inf.nextspec == g_gen_spec )
				seq_printf( seq, "Hit!\n" );
			else
				seq_printf( seq, "No hit!\n" );
			key = inf.key +1;

		} while ( inf.key < MAXKEY(BIT_U32) );

	}
	rcu_read_unlock();

	return 0;
}

static const struct seq_operations addr_group_rlp_seq_ops = {
	.start          = addr_group_rlp_seq_start,
	.next           = addr_group_rlp_seq_next,
	.stop           = addr_group_rlp_seq_stop,
	.show         	= addr_group_rlp_seq_show,
};

static int 
addr_group_rlp_seq_open( struct inode *inode, struct file *file )
{
	return seq_open( file, &addr_group_rlp_seq_ops );
}

const struct file_operations add_group_rlp_fops = {
	.owner          = THIS_MODULE,
	.open		= addr_group_rlp_seq_open,
	.read         	= seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

struct proc_dir_entry *proc_addr_group;
static int __net_init 
addr_group_net_init( struct net *net )
{
	proc_addr_group = proc_mkdir( "addr_group", proc_netobj );
	if ( !proc_addr_group )
		return -ENOMEM;

	if ( !proc_create_data( "addr_group_list", S_IRUGO, proc_addr_group, &add_group_list_fops, NULL ) )
		goto remove_addr_group;

#ifdef ADDR_GROUP_RLP
	if ( !proc_create_data( "addr_group_rlp", S_IRUGO, proc_addr_group, &add_group_rlp_fops, NULL ) )
		goto remove_addr_group_list;

	proc_symlink( "addr_group_rlp_enable", proc_addr_group, PROC_PATH"/addr_group_rlp_enable" );
#endif

	return 0;

remove_addr_group_list:
	remove_proc_entry( "addr_group_list", proc_addr_group );	
remove_addr_group:
	remove_proc_entry( "addr_group", proc_netobj );
	return -ENOMEM;
}

static void __net_exit 
addr_group_net_exit( struct net *net )
{
#ifdef ADDR_GROUP_RLP
	remove_proc_entry( "addr_group_rlp", proc_addr_group );
	remove_proc_entry( "addr_group_rlp_enable", proc_addr_group );
#endif
	remove_proc_entry( "addr_group_list", proc_addr_group );
	remove_proc_entry( "addr_group",proc_netobj  );
	return ;
}

static struct pernet_operations addr_group_net_ops = {
	.init = addr_group_net_init,
	.exit = addr_group_net_exit,
};

int
addr_group_readproc_init( void )
{
	return register_pernet_subsys( &addr_group_net_ops );
}

void
addr_group_obj_readproc_exit( void )
{
	unregister_pernet_subsys( &addr_group_net_ops );
}

#else	/* CONFIG_PROC_FS */

int
addr_group_readproc_init( void )
{
	return 0;
}

void
addr_group_obj_readproc_exit( void )
{
	return ;
}

#endif	/* CONFIG_PROC_FS */

#ifdef CONFIG_SYSCTL
struct ctl_table_header *addr_group_sysctl_header = NULL;

static ctl_table addr_group_sysctl_table[] = {
	{
		.procname		= "addr_group_rlp_enable",
		.data			= &addr_group_rlp_enable,
		.maxlen			= sizeof( int ),
		.mode			= 0644,
		.proc_handler		= &proc_dointvec,
		
	},
	{ }
};

static ctl_table addr_group_chiledir_table[] = {
	{
		.procname	= "addr_group",
		.mode		= 0555,
		.child		= addr_group_sysctl_table,
	},
	{ }
};

static ctl_table addr_group_obj_netobj_table[] = {
	{
		.procname	= "netobj",
		.mode		= 0555,
		.child		= addr_group_chiledir_table,
	},
	{ }
};

static ctl_table addr_group_root_table[] = {
	{
		.procname	= "leadsec",
		.mode		= 0555,
		.child		= addr_group_obj_netobj_table,
	},
	{ }
};

static int addr_group_sysctl_init( void )
{
	addr_group_sysctl_header = register_sysctl_table( addr_group_root_table );
	if ( NULL == addr_group_sysctl_header )
		return -ENOMEM;

	return 0;
}

static void addr_group_obj_sysctl_fint( void )
{
	unregister_sysctl_table( addr_group_sysctl_header );
	return ;
}

#else	/* CONFIG_SYSCTL */

static int addr_group_sysctl_init( void )
{
	return 0;
}

static void addr_group_obj_sysctl_fint( void )
{
	return ;
}

#endif	/* CONFIG_SYSCTL */

s32 addr_group_obj_proc_init( void )
{
	int ret = 0;

	ret = addr_group_sysctl_init();
	if ( 0 != ret )
		return ret;

	ret = addr_group_readproc_init();
	if ( 0 != ret )
		goto unreg_sysctl;

	return ret;

unreg_sysctl:
	addr_group_obj_sysctl_fint();
	return ret;

}

void addr_group_obj_proc_fint( void )
{
	addr_group_obj_readproc_exit();
	addr_group_obj_sysctl_fint();
	return ;
}

EXPORT_SYMBOL_GPL(addr_group_hash_init);
EXPORT_SYMBOL_GPL(addr_group_hash_fint);
EXPORT_SYMBOL_GPL( find_addr_group_obj );
EXPORT_SYMBOL_GPL( bind_addr_group_obj );
EXPORT_SYMBOL_GPL( release_addr_group_obj );
EXPORT_SYMBOL_GPL( construct_addr_group_obj );
EXPORT_SYMBOL_GPL( destruct_addr_group_obj );
EXPORT_SYMBOL_GPL( modify_addr_group_obj );
EXPORT_SYMBOL_GPL( flush_addr_group_obj );
EXPORT_SYMBOL_GPL( addr_group_obj_exist );
EXPORT_SYMBOL_GPL( addr_group_obj_get_count );
EXPORT_SYMBOL_GPL( addr_group_obj_show );
EXPORT_SYMBOL_GPL( addr_group_matchv4_func );
EXPORT_SYMBOL_GPL( addr_group_matchv6_func );
EXPORT_SYMBOL_GPL( addr_group_obj_proc_init );
EXPORT_SYMBOL_GPL( addr_group_obj_proc_fint );
