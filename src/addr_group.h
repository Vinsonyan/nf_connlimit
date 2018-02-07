#ifndef __ADDR_GROUP__
#define __ADDR_GROUP__

#include "class_core.h"
#include "addr_group_pub.h"

#ifndef DEBUG
#define DEBUG
#endif

#define PROC_PATH	"/proc/sys/leadsec/netobj/addr_group"

#ifdef DEBUG
#define duprintf( prio, format, args... ) printk( prio "%s %d: " format , __FUNCTION__, __LINE__, ## args )
#else
#define duprintf( prio, format, args... )
#endif	/* DEBUG */

#ifndef ADDR_GROUP_RLP
#define ADDR_GROUP_RLP
#endif	/* ADDR_GROUP_RLP */

#ifdef ADDR_GROUP_RLP
#include "rlp.h"
#endif

typedef struct addr_group_line {
	nf_inet_addr_t left;
	nf_inet_addr_t right;

} addr_group_line_t;

typedef struct addr_group_cell {
	u_int32_t 	num_cell;
	struct rcu_head	rcu;
	size_t size;
#ifdef ADDR_GROUP_RLP
	addr_group_rlp_t *rlp;
#endif
	addr_group_line_t line[0];	/* muse be in here */
	
} addr_group_cell_t;

typedef struct addr_group_item {
        char group_name[MAX_OBJ_NAME_LEN];
        struct hlist_node hnode;
        atomic_t refcnt;
        u8 family;
        size_t  size;
	addr_group_stat_t __percpu *stats;
	addr_group_cell_t *cells;

} addr_group_item_t;

#ifdef ADDR_GROUP_RLP
extern addr_group_rlp_t *g_gen_spec;
#endif
extern s32 addr_group_hash_init( void );
extern void addr_group_hash_fint( void );
extern addr_group_item_t * find_addr_group_obj( const char *group_name, u8 flags );
extern void bind_addr_group_obj( addr_group_item_t *group );
extern void  release_addr_group_obj( addr_group_item_t *group );
extern s32 construct_addr_group_obj( const char* group_name, const addr_group_unit_t* cells, u32 num_cell );
extern s32 destruct_addr_group_obj( const char *group_name );
extern s32 modify_addr_group_obj( const char* group_name, const addr_group_unit_t* cells, u32 num_cell );
extern s32 flush_addr_group_obj( void );
extern s32 addr_group_obj_exist( const char* group_name );
extern s32 addr_group_obj_get_count( const char *group_name, u32 *count );
extern s32 addr_group_obj_show( const char *group_name, addr_group_unit_t **cells, u32 *num_cell );
extern s32 addr_group_matchv4_func( addr_group_item_t *group, const u32 *ip4 );
extern s32 addr_group_matchv6_func( addr_group_item_t *group, const struct in6_addr *ip6 );
extern s32 addr_group_obj_proc_init( void );
extern void addr_group_obj_proc_fint( void );

#endif	/* __ADDR_GROUP_PUB__  */
