/* Kernel module to addrange parameters. */

/* (C) 2013 LeadSec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include "class_core.h"
#include "addr_group.h"
#include "addr_group_pub.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "addr group object kernel module" );

static unsigned long
addr_group_find_obj( const char *obj_name, unsigned char flags )
{
	return (unsigned long)find_addr_group_obj( obj_name, flags );
}

static void
addr_group_release_obj( unsigned long obj_addr )
{
	return release_addr_group_obj( (addr_group_item_t *)obj_addr );
}

static s32
addr_group_match_func( unsigned long obj_addr, s32 cmd, void *info, s32 *len )
{
	s32 ret = 0;

	switch ( cmd ) {
	case MATCH_PKT_IPV4:
		ret =  addr_group_matchv4_func( (addr_group_item_t *)obj_addr, (const u32*)info ) ;
		break;
	case MATCH_PKT_IPV6:
		ret =  addr_group_matchv6_func( (addr_group_item_t *)obj_addr, (const struct in6_addr *)info ) ;
	default:
		duprintf( KERN_ERR, "Unkonw command about service object!\n" );
		ret = 0;
		break;
	}
	return ret;
}

static int
do_add_addr_group_cmd( void __user *user, int *len )
{
	addr_group_request_t *request = NULL;
	s32 ret = 0;

	if ( *len < sizeof(addr_group_request_t) ||
		(*len - sizeof(addr_group_request_t)) % sizeof(addr_group_unit_t) != 0 ) {
		duprintf( KERN_ERR, "addr group object infomation len is" 
			  "invalid userlen[%d], kernel len[%zd]!\n", *len, sizeof(addr_group_request_t) );
		return -ENOPROTOOPT;
	}
	
	request = (addr_group_request_t*)netobj_kzalloc( *len,GFP_ATOMIC );
	if ( NULL == request ) {
		duprintf( KERN_ERR, "error can not allocate memory!\n" );
		return -ENOMEM;
	}

	ret = copy_from_user( request, user, *len );
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "can not copy information from user to kernel!\n" );
		goto free_request;
	}
	request->size = *len;
	
	if ( sizeof(addr_group_request_t) + request->num_cell * sizeof(addr_group_unit_t) != *len ) {
		duprintf( KERN_ERR, "addr_group information length is invalid!\n" );
		ret = -ENOPROTOOPT;
		goto free_request;
	}
	
	ret = construct_addr_group_obj( request->group_name, request->cells,request->num_cell );
	if ( 0 != ret ) {
		duprintf( KERN_ERR,"can not construct addr_group object!\n" );
		goto free_request;
	}

free_request:
	netobj_kfree( request, request->size );
	request=NULL;

	return ret;
}
	
static s32
do_delete_addr_group_cmd( void __user *user, int *len )
{
	char group_name[MAX_OBJ_NAME_LEN]={0};
	s32 ret = 0;

	if ( MAX_OBJ_NAME_LEN != *len ) {
		duprintf( KERN_ERR, "userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( group_name, user, *len );
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "can not copy information from userspace to kernel!\n" );
		return ret;
	}

	ret = destruct_addr_group_obj( group_name );
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "can not destruct the addr_group object!\n" );
		return ret;
	}

	return ret;
}

static s32 
do_modify_addr_group_cmd( void __user *user, int *len )
{
	addr_group_request_t* request = NULL;
	s32 ret = 0;	

	if ( *len < sizeof(addr_group_request_t) || 
		0 != (*len-sizeof(addr_group_request_t)) % sizeof(addr_group_unit_t) ) {
		duprintf( KERN_ERR, "userspace addr_group information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	request = (struct addr_group_request*)netobj_kzalloc( *len,GFP_ATOMIC );
	if ( NULL == request ){
		duprintf( KERN_ERR, "error can not allocate memory!\n" );
		return -ENOMEM;
	}

	ret = copy_from_user( request, user, *len );
	if ( 0 != ret ){
		duprintf( KERN_ERR, "can not copy information from user to kernel!\n" );
		goto free_request;
	}
	request->size = *len;

	if ( sizeof(addr_group_request_t) + request->num_cell * sizeof(addr_group_unit_t) != *len ) {
		duprintf( KERN_ERR,"addr_group information length is invalid!\n" );
		ret = -ENOPROTOOPT;
		goto free_request;
	}

	ret = modify_addr_group_obj( request->group_name, request->cells, request->num_cell );
	if ( 0 != ret ){
		duprintf( KERN_ERR,"can not modify addr_group object!\n" );
		goto free_request;
	}

free_request:
	netobj_kfree( request, request->size );
	request=NULL;
	return ret;
}

static s32
do_flush_addr_group_cmd( void __user *user, int *len )
{
	s32 ret = 0;

	if ( 0 != *len ) {
		duprintf( KERN_ERR, "userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = flush_addr_group_obj();
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "Can not flush addr_group object!\n" );
		return ret;
	}
	
	return ret;
}

static s32
do_exist_addr_group_cmd( void __user *user, int *len )
{
	s32 ret = 0;
	char group_name[MAX_OBJ_NAME_LEN] = {0};
	
	if ( MAX_OBJ_NAME_LEN != (*len) ) {
		duprintf( KERN_ERR, "userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( group_name, user, *len );
	if ( ret != 0 ) {
		duprintf( KERN_ERR, "Get serobj_name from userspace to kernel failed.\n" );
		return ret;
	}
	*len = addr_group_obj_exist( group_name );
	
	return ret;
}

static s32 
do_get_count_addr_group_cmd( void __user *user, int *len )
{
	s32 ret = 0;
	char group_name[MAX_OBJ_NAME_LEN] = {0};
	
	if( MAX_OBJ_NAME_LEN != (*len) ) {
		duprintf( KERN_ERR,"userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret  =copy_from_user( group_name, user, MAX_OBJ_NAME_LEN );
	if( 0!= ret ){
		duprintf( KERN_ERR,"can not copy addr_group name from userspace to kernel!\n" );
		return ret;
	}

	ret = addr_group_obj_get_count( group_name, len );
	if( 0!= ret ){
		duprintf( KERN_ERR,"can not get the addr_group object's count!\n" );
		return ret;
	}

	return ret;
}

static s32 
do_show_addr_group_cmd( void __user *user, int *len )
{
	addr_group_request_t request;
	s32 ret = 0;
	addr_group_unit_t *unit = NULL;
	u32 num_cell=0;
	addr_group_request_t *show_result = NULL;
	
	/* copy addr_group_request and check wether or not the *len is invalid */
	if ( (*len) < sizeof(addr_group_request_t) ){
		duprintf( KERN_ERR, "userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( &request, user, sizeof(addr_group_request_t) );
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "can not copy information from userspace to kernel!\n" );
		return ret;
	}

	if ( sizeof(addr_group_request_t) + request.num_cell * sizeof(addr_group_unit_t) != (*len) ) {
		duprintf( KERN_ERR, "userspace information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	//show addr_group information :
	ret = addr_group_obj_show( request.group_name, &unit, &num_cell );
	if ( ret!=0 ) {
		duprintf( KERN_ERR, "can not show  the '%s' addr_group object!\n" ,request.group_name);
		return ret;
	}

	//populate show_result and copy it to userspace;
	if ( num_cell != request.num_cell ) {
		duprintf( KERN_ERR, "addr_group have been changed during show!\n" );
		ret = -EINTR;
		goto free_cells;
	}
	show_result = (addr_group_request_t*)netobj_kzalloc( (*len), GFP_ATOMIC );
	if ( NULL == show_result ) {
		duprintf( KERN_ERR, "no memory to allocate for showing addr_group!\n" );
		ret = -ENOMEM;
		goto free_cells;
	}
	show_result->size = (*len);

	strncpy( show_result->group_name, request.group_name, MAX_OBJ_NAME_LEN );
	show_result->num_cell = num_cell;
	if ( 0 != num_cell ) 
		memcpy( show_result->cells,unit,(*len) - sizeof(addr_group_request_t) );

	ret = copy_to_user( user,show_result,*len);
	if( 0 != ret ){
		duprintf( KERN_ERR, "can not copy addr_group showed to userspace!\n" );
		goto free_result;
	}
free_result:
	netobj_kfree( show_result, show_result->size );
	show_result = NULL;
free_cells:
	if( NULL != unit ) {
		netobj_kfree( unit, unit->size );
		unit = NULL;
	}
	
	return ret;
}

#ifndef NETOBJ_METHOD
static s32
do_addr_group_set_ctl( struct sock *sk, int cmd, void __user *user, u32 len )
{
	s32 ret = 0;

	if ( (u32) cmd < ADDR_GROUP_OBJ_BASE || 
		(u32)cmd > ADDR_GROUP_OBJ_SET_MAX )	
		return -EINVAL;
	
	switch ( cmd ) {
	case ADDR_GROUP_OBJ_ADD:
		ret = do_add_addr_group_cmd( user, len );
		break;

	case ADDR_GROUP_OBJ_DELETE:
		ret = do_delete_addr_group_cmd( user, len );
		break;

	case ADDR_GROUP_OBJ_MODIFY:
		ret = do_modify_addr_group_cmd( user, len );
		break;

	case ADDR_GROUP_OBJ_FLUSH:
		ret = do_flush_addr_group_cmd( user, len );
		break;
		
	default:
		duprintf( KERN_ERR,"No such command for addr group!\n" );
		break;
	}

	return ret;
}

static s32
do_addr_group_get_ctl( struct sock *sk, int cmd, void __user *user, int *len )
{
	s32 ret = 0;

	if ( (int)cmd > ADDR_GROUP_OBJ_GET_MAX ||
		(int)cmd < ADDR_GROUP_OBJ_BASE )
		return -EINVAL;
	switch ( cmd ) {
	case ADDR_GROUP_OBJ_EXIST:
		ret = do_exist_addr_group_cmd( user, len );
		break;

	case ADDR_GROUP_OBJ_GET_COUNT:
		ret = do_get_count_addr_group_cmd( user, len );
		break;

	case ADDR_GROUP_OBJ_SHOW:
		ret = do_show_addr_group_cmd( user, len );
		break;

	default:
		break;
	}
	return ret;
}
#endif	/* NETOBJ_METHOD */

#ifndef NETOBJ_METHOD
static struct nf_sockopt_ops addr_group_sockopts = {
	.pf		= PF_INET,
	.set_optmin	= ADDR_GROUP_OBJ_BASE,
	.set_optmax	= ADDR_GROUP_OBJ_SET_MAX + 1,
	.set		= do_addr_group_set_ctl,
	
	.get_optmin	= ADDR_GROUP_OBJ_BASE,
	.get_optmax	= ADDR_GROUP_OBJ_GET_MAX + 1,
	.get		= do_addr_group_get_ctl,
	.owner		= THIS_MODULE,

};
#else
static sockopt_array addr_group_sockopt[] = {
		/* SET */
		{
			.id = ADDR_GROUP_OBJ_ADD,
			.method = NETOBJ_SOCKOPT_METHOD_SET,
			.sockopt_proc = do_add_addr_group_cmd,
		},
		{
			.id = ADDR_GROUP_OBJ_DELETE,
			.method = NETOBJ_SOCKOPT_METHOD_SET,
			.sockopt_proc = do_delete_addr_group_cmd,
		},
		{
			.id = ADDR_GROUP_OBJ_MODIFY,
			.method = NETOBJ_SOCKOPT_METHOD_SET,
			.sockopt_proc = do_modify_addr_group_cmd,
		},
		{
			.id = ADDR_GROUP_OBJ_FLUSH,
			.method = NETOBJ_SOCKOPT_METHOD_SET,
			.sockopt_proc = do_flush_addr_group_cmd,
		},
		/* GET */
		{
			.id = ADDR_GROUP_OBJ_EXIST,
			.method = NETOBJ_SOCKOPT_METHOD_GET,
			.sockopt_proc = do_exist_addr_group_cmd,
		},
		{
			.id = ADDR_GROUP_OBJ_GET_COUNT,
			.method = NETOBJ_SOCKOPT_METHOD_GET,
			.sockopt_proc = do_get_count_addr_group_cmd,
		},
		{
			.id = ADDR_GROUP_OBJ_SHOW,
			.method = NETOBJ_SOCKOPT_METHOD_GET,
			.sockopt_proc = do_show_addr_group_cmd,
		},

		{},
};
#endif	/* NETOBJ_METHOD */

class_item_t addr_group_class  = {
	.class_name	= "addrgrp",
	.bind_class	= &bind_class_item,
	.release_class 	= &release_class_item,
	.find_object	= &addr_group_find_obj,
	.release_object	= &addr_group_release_obj,
	.do_stuff	= &addr_group_match_func,
	.refcnt		= ATOMIC_INIT( 0 ),
	.sockopts	= addr_group_sockopt,
	/* addrange object configure */
	.cfg = {
		.max_size = 8096,
		.cur_size	= ATOMIC_INIT( 0 ),
		.max_number = 4096,
	},
};
EXPORT_SYMBOL( addr_group_class );

/* Match function */
static bool 
addr_group_mt4( const struct sk_buff *skb, struct xt_action_param *par )
{
	class_match_t *info = ( class_match_t * )par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);
	s32 ret;

	if ( info->flags & ADDROBJ_SRC ) {
		ret = info->class_ptr->do_stuff( info->obj_addr, 
		MATCH_PKT_IPV4, (void*)&iph->saddr, NULL );
		if ( !ret )
			return ret;
	}
	if ( info->flags & ADDROBJ_DST ) {
		ret = info->class_ptr->do_stuff( info->obj_addr, 
		MATCH_PKT_IPV4, (void*)&iph->daddr, NULL );
		if ( !ret )
			return ret;
	}

	return true;
}

static bool 
addr_group_mt6( const struct sk_buff *skb, struct xt_action_param *par )
{
	class_match_t *info = ( class_match_t * )par->matchinfo;
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	s32 ret;
	
	if ( info->flags & ADDROBJ_SRC ) {
		ret = info->class_ptr->do_stuff( info->obj_addr, 
		MATCH_PKT_IPV6, (void*)&iph->saddr, NULL );
		if ( !ret )
			return ret;
	}
	if ( info->flags & ADDROBJ_DST ) {
		ret = info->class_ptr->do_stuff( info->obj_addr, 
		MATCH_PKT_IPV6, (void*)&iph->daddr, NULL );
		if ( !ret )
			return ret;
	}

	return true;
}

static s32
addr_group_mt_check( const struct xt_mtchk_param *par )
{	
	return ipt_class_checkentry( par->matchinfo );
}

static void
addr_group_mt_destroy( const struct xt_mtdtor_param *par )
{
	return ipt_class_destroy( par->matchinfo );
}

static struct xt_match addr_group_match[] __read_mostly = {
	{
		.name		= "srcaddr",
		.family		= NFPROTO_IPV4,
		.match		= addr_group_mt4,
		.checkentry	= addr_group_mt_check,
		.destroy	= addr_group_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
	{
		.name		= "srcaddr",
		.family		= NFPROTO_IPV6,
		.match		= addr_group_mt6,
		.checkentry 	= addr_group_mt_check,
		.destroy	= addr_group_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
	{
		.name		= "dstaddr",
		.family		= NFPROTO_IPV4,
		.match		= addr_group_mt4,
		.checkentry	= addr_group_mt_check,
		.destroy	= addr_group_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
	{
		.name		= "dstaddr",
		.family		= NFPROTO_IPV6,
		.match		= addr_group_mt6,
		.checkentry 	= addr_group_mt_check,
		.destroy	= addr_group_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},

};

static s32 __init
addr_group_init( void )
{
	s32 ret = 0;

	/* Initiation hash table */
	ret = addr_group_hash_init();
	if ( ret < 0 ) {
		duprintf( KERN_ERR, "addr_group_init: Initiation hash table failed!\n" );
		return ret;
	}

	/* Register class_item */
	ret = register_class_item( &addr_group_class );
	if ( ret < 0 ) {
		duprintf( KERN_ERR, "addr_group_init: Register class item [addrange] failed!\n" );
		goto free_hash;
	}
#ifndef NETOBJ_METHOD
	/* Register socket_opt */
	ret = nf_register_sockopt( &addr_group_sockopts );
	if ( ret < 0 ) {
		duprintf( KERN_ERR, "addr_group_init: Register sockopt failed!\n" );
		goto unreg_class;
	}
#endif

	/* Register match */
	ret = xt_register_matches( addr_group_match, ARRAY_SIZE(addr_group_match) );
	if ( ret < 0 ) {
		duprintf( KERN_ERR, "addr_group_init: Register addrange match failed!\n" );
		goto unreg_sockopt;
	}
	
	ret = addr_group_obj_proc_init( );
	if ( 0 != ret ) {
		duprintf( KERN_ERR, "Register proc file system failed.\n" );
		goto unregister_match;
	}
	return ret;

unregister_match:
	xt_unregister_matches( addr_group_match, ARRAY_SIZE(addr_group_match) );

unreg_sockopt:
#ifndef NETOBJ_METHOD
	nf_unregister_sockopt( &addr_group_sockopts );
unreg_class:
#endif
	unregister_class_item( &addr_group_class );
	
free_hash:
	addr_group_hash_fint();
	
	return ret;
}

static void __exit
addr_group_fint( void )
{
	/* Free all addr group object */
	flush_addr_group_obj();
	/* unregister proc&&sysctl */
	addr_group_obj_proc_fint();
	/* unresigter match */
	xt_unregister_matches( addr_group_match, ARRAY_SIZE(addr_group_match) );
#ifndef NETOBJ_METHOD
	/* unresigter socket_opt */
	nf_unregister_sockopt( &addr_group_sockopts );
#endif
	/* unresigter class_item */
	unregister_class_item( &addr_group_class );
	/* Free hash table */
	addr_group_hash_fint();
	return ;
}

module_init( addr_group_init );
module_exit( addr_group_fint );

