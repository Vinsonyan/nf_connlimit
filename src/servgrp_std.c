/* Kernel module to sergrp parameters. */

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
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter/x_tables.h>

#include "class_core.h"
#include "servobj.h"
#include "servgrp.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "service group object kernel module" );

/* Class functions */
static unsigned long
servgrp_find_obj( const char *name, unsigned char flags )
{
	return (unsigned long)service_grp_find_obj( name );
}

static void
servgrp_release_obj( unsigned long addr )
{
	return service_grp_release_obj( (servgrp_item_t*)addr );
}

static int
servgrp_match_func( unsigned long addr, int cmd, void *info, int *len )
{
	switch ( cmd ) {
	case MATCH_PKT_SERVGRP:
		return service_grp_match_func( (servgrp_item_t*)addr, (const pkt_info_t *)info ) ;
		break;

	default:
		duprintf( "Unkonw command about service object!\n" );
		break;
	}
	return -ENOPROTOOPT;
}

/* Socketopt  */
static int
do_add_servgrp_cmd( void __user *user, int *len )
{
	int ret = 0;
	servgrp_request_t *req = NULL;

	if ( *len < sizeof(servgrp_request_t) ) {
		duprintf( "1: servgrp information length is invalid!\n" ) ;
		return -ENOPROTOOPT;
	}
	
	req = netobj_kmalloc( *len, GFP_ATOMIC );
	if ( req == NULL ) {
		duprintf( "Alloc memory for servgrp request struct failed.\n" );
		return -ENOMEM;
	}

	ret = copy_from_user( req, user, *len );
	if ( ret != 0 ) {
		duprintf( "Copy servgrp information from userspace to kernel failed.\n" );
		goto free_req;
		
	}
	req->size = *len;

	if ( *len != sizeof(servgrp_request_t) + req->num_cell * sizeof(servgrp_cell_t) ) {
		duprintf( "2: Servgrp infomation len is invalid!\n" );
		goto free_req;
	}

	ret = service_grp_construct_item( req->grp_name, req->cells, req->num_cell );
	if ( ret != 0 ) {
		duprintf( "Consturct servgrp item failed.\n" );
		goto free_req;
	}

free_req:
	netobj_kfree( req, req->size );
	return ret;
}

static int
do_delete_servgrp_cmd( void __user *user, int *len )
{
	int ret = 0;
	char name[MAX_OBJ_NAME_LEN]; 

	if ( *len != MAX_OBJ_NAME_LEN ) {
		duprintf( "Delete_servgrp: servgrp information length is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( name, user, *len );
	if ( ret != 0 ) {
		duprintf( "Delete_servgrp: Copy name from userspace to kernel failed.\n" );
		return ret;
	}

	ret = service_grp_destruct_item( name );
	if ( ret != 0 ) {
		duprintf( "Delete_servgtp_cmd: Delete name %s failed!\n", name );
		return ret;
	}

	return ret;
}

static int
do_modify_servgrp_cmd( void __user *user, int *len )
{
	servgrp_request_t *req = NULL;
	int ret = 0;

	if ( *len < sizeof(servgrp_request_t) ) {
		duprintf( "1, Modify_servgrp_cmd: servgrp_request information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	req = netobj_kzalloc( *len, GFP_ATOMIC );
	if ( req == NULL ) {
		duprintf( "Modify_servgrp_cmd: Alloc memory for servgrp_request_t failed!\n" );
		return -ENOMEM;
	}
	
	ret = copy_from_user( req, user, *len );
	if ( ret != 0 ) {
		duprintf( "Modify_servgrp_cmd: Copy servgrp_req from userspace to kernel failed!\n" );
		goto free_req;
	}

	req->size = *len;

	if ( *len != sizeof(servgrp_request_t) + req->num_cell * sizeof(servgrp_cell_t) ) {
		duprintf( "2, Modify_servgrp_cmd: servgrp_request information len is invalid!\n" );
		ret = -ENOPROTOOPT;
		goto free_req;
	}

	ret = service_grp_modify_item( req->grp_name, req->cells, req->num_cell );
	if ( ret != 0 ) {
		duprintf( "Modify_servgrp_cmd: Modify servgrp_item failed!\n" );
		goto free_req;
	}

free_req:
	netobj_kfree( req, req->size );
	req = NULL;
	
	return ret;
}

static int
do_flush_servgrp_cmd( void __user *user, int *len )
{
	int ret = 0;

	if ( *len != 0 ) {
		duprintf( "Flush_servgrp_cmd: servgrp_request information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = service_grp_flush_item();
	if ( ret != 0 ) {
		duprintf( "servgrp_flush_cmd: Flush all servgrp_item_t falied!\n" );
		return ret;
	}

	return ret;
}

static int
do_serv_group_exist_cmd( void __user *user, int *len )
{
	int ret = 0;
	char name[MAX_OBJ_NAME_LEN];

	if ( *len != MAX_OBJ_NAME_LEN ) {
		duprintf( "servgrp_exist: servgrp_request information len is invalid!" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( name, user, *len );
	if ( ret !=0 ) {
		duprintf( "servgrp_exist_cmd: Copy name from userspace to kernel failed!\n" );
		return ret;
	}

	*len = service_grp_exist_item( name );

	return ret;
}

static int
do_serv_group_count_cmd( void __user *user, int *len )
{
	int ret = 0;
	char name[MAX_OBJ_NAME_LEN];

	if ( *len != MAX_OBJ_NAME_LEN ) {
		duprintf( "servgrp_get_count: servgrp_request information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( name, user, *len );
	if ( ret !=0 ) {
		duprintf( "servgrp_get_count: Copy name from userspace to kernel failed!\n" );
		return ret;
	}

	ret = service_grp_count_item( name, len );

	return ret;

}

static int
do_serv_group_show_cmd( void __user *user, int *len )
{
	int ret = 0;
	servgrp_request_t req;
	servgrp_request_t *result = NULL;
	servgrp_cell_t *cells = NULL;
	u32 num_cell = 0;

	if ( *len < sizeof(servgrp_request_t) ) {
		duprintf( "1 servgrp_show_cmd: servgrp_request information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( &req, user, sizeof(servgrp_request_t) );
	if ( ret != 0 ) {
		duprintf( "1 servgrp_show_cmd: Copy servgrp_request_t information from userspace to kernel failed!\n" );
		return ret;
	}

	if ( (*len) != sizeof(servgrp_request_t) + req.num_cell * sizeof(servgrp_cell_t) ) {
		duprintf( "2 servgrp_show_cmd: servgrp_request information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = service_grp_show_item( req.grp_name, &cells, &num_cell );
	if ( ret != 0 ) {
		duprintf( "servgrp_show_cmd: Can't show all servobj by this servgrp_item!\n" );
		return ret;
	}

	if ( num_cell != req.num_cell ) {
		duprintf( "servgrp_show_cmd: Both servgrp_req and servgrp_item num_cell differcnt!\n" );
		ret = -EINTR;
		goto free_cells;
	}

	result = ( servgrp_request_t * )netobj_kzalloc( *len, GFP_ATOMIC );
	if ( result == NULL ) {
		duprintf( "servgrp_show_cmd: Alloc memory for servgrp_request_t failed!\n" );
		ret = -ENOMEM;
		goto free_cells;
	}
	result->size = *len;

	strncpy( result->grp_name, req.grp_name, MAX_OBJ_NAME_LEN );
	result->num_cell = num_cell;
	if ( num_cell != 0 )
		memcpy( result->cells, cells, *len - sizeof(servgrp_request_t) );

	/* Copy servgrp_request_t from kernel to user */
	ret = copy_to_user( user, result, *len );
	if ( ret != 0 ) {
		duprintf( "servgrp_show_cmd: Copy servgrp_request_t struct from kernel to userspace failed!\n" );
		goto free_result;
	}

free_result:
	netobj_kfree( result, result->size );
	result = NULL;
	
free_cells:
	if ( cells != NULL ) {
		netobj_kfree( cells, cells->size );
		cells = NULL;
	}

	return ret;
}

static sockopt_array service_group_sockopt[] = {
	/* SET */
	{
		.id = SERV_GROUP_OBJ_ADD,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_add_servgrp_cmd,
	},
	{
		.id = SERV_GROUP_OBJ_MODIFY,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_modify_servgrp_cmd,
	},
	{
		.id = SERV_GROUP_OBJ_DELETE,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_delete_servgrp_cmd,
	},
	{
		.id = SERV_GROUP_OBJ_EMPTY,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_flush_servgrp_cmd,
	},
	/* GET */
	{
		.id = SERV_GROUP_OBJ_SHOW,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_serv_group_show_cmd,
	},
	{
		.id = SERV_GROUP_OBJ_EXIST,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_serv_group_exist_cmd,
	},
	{
		.id = SERV_GROUP_OBJ_COUNT,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_serv_group_count_cmd,
	},

	{},
};

class_item_t servgrp_class  = {
	.class_name	= "servgrp",
	.bind_class	= &bind_class_item,
	.release_class = &release_class_item,
	.find_object 	= &servgrp_find_obj,
	.release_object	= &servgrp_release_obj,
	.do_stuff	= &servgrp_match_func,
	.refcnt		= ATOMIC_INIT( 0 ),
	.sockopts	= service_group_sockopt,
	.cfg	= {
		.max_size = 512,
		.cur_size = ATOMIC_INIT( 0 ),
		.max_number = 128
	},
	.owner		= THIS_MODULE, 
};
EXPORT_SYMBOL( servgrp_class );

/* Iptables match  */
static int
servgrp_parse_proto( pkt_info_t *pkt_info )
{
	int ret = 0;
	
	switch ( pkt_info->family ) {
	case NFPROTO_IPV4:
		pkt_info->l3proto = IPPROTO_IP;
		pkt_info->l4proto = ip_hdr( pkt_info->skb )->protocol;
		break;

	case NFPROTO_IPV6:
		pkt_info->l3proto = IPPROTO_IPV6;
		pkt_info->l4proto = ipv6_hdr( pkt_info->skb )->nexthdr;
		break;

	default:
		ret = -1;
		break;
	}

	return ret;
}


static bool 
servgrp_mt( const struct sk_buff *skb, struct xt_action_param *par )
{
	class_match_t *info = ( class_match_t * )par->matchinfo;
	pkt_info_t pkt_info;

	if ( par->fragoff != 0 )
		return false;
	
	pkt_info.skb = skb;
	pkt_info.thoff = par->thoff;
	pkt_info.family = par->family;
	
	if ( servgrp_parse_proto(&pkt_info) != 0 )
		return false;

	return info->class_ptr->do_stuff( info->obj_addr, MATCH_PKT_SERVGRP, (void*)&pkt_info, 0 );
}

static int
servgrp_mt_check( const struct xt_mtchk_param *par )
{
	return ipt_class_checkentry( par->matchinfo );
}

static void
servgrp_mt_destroy( const struct xt_mtdtor_param *par )
{
	return ipt_class_destroy( par->matchinfo );
}

static struct xt_match servgrp_match[] __read_mostly = {
	{
		.name		= "servgrp",
		.family		= NFPROTO_IPV4,
		.match		= servgrp_mt,
		.checkentry	= servgrp_mt_check,
		.destroy	= servgrp_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
	{
		.name		= "servgrp",
		.family		= NFPROTO_IPV6,
		.match		= servgrp_mt,
		.checkentry 	= servgrp_mt_check,
		.destroy	= servgrp_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
};

static int __init
servgrp_init( void )
{
	int ret = 0;
	/* Register class_item */
	ret = register_class_item( &servgrp_class );
	if ( ret < 0 ) {
		duprintf( "servgrp_init: Register class item [servgrp_class] failed!\n" );
		return ret;
	}

	/* Register match */
	ret = xt_register_matches( servgrp_match, ARRAY_SIZE(servgrp_match) );
	if ( ret < 0 ) {
		duprintf( "servgrp_init: Register servobj match failed!\n" );
		goto unreg_class;
	}

	ret = servict_grp_init_class( &servgrp_class );
	 if ( ret < 0 ) {
		duprintf( "servgrp_init: Initialize service_class failed!\n" );
		goto unreg_match;
	 }

	ret = service_grp_proc_init();
	if ( ret != 0 ) {
		duprintf( "servgrp_init: Register proc fs failed!\n" );
		goto unreg_match;
	}

	return ret;

unreg_match:
	xt_unregister_matches( servgrp_match, ARRAY_SIZE(servgrp_match) );
unreg_class:
	unregister_class_item( &servgrp_class );

	return ret;
}

static void __exit
servgrp_fint( void )
{
	/* unresigter match */
	xt_unregister_matches( servgrp_match, ARRAY_SIZE(servgrp_match) );
	/* Release child class_item */
	service_grp_fint_class();
	/* Register class_item */
	unregister_class_item( &servgrp_class );
	/* Unregister proc fs */
	service_grp_proc_exit();

	return ;
}

module_init( servgrp_init );
module_exit( servgrp_fint );

