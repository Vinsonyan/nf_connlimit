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
#include "servobj.h"

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "LeadSec" );
MODULE_DESCRIPTION( "service object kernel module" );

static unsigned long
servobj_find_obj( const char *name, unsigned char flags )
{
	return ( unsigned long )service_find_obj( name );
}

static void
servobj_release_obj( unsigned long addr )
{
	return service_release_obj( (servobj_item_t*)addr );
}

static int
servobj_match_func( unsigned long addr, int cmd, void *info, int *len )
{
	int ret = 0;

	switch ( cmd ) {
	case MATCH_PKT_SERVICE:
		ret =  service_match_func( (servobj_item_t*)addr, (const pkt_info_t *)info ) ;
		break;
	default:
		duprintf( "Unkonw command about service object!\n" );
		ret = 0;
		break;
	}
	return ret;
}

static int
do_add_servobj_cmd( void __user *user, int *len )
{
	servobj_request_t req;

	int ret = 0;

	if ( servobj_class.cfg.max_size &&
	   unlikely(atomic_read(&servobj_class.cfg.cur_size) > servobj_class.cfg.max_size) ) {
		duprintf( "table full, droping request!\n" );
		return -ENOMEM;
	}

	if ( *len != sizeof(servobj_request_t) ) {
		duprintf( "service object infomation len is invalid kern len [%zd] != user len[%d]!\n",
		    sizeof(servobj_request_t), *len );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( &req, user, *len );
	if ( ret != 0 ) {
		duprintf( "Servobj copy from userspace to kernel failed.!\n" );
		return ret;
	}

	ret = servobj_construct_item( &req );
	if( ret != 0 ) {
		duprintf( "Construct servobj_item failed.\n" );
		return ret;
	}

	return ret;
}
	
static int
do_delete_servobj_cmd( void __user *user, int *len )
{
	char servobj_name[MAX_OBJ_NAME_LEN];
	int ret = 0;

	if ( *len != MAX_OBJ_NAME_LEN ) {
		duprintf( "service object infomation len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( servobj_name, user, *len );
	if ( ret != 0 ) {
		duprintf( "Servobj copy from userspace to kernel failed.!\n" );
		return ret;
	}

	ret = servobj_destruct_item( servobj_name );
	if ( ret != 0 ) {
		duprintf( "Destruct servobj_item failed.\n" );
		return ret;
	}

	return ret;
}

static int
do_modify_servobj_cmd( void __user *user, int *len )
{
	servobj_request_t req;
	int ret = 0;

	if ( *len != sizeof(servobj_request_t) ) {
		duprintf( "service object infomation len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( &req, user, *len );
	if ( ret != 0 ) {
		duprintf( "Servobj copy from userspace to kernel failed.!\n" );
		return ret;
	}

	ret = servobj_modify_item( &req );
	if ( ret != 0 ) {
		duprintf( "Modify servobj [%s] failed.\n", req.name );
		return ret;
	}

	return ret;
}

static int
do_flush_servobj_cmd( void __user *user, int *len )
{
	int ret = 0;

	if ( *len != 0 ) {
		duprintf( "service object infomation len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = servobj_flush_item();
	if ( ret != 0 ) {
		duprintf( "Flush all servobj failed!\n" );
		return ret;
	}

	return ret;
}

static int
do_count_servobj_cmd( void __user *user, int *len )
{
	return 0;
}

static int
do_exist_servobj_cmd( void __user *user, int *len )
{
	int ret = 0;
	char servobj_name[MAX_OBJ_NAME_LEN] = {0};

	if ( *len != MAX_OBJ_NAME_LEN ) {
		duprintf( "service object infomation len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( servobj_name, user, *len );
	if ( ret != 0 ) {
		duprintf( "Get serobj_name from userspace to kernel failed.\n" );
		return ret;
	}

	*len = servobj_exist_item( servobj_name );
	if ( ret != 0 ) 
		duprintf( "This servobj already exitst!\n" );
	
	return 0;
}

static int
do_show_servobj_cmd( void __user *user, int *len )
{
	int ret = 0;
	servobj_request_t req;

	if ( *len != sizeof(servobj_request_t) ) {
		duprintf( "service object information len is invalid!\n" );
		return -ENOPROTOOPT;
	}

	ret = copy_from_user( &req, user, *len );
	if ( ret != 0 ) {
		duprintf( "Get serobj_name from userspace to kernel failed.\n" );
		return ret;
	}

	ret = servobj_show_item( &req );
	if ( ret != 0 ) {
		duprintf( "Get service object [%s] information failed!\n", req.name );
		return ret;
	}

	ret = copy_to_user( user, &req, *len );
	if ( ret != 0 ) {
		duprintf( "Copy servobj [%s] information to userspace failed!\n", req.name );
		return ret;
	}

	return 0;
}

static sockopt_array service_object_sockopt[] = {
	/* SET */
	{
		.id = SERVICE_OBJ_ADD,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_add_servobj_cmd,
	},
	{
		.id = SERVICE_OBJ_MODIFY,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_modify_servobj_cmd,
	},
	{
		.id = SERVICE_OBJ_DELETE,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_delete_servobj_cmd,
	},
	{
		.id = SERVICE_OBJ_EMPTY,
		.method = NETOBJ_SOCKOPT_METHOD_SET,
		.sockopt_proc = do_flush_servobj_cmd,
	},
	/* GET */
	{
		.id = SERVICE_OBJ_SHOW,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_show_servobj_cmd,
	},
	{
		.id = SERVICE_OBJ_EXIST,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_exist_servobj_cmd,
	},
	{
		.id = SERVICE_OBJ_COUNT,
		.method = NETOBJ_SOCKOPT_METHOD_GET,
		.sockopt_proc = do_count_servobj_cmd,
	},

	{},
};

/* Class_item */
class_item_t servobj_class  = {
	.class_name	= "servobj",
	.bind_class	= &bind_class_item,
	.release_class = &release_class_item,
	.find_object 	= &servobj_find_obj,
	.release_object	= &servobj_release_obj,
	.do_stuff	= &servobj_match_func,
	.refcnt		= ATOMIC_INIT( 0 ),
	.sockopts	= service_object_sockopt,
	/* service object configure */
	.cfg = {
		.max_size = 4096,
		.cur_size	= ATOMIC_INIT( 0 ),
	},
	.owner		= THIS_MODULE, 
};
EXPORT_SYMBOL( servobj_class );

static int
servobj_parse_proto( pkt_info_t *pkt_info )
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
servobj_mt( const struct sk_buff *skb, struct xt_action_param *par )
{
	class_match_t *info = ( class_match_t * )par->matchinfo;
	pkt_info_t pkt_info;

	if ( par->fragoff != 0 )
		return false;
	
	pkt_info.skb = skb;
	pkt_info.thoff = par->thoff;
	pkt_info.family = par->family;
	
	if ( servobj_parse_proto(&pkt_info) != 0 )
		return false;
	
	return info->class_ptr->do_stuff( info->obj_addr, MATCH_PKT_SERVICE, (void*)&pkt_info, 0 );
}

static int
servobj_mt_check( const struct xt_mtchk_param *par )
{
	return ipt_class_checkentry( par->matchinfo );
}

static void
servobj_mt_destroy( const struct xt_mtdtor_param *par )
{
	return ipt_class_destroy( par->matchinfo );
}

static struct xt_match servobj_match[] __read_mostly = {
	{
		.name		= "servobj",
		.family		= NFPROTO_IPV4,
		.match		= servobj_mt,
		.checkentry	= servobj_mt_check,
		.destroy	= servobj_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
	{
		.name		= "servobj",
		.family		= NFPROTO_IPV6,
		.match		= servobj_mt,
		.checkentry 	= servobj_mt_check,
		.destroy	= servobj_mt_destroy,
		.matchsize	= sizeof( class_match_t ),
		.me		= THIS_MODULE,
	},
};

static int __init
servobj_init( void )
{
	int ret = 0;
	/* Register class_item */
	ret = register_class_item( &servobj_class );
	if ( ret < 0 ) {
		duprintf( "Servobj_init: Register class item [servobj] failed!\n" );
		return ret;
	}
	
	/* Register match */
	ret = xt_register_matches( servobj_match, ARRAY_SIZE(servobj_match) );
	if ( ret < 0 ) {
		duprintf( "Servobj_init: Register servobj match failed!\n" );
		goto unreg_class;
	}

	ret = service_obj_proc_init();
	if ( 0 != ret ) {
		duprintf( "Register proc file system failed.\n" );
		goto unregister_match;
	}

	return ret;

unregister_match:
	xt_unregister_matches( servobj_match, ARRAY_SIZE(servobj_match) );
unreg_class:
	unregister_class_item( &servobj_class );
	return ret;
}

static void __exit
servobj_fint( void )
{
	/* unresigter match */
	xt_unregister_matches( servobj_match, ARRAY_SIZE(servobj_match) );
	/* Flush all servobj_item */
	servobj_flush_item();
	/* Resigter class_item */
	unregister_class_item( &servobj_class );
	service_obj_proc_fint();
}

module_init( servobj_init );
module_exit( servobj_fint );
