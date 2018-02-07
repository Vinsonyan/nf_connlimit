/* servobj cli for service object */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/icmp.h>

#include "servobj.h"

#ifndef DEBUG
#define DEBUG
#endif

#ifdef DEBUG
#define duprintf( format, args... ) printf( "%s %d: " format , __FUNCTION__, __LINE__, ## args )
#else
#define duprintf( format, args... )
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct service_cmd
{
	const char* cmd;
	int (*fn)( int argc, char* argv[] );
};

typedef struct port_range {
	u16 srcstart, srcend;
	u16 dststart, dstend;

} port_range_t;

/* API list */
static int
str2range( port_range_t *range, char *str, int flags )
{
	char *buffer = strdup( str );
	char *cp = strchr( buffer, '-' );

	if ( cp == NULL )
		return -1;

	*cp = '\0';
	cp++;

	if ( !flags ) {
		range->srcstart = atoi( buffer );
		if ( range->srcstart > 0xffff )
			return -1;

		range->srcend = atoi( cp );
		if ( range->srcend > 0xffff )
			return -1;
	} else {
		range->dststart = atoi( buffer );
		if ( range->dststart > 0xffff )
			return -1;

		range->dstend = atoi( cp );
		if ( range->dstend > 0xffff )
			return -1;
	}

	return 0;
}

#if 0
static void
str2proto( char *proto, servobj_info_t *info )
{
	if ( strcmp( proto, "tcp" ) == 0 )
		info->proto = IPPROTO_TCP;
	else if ( strcmp(proto, "udp") == 0 )
		info->proto = IPPROTO_UDP;
	else if ( strcmp(proto, "icmp") == 0 )
		info->proto = IPPROTO_ICMP;
	else 
		return ;

	return ;
}
#endif

static int
servobj_check_icmp( int argc, char **argv )
{
	int ret = 0;
	u8 type = 0;
	u8 code = 0;

	if ( argc < 3 ) {
		duprintf( "Less key argment!\n" );
		return -1;
	}	

	type = atoi( argv[3] );

	duprintf( "Icmp type [%s]\n", argv[3] );
	switch ( type ) {
	case ICMP_DEST_UNREACH:
		if ( argc < 4 )	
			break;
		
		code = atoi( argv[4] );
		if ( code < ICMP_NET_UNREACH || code > NR_ICMP_UNREACH ) {
			duprintf( "Icmp code failed!\n" );
			ret = -1;
		} 

		break;

	case ICMP_REDIRECT:
		if ( argc < 4 )
			break;
		code = atoi( argv[4] );
		if ( code < ICMP_REDIR_NET || code > ICMP_REDIR_HOSTTOS ) {
			duprintf( "Icmp code failed!\n" );
			ret = -1;
		}

		break;

	case ICMP_TIME_EXCEEDED:
		if ( argc < 4 )	
			break;
		if ( code < ICMP_EXC_TTL || code > ICMP_EXC_FRAGTIME ) {
			duprintf( "Icmp code failed!\n" );
			ret = -1;
		}
		break;

	default:
		break;
	
	}

	return ret;
}

static void
servobj_fill_info( int argc, char **argv, servobj_info_t *info )
{
	int ret = 0;

	info->proto = atoi( argv[2] );
	
	switch ( info->proto ) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		info->optionisvalid = 1;
		info->option.port.srcstart = info->option.port.dststart = 0;
		info->option.port.srcend = info->option.port.dstend = 65535;
		
		if ( str2range((port_range_t*)&info->option.port, argv[3], 0) < 0 ) {
			duprintf( "Invalid srcport range!\n" );
			return ;
		}	
		
		if ( argc > 4 ) {
			if ( str2range((port_range_t*)&info->option.port, argv[4], 1) < 0 ) {
				duprintf( "Invalid srcport range!\n" );
				return ;
			}       
		}
		
		break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if ( strncmp(argv[3], "any", 3) == 0 )
			break;
		
		info->optionisvalid = 1;
		ret = servobj_check_icmp( argc, argv );	
		if ( ret != 0 )
			break;

		info->option.icmp.type = atoi( argv[3] );
		info->option.icmp.flags |= SERVICE_ICMP_TYPE_VALID;

		if ( strncmp(argv[4], "any", 3) == 0 ) 
			break;
		else {
			char *p = NULL;
			info->option.icmp.flags |= SERVICE_ICMP_CODE_VALID;
			
			p = strchr( argv[4], '-' );
			if ( p ) {
				*p = '\0';
				info->option.icmp.code[0] = atoi( argv[4] );
				info->option.icmp.code[1] = atoi( p + 1 );
			} else {
				info->option.icmp.code[0] = info->option.icmp.code[1] = atoi( argv[4] );	
			}
		}
		
		break;

	default:
		break;
	}

	return ;
}

int
servobj_add_obj( const char *name, servobj_info_t *info )
{
	servobj_request_t req;
	int ret = 0;
	int sockfd = -1;	

	duprintf( "Add New service object: " );
	duprintf( "Name: %s , ", name );
	duprintf( "Protocol: %u\n\n", info->proto );
	memset( &req, 0, sizeof(servobj_request_t) );
	strncpy( req.name, name, strlen(name) );
	req.serv_info = *info;

	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ){
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	ret=setsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_ADD, &req, sizeof(servobj_request_t) );
	if ( ret != 0 ) {
		duprintf( "Can't create new service object!\n" );
		ret = errno;
		goto close;
	}

close:

	close( sockfd );
	return ret;
}

int
servobj_delete_obj( const char *name )
{
	int sockfd = -1;
	int ret = 0;
	
	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ){
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	ret=setsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_DELETE, name, MAX_OBJ_NAME_LEN );
	if ( ret != 0 ) {
		duprintf( "Can't delete this service object!\n" );
		ret = errno;
		goto close;
	}	

close:
	close( sockfd );
	return ret;

}

int
servobj_modify_obj( const char *name, servobj_info_t *info )
{
	servobj_request_t req;
	int ret = 0;
	int sockfd = -1;

	duprintf( "Modify service object: " );
	duprintf( "Name: %s , ", name );
	duprintf( "Protocol: %u\n\n", info->proto );

	memset( &req, 0, sizeof(servobj_request_t) );
	strncpy( req.name, name, MAX_OBJ_NAME_LEN );
	req.serv_info = *info;

	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ){
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	ret=setsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_MODIFY, &req, sizeof(servobj_request_t) );
	if ( ret != 0 ) {
		duprintf( "Can't modify service object [%s]!\n", name );
		ret = errno;
		goto close;
	}

close:

	close( sockfd );
	return ret;
	
}

int 
servobj_show_obj( const char *name )
{
	int sockfd = -1;
	int len = 0, ret = 0;
	servobj_request_t req;
	
	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ){
		duprintf( "socket system call failed!\n" );
		return -errno;
	}
	
	memset( &req, 0, sizeof(servobj_request_t) );
	strncpy( req.name, name, strlen(name) );
	len = sizeof( servobj_request_t );
	ret = getsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_SHOW, &req, (socklen_t*)&len );
	if ( ret != 0 ) {
		duprintf( "Can't display service object!\n" );
		ret = -errno;
		goto close;
	}

close:
	close( sockfd );
	return ret;

}

#if 0
void
servobj_show_obj( servobj_request_t *req )
{
	servobj_info_t info = req->serv_info;
	u16 proto = info.proto;

	printf( "Service object name [%s], protocol [%u]\n", req->name, proto );
	switch ( proto ) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		printf( "sport[%u-%u], dport[%u-%u].\n", info.option.port.srcstart, info.option.port.srcend,
			info.option.port.dststart, info.option.port.dstend );
		break;
	case IPPROTO_ICMP:
		printf( "Type[%u], Code[%u-%u].\n", info.option.icmp.type, info.option.icmp.code[0],
			info.option.icmp.code[1] );
		break;
	default:
		break;
	}

	return ;
}
#endif

int servobj_exist_obj(  char *name )
{
	int sockfd = -1;
	int ret = 0;
	int len = 0;
	
	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call for check_service_exist failed!\n" );
		return -errno;
	}

	len = MAX_OBJ_NAME_LEN;
	
	ret = getsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_EXIST, name, (socklen_t*)&len );
	if ( ret != 0 ) {
		duprintf( "Check service object [%s] failed!\n", name );
		ret = -errno;
		goto close;
	}

close:
	close( sockfd );
	return ret == 0 ? len : ret;
}

/* Socketopt operation functions */
static int
add_service( int argc, char **argv )
{
	
	int ret = 0;
	char *name[MAX_OBJ_NAME_LEN] = {0};

	if ( argc < 3 ) {
		duprintf( "Less parameters for add_service!\n" );
		return -1;
	}	

	duprintf( "%s %s %s %s %s\n", argv[0], argv[1],argv[2], argv[3], argv[4] );

	servobj_info_t info;
	memset( &info, 0, sizeof(servobj_info_t) );

	servobj_fill_info( argc, argv, &info );
	ret = servobj_add_obj( argv[1], &info );
	if ( ret != 0 ) {
		duprintf( "Add new service object failed!\n" );
	}

	return ret;
}

static int
delete_service( int argc, char **argv )
{
	if ( argc < 2 ) {
		duprintf( "Less parameters for delete_service!\n" );
		return -1;
	}

	char service_name[MAX_OBJ_NAME_LEN];
	int sockfd = -1;
	int ret = 0;
	
	memset( service_name, 0, MAX_OBJ_NAME_LEN );
	strncpy( service_name, argv[1], MAX_OBJ_NAME_LEN );

	ret = servobj_delete_obj( service_name );
	if ( ret != 0 ) {
		duprintf( "Delete service object[%s] failed!\n", service_name );
		return ret;
	}

	return ret;
}

static int
modify_service( int argc, char **argv )
{
	int ret = 0;
	char name[MAX_OBJ_NAME_LEN];
	servobj_info_t info;

	if ( argc < 3 ) {
		duprintf( "Less parameters for modify_service!\n" );
		return -1;
	}	

	duprintf( "%s %s %s %s %s\n", argv[0], argv[1],argv[2], argv[3], argv [4] );

	memset( &info, 0, sizeof(servobj_info_t) );
	

	servobj_fill_info( argc, argv, &info );
	ret = servobj_modify_obj( argv[1], &info );
	if ( ret != 0 ) {
		duprintf( "Modify service object [%s] failed!\n", argv[1] );
	}
	
	return 0;
}

static int
show_service( int argc, char **argv )
{
	if ( argc < 2 ) {
		duprintf( "Less parameters for show_service!!\n" );
		return -1;
	}

	return servobj_show_obj( argv[1] );
}

static int
check_service_exist( int argc, char **argv )
{
	if ( argc < 2 ) {
		duprintf( "Less pararmters for judge_service_eixt!\n" );
		return -1;
	}

	int ret = 0;
	int sockfd = -1;
	char service_name[MAX_OBJ_NAME_LEN];

	memset( service_name, 0, MAX_OBJ_NAME_LEN );
	strncpy( service_name, argv[1], strlen(argv[1]) );

	ret  = servobj_exist_obj( service_name );
	if ( ret > 0 ) 
		duprintf( "Service object [%s] not exist!\n", argv[1] );
	else
		duprintf( "Service object [%s] already exist!\n", argv[1] );
	
	return ret;
}

static int
flush_service_set( int argc, char **argv )
{
	if ( argc < 1 ) {
		duprintf( "Less paramters for flush_service_set!\n" );
		return -1;
	}

	int ret = 0;
	int sockfd = -1;

	sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call for flush_service_set failed!\n" );
		return -errno;
	}
	
	ret=setsockopt( sockfd, IPPROTO_IP, SERVICE_OBJ_EMPTY, NULL, 0 );
	if ( ret != 0 ) {
		duprintf( "Can't Flush all service object!\n" );
		ret = errno;
		goto close;
	}

close:
	close( sockfd );
	return ret;
}

static struct service_cmd cmds[]={
	{"exist",check_service_exist},
	{"add",add_service},
	{"delete",delete_service},
	{"modify",modify_service},
	{"show",show_service},
	{"empty",flush_service_set},
	{NULL,NULL},
};

int main( int argc, char **argv )
{
	if ( argc < 2 ) {
		duprintf( "Less parameters for servobj command!\n" );
		return -1;
	}

	int i = 0;
	while ( cmds[i].cmd != NULL ) {
		if ( strcmp(cmds[i].cmd, argv[1]) == 0 )
			return cmds[i].fn( argc - 1, argv + 1 );

		i++;
	}

	duprintf( "Unknow parameters [%s] for servobj command!\n", argv[1] );

	return 0;
}
