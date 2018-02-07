/* servobj cli for service object */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "servgrp.h"

#ifndef DEBUG
#define DEBUG
#endif

#ifdef DEBUG
#define duprintf( format, args... ) fprintf(stderr, "%s %d: " format, __FUNCTION__, __LINE__, ## args)
#else
#define duprintf( format, args... )
#endif  /* DEBUG */

typedef unsigned int u32;
typedef unsigned char u8;

static struct option opts[] =
{
	{"add",1,0,'A'},
	{"delete",1,0,'D'},
	{"modify",1,0,'M'},
	{"exist",1,0,'E'},
	{"show",1,0,'S'},
	{"clean",1,0,'C'},
	{"service",1,0,'s'},
	{NULL},
};

#define OPERATE_FOUND	0x0001

#define ADD	1
#define DELETE	2
#define MODIFY	3
#define EXIST	4
#define SHOW	5
#define CLEAN	6

/* Api for sockopt */
static int
servgrp_show_obj_number( const char *name, servgrp_cell_t **cells, u32 *num_serv )
{
	int sockfd = -1;
	int ret = 0;
	int len = 0;
	u32 num_cells = 0, size = 0;
	char grp_name[MAX_OBJ_NAME_LEN] = {0};
	servgrp_request_t *group_info = NULL;

	/* Get number of servgrp object */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	strncpy( grp_name, name, MAX_OBJ_NAME_LEN );
	len = MAX_OBJ_NAME_LEN;
	ret = getsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_COUNT, grp_name, (socklen_t*)&len );
	if ( ret != 0 ) {
		ret = -errno;
		duprintf( "can't acquire the members count of the service group object(%s)!\n", grp_name );
		goto close_sockfd;
	}
	
	num_cells = len;
	size = sizeof( servgrp_request_t ) + sizeof( servgrp_cell_t ) * num_cells;
	group_info = malloc( size );
	if ( group_info == NULL ) {
		duprintf( "Alloc memory failed for servgrp_request_t!\n" );
		goto close_sockfd;
	}

	memset( group_info, 0, size );
	strncpy( group_info->grp_name, name, MAX_OBJ_NAME_LEN );
	group_info->num_cell=num_cells;
	
	ret = getsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_SHOW, group_info, (socklen_t*)&size );
	if ( ret != 0 ) {
		duprintf( "can't acquire information about the service group object(%s)!\n", name);
		ret=-errno;
		goto free_group_info;
	}

	if( group_info->num_cell != num_cells ) {
		duprintf( "group changed during showing!\n" );
		ret=-EINTR;
		goto free_group_info;
	}
	/* Get servgrp information success!! */
	
	if ( cells == NULL && *cells != NULL )
		goto free_group_info;

	*num_serv = num_cells;
	if ( num_cells != 0 ) {
		int size = sizeof(servgrp_cell_t) * num_cells;
		( *cells ) = ( servgrp_cell_t * )malloc( size );
		if( (*cells) == NULL ) {
			duprintf( "insufficient memory!\n");
			ret = -ENOMEM;
			goto free_group_info;
		}
		memset( (*cells ),0,size );
		u_int32_t i = 0;
		for( i = 0; i < num_cells; i++ ) {
			strncpy( (*cells)[i].serv_name, group_info->cells[i].serv_name, MAX_OBJ_NAME_LEN );
		}	
	}	

free_group_info:
	free( group_info );
	group_info = NULL;
close_sockfd:
	close( sockfd );
	return ret;
}

/* socketopt operation */
int
__servgrp_add_obj( const char *name, servgrp_cell_t *cells, u32 num_cell )
{
	int i = 0, ret = 0, sockfd = -1;
	int size = sizeof( servgrp_request_t ) + sizeof( servgrp_cell_t ) * num_cell;
	servgrp_request_t *req = ( servgrp_request_t * )malloc( size );
	if ( req == NULL ) {
		duprintf( "Alloc memory for servgrp_add_obj failed!\n" );
		return -ENOMEM;
	}
	memset( req, 0, size );
	
	duprintf( "Alloc memory size[%d], grp name is[%s]\n", size, name );
	/* Fill request struct */
	strncpy( req->grp_name, name, strlen(name) );
	req->num_cell = num_cell;
	
	duprintf( "Here!\n" );	
	for ( i = 0; i < num_cell; i++ ) {
		strncpy( req->cells[i].serv_name, cells[i].serv_name, strlen(cells[i].serv_name) );
	}

	duprintf( "Here!\n" );	
	/* Create socket and socket set */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		ret = -errno;
		goto free_req_mm;
	}

	duprintf( "Here!\n" );	
	ret = setsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_ADD, req, size );
	if ( ret != 0 ) {
		duprintf( "can't create a new service group object(%s)!\n", name );
		ret = -errno;
		goto close_sock;
	}

	duprintf( "Here!\n" );	
close_sock:
	close( sockfd );
free_req_mm:
	free( req );
	return ret;
}

extern int servgrp_add_obj( const char *name )
{

	return __servgrp_add_obj( name, NULL, 0 );
}

int
servgrp_delete_obj( const char *name )
{
	int ret = 0;
	int sockfd = -1;

	char grp_name[MAX_OBJ_NAME_LEN] = {0};

	memset( grp_name, 0, MAX_OBJ_NAME_LEN );
	strncpy( grp_name, name, MAX_OBJ_NAME_LEN );
	
	/* Create socket and socket set */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}
		
	ret = setsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_DELETE, grp_name, MAX_OBJ_NAME_LEN );
	if ( ret != 0 ) {
		duprintf( "can't delete service group object(%s)!\n", name );
		ret = -errno;
	}

free_sock:
	close( sockfd );
	return ret;
}

static int
servgrp_modify_obj( const char *name, servgrp_cell_t *cells, u32 num_cell )
{
	int i = 0, ret = 0, sockfd = -1;
	int size = sizeof( servgrp_request_t ) + sizeof( servgrp_cell_t ) * num_cell;
	servgrp_request_t *new_req = ( servgrp_request_t * )malloc( size );
	if ( new_req == NULL ) {
		duprintf( "Alloc memory for servgrp_modify_obj failed!\n" );
		return -ENOMEM;
	}
	memset( new_req, 0, size );
	
	/* Fill request struct */
	strncpy( new_req->grp_name, name, MAX_OBJ_NAME_LEN );
	new_req->num_cell = num_cell;

	for ( i = 0; i < num_cell; i++ ) {
		strncpy( new_req->cells[i].serv_name, cells[i].serv_name, MAX_OBJ_NAME_LEN );
	}

	/* Create socket and socket set */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		ret = -errno;
		goto free_newreq_mm;
	}

	ret = setsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_MODIFY, new_req, size );
	if ( ret != 0 ) {
		duprintf( "can't modify service group object(%s)!\n", new_req->cells[i].serv_name );
		ret = -errno;
		goto close_sock;
	}

close_sock:
	close( sockfd );
free_newreq_mm:
	free( new_req );
	return ret;	
}

/* Sockopt Get */
static int
servgrp_exist_obj( const char *name )
{
	int ret = 0;
	int sockfd = -1;

	char grp_name[MAX_OBJ_NAME_LEN] = {0};
	strncpy( grp_name, name, MAX_OBJ_NAME_LEN );
	
	/* Create socket and socket set */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	u32 len = MAX_OBJ_NAME_LEN;
	ret=getsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_EXIST, grp_name, (socklen_t*)&len );	
	if ( ret != 0 ) {
		duprintf( "can't delete service group object(%s)!\n", name );
		ret = -errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
	return ret == 0 ? len : ret;	
}

static int
servgrp_show_obj( const char *name )
{
	servgrp_cell_t *cells = NULL;	
	u32 num_cell = 0;
	int ret = 0;

	ret = servgrp_show_obj_number( name, &cells, &num_cell );
	if ( ret != 0 ) {
		duprintf( "Can't show service group object(s)!\n" );
		return -errno;
	}
	
	/* display servgrp object(s) information */
	printf( "the '%s' serv_group object information : \n",name );
	printf( "\tit has '%lu' service objects : \n", num_cell );
	u_int32_t i = 0;
	for( i = 0; i < num_cell; i++ ) {
		printf( "\t\t%s\n",cells[i].serv_name );
	}

	if ( cells ) {
		free( cells );
		cells = NULL;
	}	

	return ret;
}

static int
servgrp_clean_obj()
{
	int ret = 0;
	int sockfd = -1;

	/* Create socket and socket set */
	sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}
		
	ret = setsockopt( sockfd, IPPROTO_IP, SERV_GROUP_OBJ_EMPTY, NULL, 0 );
	if ( ret != 0 ) {
		duprintf( "can't flush service group object!\n");
		ret = -errno;
	}

free_sock:
	close( sockfd );
	return ret;
}

static int
servgrp_add_service_to_group( const char *servgrp_name, const char *name )
{
	servgrp_cell_t *servs = NULL;
	u32 num_cell = 0;
	int ret = -1;
	u32 i = 0;

	ret = servgrp_show_obj_number( servgrp_name, &servs, &num_cell );
	if ( ret != 0 ) {
		duprintf( "nothing about the service group(%s)!\n" );
		return ret;
	}

	for ( i = 0; i < num_cell; i++ ) {
		if ( strncmp(servs[i].serv_name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			duprintf( "This service object(%s) already exist", name );
			ret = -EEXIST;
			goto free_servs;
		}
	}

	servs = realloc( servs, sizeof(servgrp_cell_t) * (num_cell + 1) );
	if ( servs == NULL ) {
		duprintf( "Alloc memory for servgrp_cell_t failed!\n" );
		ret = -ENOMEM;
		goto free_servs;
	}

	strncpy( servs[num_cell].serv_name, name, MAX_OBJ_NAME_LEN );

	duprintf( "Before modify grpname[ %s ], num_cell[%d].\n", servgrp_name, num_cell + 1 );
	ret = servgrp_modify_obj( servgrp_name, servs, num_cell + 1 );
	if ( ret != 0) {
		duprintf( "can not modify service group object(%s)!\n", servgrp_name);
		goto free_servs;
	}

free_servs:
	if ( servs != NULL ) {
		free( servs );
		servs = NULL;
	}
	return ret;
}

static int
servgrp_remove_service_from_group( const char *servgrp_name, const char *name )
{
	servgrp_cell_t *servs = NULL;
	u32 num_cell = 0;
	int ret = -1;
	u32 i = 0, j = 0;

	ret = servgrp_show_obj_number( servgrp_name, &servs, &num_cell );
	if ( ret != 0 ) {
		duprintf( "nothing about the service group(%s)!\n" );
		return ret;
	}

	ret = -ENOENT;
	for ( i = 0; i < num_cell; i++ ) {
		if ( strncmp(servs[i].serv_name, name, MAX_OBJ_NAME_LEN) == 0 ) {
			duprintf( "This service object(%s) already exist\n", name );
			ret = 0;
			break;
		}
	}
	
	if ( ret != 0 ) {
		duprintf( "The servgrp object not a member of service object(%s).\n", name );
		goto free_servs;
	}
	
	for ( j = i; j < num_cell - 1; j++ ) {
		strncpy( servs[j].serv_name, servs[j+1].serv_name, MAX_OBJ_NAME_LEN ) ;
	}

	duprintf( "num_cell [%d]\n", num_cell );
	ret=servgrp_modify_obj( servgrp_name, servs, num_cell - 1);
	if ( ret != 0) {
		duprintf( "can not modify service group object(%s)!\n", servgrp_name);
		goto free_servs;
	}

free_servs:
	if ( servs != NULL ) {
		free( servs );
		servs = NULL;
	}
	return ret;

}

/* Socketopt operation function end */

int main( int argc, char **argv )
{
	int c = 0, ret = -1;
	int optflags = 0;
	char name[MAX_OBJ_NAME_LEN] = {0};
	char serv_name[MAX_OBJ_NAME_LEN] = {0};
	int operate = 0;
	u_int32_t num_cell = 0;
	servgrp_cell_t *cells = NULL;
	
	while ( (c = getopt_long(argc, argv, "-A:D:S:C:E:M:s:", opts, NULL)) != -1 ) {
		switch ( c ) {
		case 'A':
			if ( optflags & OPERATE_FOUND ){
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = ADD;
			duprintf( "%s\n", optarg );
			strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			duprintf( "%s\n", name );
			optflags |= OPERATE_FOUND;

			break;
		case 'D':
			if ( optflags & OPERATE_FOUND ) {
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = DELETE;
			strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			
			break;
		case 'S':
			if ( optflags & OPERATE_FOUND ) {
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = SHOW;
			strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;
		case 'E':
			if ( optflags & OPERATE_FOUND ) {
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = EXIST;
			strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;	
		case 'M':
			if ( optflags & OPERATE_FOUND ) {
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = MODIFY;
			strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;	
		case 'C':
			if ( optflags & OPERATE_FOUND ) {
				duprintf( "can not define operation more than once!\n" );
				return -1;
			}
			operate = CLEAN;
			optflags |= OPERATE_FOUND;
			break;
		case 's':
			duprintf( "operation 's', realloc srevgrp_cell_t sizeof [%d], num_cell [%d] optarg[%s]\n", 
					sizeof(servgrp_cell_t), num_cell, optarg) ;
			ret = servgrp_exist_obj( name );
			duprintf( "Ret is %d\n", ret );
			if ( !ret ) {	
				cells = ( servgrp_cell_t * )realloc( cells, sizeof(servgrp_cell_t) * (num_cell + 1) );
				if ( cells == NULL ) {
					duprintf( "Alloc memory for servgrp_cell_t failed!\n" );
					return -1;
				}
				strncpy( cells[num_cell].serv_name, optarg, MAX_OBJ_NAME_LEN );
				num_cell++;
			} else
				strncpy( serv_name, optarg, MAX_OBJ_NAME_LEN );

			break;
		default:
			duprintf( "1 Unknow command for servgrp!\n" );
			return -1;
		
		}
	}

	if ( !(optflags & OPERATE_FOUND) ) {
		duprintf( "Operation failed!\n" );
		return -1;
	}

	switch ( operate ) {
	case ADD:
		ret = servgrp_exist_obj( name );
		if ( !ret ) {
			ret = __servgrp_add_obj( name, cells, num_cell );
		} else {
			ret = servgrp_add_service_to_group( name, serv_name );
		}
		break;
	case DELETE:

		if ( name[0] != '\0' )
			ret = servgrp_remove_service_from_group( name, serv_name );
		else
			ret = servgrp_delete_obj( name );
		break;
	case MODIFY:
		ret = servgrp_modify_obj( name, cells, num_cell );
		break;
	case EXIST:
		ret = servgrp_exist_obj( name );
		break;
	case SHOW:
		ret = servgrp_show_obj( name );	
		break;
	case CLEAN:
		ret = servgrp_clean_obj();
		break;
	default:
		duprintf( "2 Unknow command for servgrp!!\n" );
		ret = -1;
		break;
	}	

	if ( cells )
		free( cells );
	return ret;
}
