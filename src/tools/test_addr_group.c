/*
*
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sys/types.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include "addr_group_pub.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
//#define NIPQUAD_FMT "%u.%u.%u.%u"


#ifdef DEBUG
#define duprintf( format, args... ) fprintf(stderr, "%s %d: " format, __FUNCTION__, __LINE__, ## args)
#else
#define duprintf( format, args... )
#endif  /* DEBUG */

static struct option opts[]={
		{"add",1,0,'A'},
		{"delete",1,0,'D'},
		{"modify",1,0,'M'},
		{"exist",1,0,'E'},
		{"show",1,0,'S'},
		{"clear",1,0,'C'},
		{"addr",1,0,'a'},
		{"number",0,0,'n'},
		{"verbose",0,0,'v'},
		{NULL},
};

#define OPERATE_FOUND		0x0001

#define ADD				1
#define ADD_TO		2
#define DELETE			3
#define DELETE_FROM			4
#define MODIFY			5
#define EXIST 			6
#define CLEAR			7
#define SHOW   			8

static int str2iprange( const char *str, struct in_addr *left, struct in_addr *right )
{
	int ret = -1;
        char *p = NULL;

        p = strchr( str, '-' );
        if ( NULL == p ) 
		return -1;

        *p = '\0';
        p++;
        ret = inet_aton( str, left );
        if ( 0 == ret )
                return -1;

        ret = inet_aton( p, right );
        if ( 0 == ret )
                return -1;

        return 0;
}

#if 0
static inline int nf_inet_addr_cmp(const nf_inet_addr_t_ipv4 *a1,
				   const nf_inet_addr_t_ipv4 *a2)
{
#if 0
	return a1->all[0] == a2->all[0] &&
	       a1->all[1] == a2->all[1] &&
	       a1->all[2] == a2->all[2] &&
	       a1->all[3] == a2->all[3];
#else
	return a1->ip == a2->ip;
#endif
}
#else
static inline int nf_inet_addr_cmp(const nf_inet_addr_t *a1,
				   const nf_inet_addr_t *a2)
{
	return a1->ip == a2->ip;
}
#endif

static int
addr_group_cells_equal( const addr_group_unit_t *a, const addr_group_unit_t *b )
{
	return nf_inet_addr_cmp( &a->left, &b->left ) &&
		nf_inet_addr_cmp( &a->right, &b->right );
}

static int 
add_group_obj_add( const char* groupname, const addr_group_unit_t* cells,u_int32_t num_cell )
{
	int socktfd = -1;
	int ret = 0;
	u_int32_t i = 0;
	addr_group_request_t* group = NULL;
	
	int len = sizeof(addr_group_request_t);
	if (num_cell!=0) {
		len = len + num_cell * sizeof(addr_group_unit_t);
	}

	group = (addr_group_request_t*)malloc( len );
	if ( group == NULL ) {
		printf("error : no memory to allocate!\n");
		exit(-1);
	}
	memset( group,0,len );
	strncpy(group->group_name, groupname, MAX_OBJ_NAME_LEN);
	group->num_cell = num_cell;

	for ( i = 0; i < num_cell; i++ ) {
		group->cells[i].left = cells[i].left;
		group->cells[i].right = cells[i].right;
	}

	int sockfd = socket( PF_INET,SOCK_STREAM,0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		ret =- errno;
		goto free_need_add;
	}

	ret = setsockopt( sockfd,IPPROTO_IP,ADDR_GROUP_OBJ_ADD,group,len );
	if ( ret != 0 ) {
		duprintf( "can't create a new address group object(%s)!\n" ,groupname );
		ret=-errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
free_need_add:
	free( group );
	return ret;
}

extern int 
addr_group_obj_del( const char * name )
{
	char group_name[MAX_OBJ_NAME_LEN] = {0};
	strncpy( group_name,name,MAX_OBJ_NAME_LEN );

	int ret=0;
	int sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd<0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	ret = setsockopt( sockfd,IPPROTO_IP,ADDR_GROUP_OBJ_DELETE,group_name,MAX_OBJ_NAME_LEN );
	if ( ret != 0 ) {
		duprintf( "can't delete the address group object(%s)!\n" ,name);
		ret=-errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
	return ret;	
}

static int 
addr_group_obj_modify( const char * name, const addr_group_unit_t * cells, unsigned long num_cell )
{
	int ret = 0;
	int size = sizeof(addr_group_request_t) + num_cell * sizeof(addr_group_unit_t);
	addr_group_request_t* new_context = (addr_group_request_t*)malloc( size );
	if ( new_context==NULL ){
		duprintf( "insufficient memory!\n" );
		return -ENOMEM;
	}
	memset( new_context, 0, size );

	strncpy( new_context->group_name, name, MAX_OBJ_NAME_LEN );
	new_context->num_cell = num_cell;

	if ( num_cell != 0 ) {
		memcpy( new_context->cells, cells,num_cell * sizeof(addr_group_unit_t));
	}

	int sockfd = socket( PF_INET,SOCK_STREAM,0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		ret=-errno;
		goto free_new_context;
	}

	ret = setsockopt( sockfd, IPPROTO_IP, ADDR_GROUP_OBJ_MODIFY, new_context,size );
	if ( ret != 0 ) {
		duprintf( "can not modify address group object(%s)!\n" ,name);
		ret=-errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
free_new_context:
	free( new_context );
	return ret;
}

static int
addr_group_obj_exist( const char * name )
{
	char group_name[MAX_OBJ_NAME_LEN] = {0};
	strncpy( group_name, name, MAX_OBJ_NAME_LEN );

	int ret = 0;
	int sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}

	int len = MAX_OBJ_NAME_LEN;
	ret = getsockopt( sockfd, IPPROTO_IP, ADDR_GROUP_OBJ_EXIST, group_name, (socklen_t*)&len );
	if ( ret != 0 ) {
		duprintf( "getsockopt system call failed!\n" );
		ret=-errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
	return ret == 0 ? len : ret;
}

extern int 
addr_group_obj_show( const char * name, addr_group_request_t ** info )
{
	int ret = 0;
	int sockfd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		return -errno;
	}
	
	char groupname[MAX_OBJ_NAME_LEN];
	strncpy( groupname, name, MAX_OBJ_NAME_LEN );
	int len = MAX_OBJ_NAME_LEN;
	
	unsigned long num_cells = 0;
	ret = getsockopt( sockfd, IPPROTO_IP, ADDR_GROUP_OBJ_GET_COUNT, groupname, (socklen_t*)&len );
	if ( ret != 0 ) {
		duprintf( "can't acquire the count of members which the address group object(%s) owns!\n" ,name);
		ret=-errno;
		goto free_sock;
	}

	num_cells = len;
	int size = sizeof(addr_group_request_t) + num_cells*sizeof(addr_group_unit_t);
	addr_group_request_t *group_info = (addr_group_request_t*)malloc( size );
	if ( group_info == NULL ) {
		duprintf( "insufficient memory!\n" );
		ret = -ENOMEM;
		goto free_sock;
	}
	memset( group_info, 0, size );
	strncpy( group_info->group_name, name, MAX_OBJ_NAME_LEN );
	group_info->num_cell = num_cells;

	ret = getsockopt( sockfd,IPPROTO_IP,ADDR_GROUP_OBJ_SHOW,group_info,(socklen_t*)&size);
	if ( ret!=0 ) {
		duprintf( "can't acquire the members of the address group object(%s)!\n" ,name);
		ret = -errno;
		goto free_group_info;
	}

	if ( group_info->num_cell != num_cells ) {
		duprintf( "group changed during showing!\n" );
		ret = -EINTR;
		goto free_group_info;
	}

	//malloc info and fil it up
	size = sizeof(addr_group_request_t) + sizeof(addr_group_unit_t) * num_cells;
	(*info) = (addr_group_request_t*)malloc( size );
	if ( (*info) == NULL ) {
		duprintf( "insufficient memory!\n" );
		ret = -ENOMEM;
		goto free_group_info;
	}
	memset( (*info),0,size );
	memcpy( (*info)->cells, group_info->cells, size - sizeof(addr_group_request_t) );
	(*info)->num_cell = group_info->num_cell;

	if ( ret != 0 ) {
		free( *info );
		*info = NULL;
	}

free_group_info:
	free( group_info );
	group_info = NULL;
free_sock:	
	close( sockfd );
	return ret;
}

static void 
print_addr_group_unit( const addr_group_unit_t* unit )
{

	//printf( "addr_range : 0x%x - 0x%x",unit->left.ip, unit->right.ip );
	printf( "addr_range : %u.%u.%u.%u - %u.%u.%u.%u",NIPQUAD(unit->left.ip), NIPQUAD(unit->right.ip) );
	return;
}

static int 
show_group( const char* name, int flags )
{
	addr_group_request_t* group_info = NULL;
	int ret = addr_group_obj_show( name, &group_info );
	if( ret != 0 ) {
		printf( "can not show the '%s' addr_group object!\n", name );
		return ret;
	}

	printf( "the '%s' addr_group object information:\n", name );
	printf( "		total %lu\n",group_info->num_cell ); 
	u_int32_t i = 0;

	if ( flags != 1 )
		goto out;

	for( i = 0; i < group_info->num_cell; i++ ) {
		printf("				");
		print_addr_group_unit( &group_info->cells[i] );
		printf( "\n" );
	}

out:
	return ret;
}

static int addr_group_clear(void)
{
	int socktfd = -1;
	int ret = 0;

	int sockfd = socket( PF_INET,SOCK_STREAM,0 );
	if ( sockfd < 0 ) {
		duprintf( "socket system call failed!\n" );
		ret =- errno;
		return ret;
	}

	ret = setsockopt( sockfd,IPPROTO_IP, ADDR_GROUP_OBJ_FLUSH, NULL, 0);
	if ( ret != 0 ) {
		duprintf( "can't create a new address group object!\n" );
		ret=-errno;
		goto free_sock;
	}

free_sock:
	close( sockfd );
	return ret;
}

static int 
add_cell_to_addr_group_obj(const char * name, const addr_group_unit_t *obj )
{
	addr_group_request_t *groupinfo = NULL;
	addr_group_unit_t *cells = NULL;
	size_t size = 0;
	int ret = addr_group_obj_show( name, &groupinfo );
	if( ret != 0 ) {
		duprintf( "can't acquire address group object(%s) information!\n", name );
		return ret;
	}

	u_int32_t i = 0;
	for ( i = 0; i < groupinfo->num_cell; i++ ) {
		if ( addr_group_cells_equal(obj,&groupinfo->cells[i]) ) {
			duprintf( "address object had been a member of the address group(%s)!\n", name);
			ret =- EEXIST;
			errno = EEXIST;
			goto free_groupinfo;
		}
	}

	size = sizeof(addr_group_request_t) + ((groupinfo->num_cell + 1) * sizeof(addr_group_unit_t));
	groupinfo = (addr_group_request_t*)realloc( groupinfo, size );
	if ( groupinfo == NULL ) {
		duprintf( "insufficient memory!\n" );
		ret=-ENOMEM;
		goto free_groupinfo;
	}
	groupinfo->cells[groupinfo->num_cell] = *obj;
	(groupinfo->num_cell)++;

	ret = addr_group_obj_modify( name, groupinfo->cells, groupinfo->num_cell );
	if ( ret != 0 ) {
		duprintf( "can not modify the address group object(%s)!\n" );
		goto free_groupinfo;
	}

free_groupinfo:
	if ( groupinfo != NULL ) {
		free( groupinfo );
		groupinfo = NULL;
	}
	return ret;
}


static int 
remove_cell_to_addr_group_obj( const char * name, const addr_group_unit_t *obj )
{
	addr_group_request_t *groupinfo = NULL;
	u_int32_t i = 0, j = 0;
	size_t size = 0;
	int ret = addr_group_obj_show( name, &groupinfo );
	if ( ret != 0 ) {
		duprintf( "can't acquire address group object(%s) information!\n", name );
		return ret;
	}

	ret = -ENOENT;
	for ( i = 0; i < groupinfo->num_cell; i++ ) {
		if ( addr_group_cells_equal(obj,&groupinfo->cells[i]) ) {
			ret = 0;
			break;
		}
	}
	
	if ( 0 != ret )
		goto free_groupinfo;

	for( j = i; j < groupinfo->num_cell - 1; j++ ) {
		groupinfo->cells[j] = groupinfo->cells[j+1];
	}
	groupinfo->num_cell--;

	ret = addr_group_obj_modify( name, groupinfo->cells, groupinfo->num_cell );
	if ( ret != 0 ) {
		duprintf("can not modify the address group object(%s)!\n" );
		goto free_groupinfo;
	}

free_groupinfo:
	if ( groupinfo != NULL ) {
		free( groupinfo );
		groupinfo = NULL;
	}
	return ret;
}

int 
main(int argc,char* argv[])
{
	int c = 0;
	int optflags = 0, show_flags = 0;
	char name[MAX_OBJ_NAME_LEN] = {0};
	int operate = 0;
	unsigned long num_cell = 0;
	addr_group_unit_t* context = NULL;
	struct in_addr left, right;
	
	optind = 0;
	while( (c = getopt_long(argc,argv,"-A:D:L:M:E:a:nv:",opts,NULL)) != -1 ) {
		switch ( c ) {
		case 'A':
			if ( optflags & OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			strncpy( name,optarg,MAX_OBJ_NAME_LEN );
			if ( addr_group_obj_exist(name) )
				operate = ADD_TO;
			else
				operate = ADD;
			optflags |= OPERATE_FOUND;
			break;
		case 'D':
			if( optflags&OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			operate = DELETE;
			strncpy( name,optarg,MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;
		case 'L':
			if ( optflags&OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			operate = SHOW;
			if ( optarg )
				strncpy( name, optarg, MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;
		case 'M':
			if ( optflags & OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			operate = MODIFY;
			strncpy( name,optarg,MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
			break;
		case 'E':
			if ( optflags & OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			operate = EXIST;
			strncpy( name,optarg,MAX_OBJ_NAME_LEN );
			optflags |= OPERATE_FOUND;
					
		case 'C':
			if ( optflags & OPERATE_FOUND ) {
				printf("can not define operation more than once!\n");
				exit(-1);
			}
			operate = CLEAR;
			optflags |= OPERATE_FOUND;
			break;break;
		case 'a':
			if ( 0 != (str2iprange( optarg, &left, &right)) ) {
				printf( "can not conver string to iprange!\n" );
				exit( -1 );
			}

			context = (addr_group_unit_t*)realloc( context, sizeof(addr_group_unit_t) * (num_cell + 1) );
			if ( context == NULL ) {
				printf("fatal error : no memory to allocate!\n");
				exit(-1);
			}

			context[num_cell].left.ip = left.s_addr;
			context[num_cell].right.ip = right.s_addr;
			num_cell++;	

			if ( operate == DELETE )
				operate = DELETE_FROM;

			break;

		case 'n':
		case 'v':
			if ( operate != SHOW ) {
				duprintf( "%s Error arg!\n", optarg );
				exit(-1);
			}
			
			show_flags = 1;	
			break;
		default:
			break;
		
		}
	}

	if ( (optflags&OPERATE_FOUND) == 0 ) {
		printf( "less operate!\n" );
		exit( -1 );
	}

	int ret = 0;
	switch ( operate ) {
	case ADD:
		ret = add_group_obj_add( name, context, num_cell );
		break;
	case ADD_TO:
		ret = add_cell_to_addr_group_obj(name,  context );
		break;
	case DELETE:
		ret = addr_group_obj_del( name );
		break;
	case DELETE_FROM:
		ret = remove_cell_to_addr_group_obj( name, context );
		break;
	case MODIFY:
		ret = addr_group_obj_modify( name,context,num_cell );
		break;
	case SHOW:
		ret = show_group( name, show_flags );
		break;
	case EXIST:
		ret = addr_group_obj_exist( name );
		switch ( ret ) {
		case 0:
			printf( "the addr_group '%s' does not exist!\n",name );
			break;
		case 1:
			printf( "the addr_group '%s' exists!\n",name );
			break;	
		default:
			printf( "I don't know whether or not the '%s' addr_group exists!\n",name );	
			break;
		}
			break;
		default:
			printf( "unknown operate!\n" );
			break;
	case CLEAR:
		ret = addr_group_clear();
		break;
	}
	

	if ( context != NULL ) {
		free( context );
	}

	return ret;
}

