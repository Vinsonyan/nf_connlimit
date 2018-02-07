#ifndef __SERVGRP_STD_H__
#define __SERVGRP_STD_H__

#include <linux/types.h>

#ifndef DEBUG
//#define DEBUG
#endif

#ifndef MAX_OBJ_NAME_LEN
#define MAX_OBJ_NAME_LEN 64
#endif

#define PROC_SERVGRP	"/proc/sys/leadsec/netobj/servgrp"
#ifndef __KERNEL
typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
#endif

/* Socketopt cmds */
#define SERV_GRP_OBJ_BASE	1096
enum servgrp_setsockopt_cmds {
	SERV_GROUP_OBJ_ADD = 	SERV_GRP_OBJ_BASE,
	SERV_GROUP_OBJ_MODIFY,
	SERV_GROUP_OBJ_DELETE,
	SERV_GROUP_OBJ_EMPTY,
	SERV_GROUP_OBJ_SET_MAX,
	
};

enum servgrp_getsockopt_cmds {
	SERV_GROUP_OBJ_SHOW = SERV_GRP_OBJ_BASE,
	SERV_GROUP_OBJ_EXIST,
	SERV_GROUP_OBJ_COUNT,
	SERV_GROUP_OBJ_GET_MAX,
	
};

#ifdef USE_OPTIMIZE
enum servgrp_protocol {
	PROTO_TCP,
	PROTO_UDP,
	PROTO_ICMP,
	PROTO_OTHER,
	PROTO_MAX,

}
#endif

typedef struct servgrp_cell {
	char serv_name[MAX_OBJ_NAME_LEN];
	size_t size;
	
} servgrp_cell_t;

typedef struct servgrp_request {
	char grp_name[MAX_OBJ_NAME_LEN];
	u32	num_cell;
	u32	size;
	servgrp_cell_t cells[0];
	
} servgrp_request_t;


/* Kernel struct for servgrp */
#ifdef __KERNEL__

typedef struct servobj_item_cell {
        char name[MAX_OBJ_NAME_LEN];
        unsigned long obj_addr;
	size_t size;

}servobj_cell_t;

typedef struct servgrp_item {
        char name[MAX_OBJ_NAME_LEN];
        struct list_head list;
        rwlock_t lock;
        atomic_t refcnt;
        u32      num_cell;
	u32	 size;
#ifndef USE_OPTIMIZE
        servobj_cell_t *cells;
#else
	servobj_cell_t cells[128][PROTO_MAX];
#endif
} servgrp_item_t;

/* Export API */
extern class_item_t servgrp_class;

extern servgrp_item_t *service_grp_find_obj( const char *grp_name );
extern void service_grp_bind_obj( unsigned long servgrp_addr );
extern void service_grp_release_obj( unsigned long servgrp_addr );
extern int service_grp_match_func( unsigned long servgrp_addr, const struct sk_buff *skb );

extern int servict_grp_init_class( class_item_t *servgrp_item );
extern void service_grp_fint_class( void );
 
extern int service_grp_construct_item( const char *name, servgrp_cell_t *cells, u32 num_cell );
extern int service_grp_destruct_item( const char *name );
extern int service_grp_modify_item( const char *grp_name, servgrp_cell_t *cells, u32 num_cell );
extern int service_grp_flush_item( void );
extern int service_grp_exist_item( const char *grp_name );
extern int service_grp_count_item( const char *grp_name, int *count );
extern int service_grp_show_item( const char *grp_name, servgrp_cell_t **cells, u32 *num_cell );

extern int service_grp_proc_init( void );
extern void service_grp_proc_exit( void );

#endif	/* __KERNEL__ */

#endif	/* __SERVGRP_H__ */
