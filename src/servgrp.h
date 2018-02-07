#ifndef __SERVGRP_STD_H__
#define __SERVGRP_STD_H__

#include "class_core.h"

#ifndef DEBUG
#define DEBUG
#endif

#ifdef __KERNEL__
#ifdef DEBUG
#define duprintf( format, args... ) printk( "%s %d: " format , __FUNCTION__, __LINE__, ## args )
#else
#define duprintf( format, args... )
#endif

#define PROC_SERVGRP	"/proc/sys/leadsec/netobj/servgrp"

#endif	/* __KERNEL__ */

typedef struct servgrp_cell {
	char serv_name[MAX_OBJ_NAME_LEN];
	size_t size;
	
} servgrp_cell_t;

/* usertoker request struct */
typedef struct servgrp_request {
	char grp_name[MAX_OBJ_NAME_LEN];
	u_int32_t	num_cell;
	u_int32_t	size;
	servgrp_cell_t cells[0];
	
} servgrp_request_t;

/* Kernel struct for servie group */
#ifdef __KERNEL__

typedef struct servgp_elem {
	char name[MAX_OBJ_NAME_LEN];
	unsigned long obj_addr;

} servgrp_elem_t; 

typedef struct servgrp_item_cell {
	u32	num_cell;
	size_t 	size;
	servgrp_elem_t elem[0];

}servgrp_unit_t;

typedef struct servgrp_item {
        char name[MAX_OBJ_NAME_LEN];
        struct list_head list;
        atomic_t refcnt;
	u32	 size;
       	servgrp_unit_t *cells;

} servgrp_item_t;

/* Export API */
extern class_item_t servgrp_class;

extern servgrp_item_t *service_grp_find_obj( const char *name );
extern void service_grp_release_obj( servgrp_item_t *group );
extern int service_grp_match_func( servgrp_item_t *group, const pkt_info_t *skb );

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
