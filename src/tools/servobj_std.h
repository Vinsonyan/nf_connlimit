#ifndef __SERVOBJ_STD_H__
#define __SERVOBJ_STD_H__

#include <linux/types.h>

#ifndef SERVOBJ_DEBUG
#define SERVOBJ_DEBUG
#endif

#ifdef SERVOBJ_DEBUG
#define duprintf( format, args... ) printf( "%s %d: " format , __FUNCTION__, __LINE__, ## args )
#else
#define duprintf( format, args... )
#endif

#ifndef MAX_OBJ_NAME_LEN
#define MAX_OBJ_NAME_LEN	64
#endif	/* MAX_OBJ_NAME_LEN */ 

#define PROC_SERVOBJ	"/proc/sys/leadsec/netobj/servobj"

typedef unsigned char	u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct sk_buff;

/* Socketopt cmds */
#define SERVICE_OBJ_BASE	1048
enum servobj_sockopt_set_cmds {
	SERVICE_OBJ_ADD = 	SERVICE_OBJ_BASE,
	SERVICE_OBJ_MODIFY,
	SERVICE_OBJ_DELETE,
	SERVICE_OBJ_EMPTY,
	SERVICE_OBJ_SET_MAX,
};

enum servobj_sockopt_get_cmds {
	SERVICE_OBJ_SHOW = SERVICE_OBJ_BASE,
	SERVICE_OBJ_EXIST,
	SERVICE_OBJ_COUNT,
	SERVICE_OBJ_GET_MAX,
};

enum icmp_match_types {
	SERVICE_ICMP_TYPE_VALID = 0x1,
	SERVICE_ICMP_CODE_VALID		
};

/* Servobj request struct */
typedef struct servobj_info {
	u8 proto;
	u8	optionisvalid;
	union {
		struct {
			u16	srcstart, srcend;
			u16	dststart, dstend;
		} port;
		struct {
			u16	flags;
			u16 	type;
			u8	code[2];
		}icmp;
		struct {
			u16	dpi_proto;
		};
	} option;
	
} servobj_info_t;

typedef struct servobj_request {
	char name[MAX_OBJ_NAME_LEN];
	u32 size;
	servobj_info_t serv_info;
	
} servobj_request_t;

#ifdef __KERNEL__
/* servobj item for kernel  */
typedef struct servobj_item {
        char name[MAX_OBJ_NAME_LEN];
        struct list_head list;
        atomic_t        refcnt;
	size_t size;
        rwlock_t lock;
        servobj_info_t info;

} servobj_item_t;

typedef struct pkt_info {
	const struct sk_buff *skb;
	u8 family;
	u8 fragoff;
	u32 thoff;
	u8 l3proto;
	u8 l4proto;

} pkt_info_t;

/* Export API */


extern class_item_t servobj_class;

extern servobj_item_t *service_find_obj( const char *name );
extern void service_bind_obj( unsigned long obj_addr );
extern void service_release_obj( unsigned long obj_addr );
extern int service_match_func( servobj_item_t *serv, const pkt_info_t *pkt_info );

extern int servobj_construct_item( servobj_request_t *req );
extern int servobj_destruct_item( const char *name );
extern int servobj_modify_item( servobj_request_t *info );
extern int servobj_flush_item( void );
extern int servobj_exist_item( const char *name );
extern int servobj_show_item( servobj_request_t *req );
extern int service_obj_proc_init( void );
extern void service_obj_proc_fint( void );;

#endif	/* __KERNEL__ */

#endif	/* __SERVOBJ_STD_H__ */
