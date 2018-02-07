#ifndef __SERVOBJ_STD_H__
#define __SERVOBJ_STD_H__

#include "class_core.h"

#ifndef SERVOBJ_DEBUG
#define SERVOBJ_DEBUG
#endif

#ifdef __KERNEL__
#ifdef SERVOBJ_DEBUG
#define duprintf( format, args... ) printk( "%s %d: " format , __FUNCTION__, __LINE__, ## args )
#else
#define duprintf( format, args... )
#endif

#define PROC_SERVOBJ	"/proc/sys/leadsec/netobj/servobj"

#endif	/* __KERNEL__ */

struct sk_buff;

enum icmp_match_types {
	SERVICE_ICMP_TYPE_VALID = 0x1,
	SERVICE_ICMP_CODE_VALID		
};

/* Servobj request struct */
typedef struct servobj_info {
	u_int8_t proto;
	u_int8_t optionisvalid;
	union {
		struct {
			u_int16_t srcstart, srcend;
			u_int16_t dststart, dstend;
		} port;
		struct {
			u_int16_t	flags;
			u_int16_t 	type;
			u_int16_t	code[2];
		}icmp;
		struct {
			u_int16_t	dpi_proto;
		};
	} option;
	
} servobj_info_t;

typedef struct servobj_request {
	char name[MAX_OBJ_NAME_LEN];
	u_int32_t size;
	servobj_info_t serv_info;
	
} servobj_request_t;

#ifdef __KERNEL__
/* servobj item for kernel  */
typedef struct servobj_item {
        char name[MAX_OBJ_NAME_LEN];
        struct list_head list;
        atomic_t        refcnt;
	size_t size;
        servobj_info_t *info;

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
extern void service_release_obj( servobj_item_t *object );
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
